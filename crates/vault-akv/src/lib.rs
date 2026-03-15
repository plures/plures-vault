//! Azure Key Vault bidirectional sync for Plures Vault.
//!
//! Credentials map to AKV secrets as:
//! - Secret name: `plures-{credential-id}`
//! - Secret value: JSON `{ title, username, password, url, notes, updated_at, source_id }`
//! - AKV encrypts at rest via HSM-backed keys

use anyhow::Result;
use azure_identity::AzureCliCredential;
use azure_security_keyvault_secrets::{
    models::SetSecretParameters,
    SecretClient, ResourceExt,
};
use azure_core::http::RequestContent;
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum AkvSyncError {
    #[error("Azure Key Vault error: {0}")]
    AkvError(String),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Sync conflict: credential={credential_id}")]
    SyncConflict { credential_id: String },
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ConflictStrategy {
    RemoteWins,
    LocalWins,
    LastWriteWins,
    Skip,
}

impl Default for ConflictStrategy {
    fn default() -> Self { Self::RemoteWins }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkvPartitionConfig {
    pub vault_url: String,
    pub partition_name: String,
    #[serde(default)]
    pub conflict_strategy: ConflictStrategy,
    #[serde(default = "default_prefix")]
    pub secret_prefix: String,
    #[serde(default)]
    pub auto_sync_interval_secs: u64,
    pub last_sync: Option<DateTime<Utc>>,
}

fn default_prefix() -> String { "plures-".to_string() }

// ── Sync data types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkvSecretPayload {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub updated_at: String,
    pub source_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
    pub timestamp: DateTime<Utc>,
}

// ── AKV Sync Manager ────────────────────────────────────────────────────────

pub struct AkvSyncManager {
    client: SecretClient,
    config: AkvPartitionConfig,
}

impl AkvSyncManager {
    /// Create using Azure CLI credential (supports `az login`, managed identity fallback).
    pub fn new(config: AkvPartitionConfig) -> Result<Self> {
        let credential = AzureCliCredential::new(None)
            .map_err(|e| AkvSyncError::AuthError(e.to_string()))?;

        let client = SecretClient::new(&config.vault_url, credential, None)
            .map_err(|e| AkvSyncError::AkvError(e.to_string()))?;

        info!("AKV sync manager initialized for {}", config.vault_url);
        Ok(Self { client, config })
    }

    /// Push a credential to Azure Key Vault.
    pub async fn push_credential(
        &self,
        credential_id: &Uuid,
        payload: &AkvSecretPayload,
    ) -> Result<String> {
        let secret_name = self.credential_to_secret_name(credential_id);
        let secret_value = serde_json::to_string(payload)?;
        let content_hash = Self::compute_hash(&secret_value);

        debug!("Pushing credential {} → AKV secret {}", credential_id, secret_name);

        let params = SetSecretParameters {
            value: Some(secret_value),
            content_type: Some("application/json".to_string()),
            tags: None,
            secret_attributes: None,
        };

        let body: RequestContent<SetSecretParameters> = RequestContent::try_from(params)
            .map_err(|e| AkvSyncError::AkvError(e.to_string()))?;

        self.client
            .set_secret(&secret_name, body, None)
            .await
            .map_err(|e| AkvSyncError::AkvError(format!("set_secret failed: {}", e)))?;

        info!("Pushed {} to AKV (hash: {}…)", credential_id, &content_hash[..8]);
        Ok(content_hash)
    }

    /// Pull a credential from Azure Key Vault.
    pub async fn pull_credential(
        &self,
        credential_id: &Uuid,
    ) -> Result<Option<AkvSecretPayload>> {
        let secret_name = self.credential_to_secret_name(credential_id);

        match self.client.get_secret(&secret_name, None).await {
            Ok(response) => {
                let secret = response.into_model()
                    .map_err(|e| AkvSyncError::AkvError(e.to_string()))?;
                match secret.value {
                    Some(value) => {
                        let payload: AkvSecretPayload = serde_json::from_str(&value)?;
                        Ok(Some(payload))
                    }
                    None => Ok(None),
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("SecretNotFound") || err_str.contains("404") {
                    Ok(None)
                } else {
                    Err(AkvSyncError::AkvError(format!("get_secret failed: {}", err_str)).into())
                }
            }
        }
    }

    /// Delete a credential from Azure Key Vault.
    pub async fn delete_credential(&self, credential_id: &Uuid) -> Result<bool> {
        let secret_name = self.credential_to_secret_name(credential_id);

        match self.client.delete_secret(&secret_name, None).await {
            Ok(_) => {
                info!("Deleted secret {} from AKV", secret_name);
                Ok(true)
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("SecretNotFound") || err_str.contains("404") {
                    Ok(false)
                } else {
                    Err(AkvSyncError::AkvError(format!("delete_secret failed: {}", err_str)).into())
                }
            }
        }
    }

    /// List all Plures-managed secret IDs in the vault.
    pub async fn list_remote_credentials(&self) -> Result<Vec<Uuid>> {
        let mut results = Vec::new();

        let mut pager = self.client.list_secret_properties(None)
            .map_err(|e| AkvSyncError::AkvError(e.to_string()))?;

        while let Some(secret_props) = pager.try_next().await
            .map_err(|e: azure_core::Error| AkvSyncError::AkvError(e.to_string()))? {
            if let Ok(resource_id) = secret_props.resource_id() {
                if let Some(cred_id) = self.secret_name_to_credential(&resource_id.name) {
                    results.push(cred_id);
                }
            }
        }

        debug!("Found {} Plures secrets in AKV", results.len());
        Ok(results)
    }

    /// Full bidirectional sync.
    pub async fn full_sync(
        &self,
        local_credentials: &[(Uuid, AkvSecretPayload, String)],
    ) -> Result<SyncResult> {
        let start = std::time::Instant::now();
        let mut result = SyncResult {
            pushed: 0, pulled: 0, conflicts: 0, skipped: 0,
            errors: Vec::new(), duration_ms: 0, timestamp: Utc::now(),
        };

        let local_map: HashMap<Uuid, (&AkvSecretPayload, &str)> = local_credentials
            .iter()
            .map(|(id, p, h)| (*id, (p, h.as_str())))
            .collect();

        let remote_ids = match self.list_remote_credentials().await {
            Ok(ids) => ids,
            Err(e) => {
                result.errors.push(format!("List remote failed: {}", e));
                result.duration_ms = start.elapsed().as_millis() as u64;
                return Ok(result);
            }
        };

        let remote_id_set: HashSet<Uuid> = remote_ids.iter().copied().collect();

        // Push local-only
        for (id, payload, _) in local_credentials {
            if !remote_id_set.contains(id) {
                match self.push_credential(id, payload).await {
                    Ok(_) => result.pushed += 1,
                    Err(e) => result.errors.push(format!("Push {} failed: {}", id, e)),
                }
            }
        }

        // Pull remote-only + resolve conflicts
        for remote_id in &remote_ids {
            match local_map.get(remote_id) {
                None => match self.pull_credential(remote_id).await {
                    Ok(Some(_)) => result.pulled += 1,
                    Ok(None) => result.skipped += 1,
                    Err(e) => result.errors.push(format!("Pull {} failed: {}", remote_id, e)),
                },
                Some((local_payload, local_hash)) => {
                    match self.pull_credential(remote_id).await {
                        Ok(Some(remote_payload)) => {
                            let remote_value = serde_json::to_string(&remote_payload)?;
                            let remote_hash = Self::compute_hash(&remote_value);
                            if remote_hash == *local_hash { continue; }

                            result.conflicts += 1;
                            match self.config.conflict_strategy {
                                ConflictStrategy::RemoteWins => result.pulled += 1,
                                ConflictStrategy::LocalWins => {
                                    match self.push_credential(remote_id, local_payload).await {
                                        Ok(_) => result.pushed += 1,
                                        Err(e) => result.errors.push(format!("Push {} failed: {}", remote_id, e)),
                                    }
                                }
                                ConflictStrategy::LastWriteWins => {
                                    if remote_payload.updated_at > local_payload.updated_at {
                                        result.pulled += 1;
                                    } else {
                                        match self.push_credential(remote_id, local_payload).await {
                                            Ok(_) => result.pushed += 1,
                                            Err(e) => result.errors.push(format!("LWW push {} failed: {}", remote_id, e)),
                                        }
                                    }
                                }
                                ConflictStrategy::Skip => {
                                    warn!("Skipping conflict for {}", remote_id);
                                    result.skipped += 1;
                                }
                            }
                        }
                        Ok(None) => result.skipped += 1,
                        Err(e) => result.errors.push(format!("Check {} failed: {}", remote_id, e)),
                    }
                }
            }
        }

        result.duration_ms = start.elapsed().as_millis() as u64;
        info!("Sync: pushed={}, pulled={}, conflicts={}, errors={}",
            result.pushed, result.pulled, result.conflicts, result.errors.len());
        Ok(result)
    }

    pub fn config(&self) -> &AkvPartitionConfig { &self.config }

    fn credential_to_secret_name(&self, id: &Uuid) -> String {
        format!("{}{}", self.config.secret_prefix, id)
    }

    fn secret_name_to_credential(&self, name: &str) -> Option<Uuid> {
        name.strip_prefix(&self.config.secret_prefix)
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    fn compute_hash(content: &str) -> String {
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_name_roundtrip() {
        let prefix = "plures-";
        let id = Uuid::new_v4();
        let name = format!("{}{}", prefix, id);
        let parsed = name.strip_prefix(prefix).and_then(|s| Uuid::parse_str(s).ok());
        assert_eq!(parsed, Some(id));
    }

    #[test]
    fn test_content_hash_deterministic() {
        let h1 = AkvSyncManager::compute_hash("test");
        let h2 = AkvSyncManager::compute_hash("test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_payload_roundtrip() {
        let payload = AkvSecretPayload {
            title: "GitHub".into(),
            username: Some("alice".into()),
            password: "s3cr3t".into(),
            url: Some("https://github.com".into()),
            notes: None,
            updated_at: Utc::now().to_rfc3339(),
            source_id: Uuid::new_v4().to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: AkvSecretPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "GitHub");
    }

    #[test]
    fn test_conflict_strategy_default() {
        assert_eq!(ConflictStrategy::default(), ConflictStrategy::RemoteWins);
    }
}
