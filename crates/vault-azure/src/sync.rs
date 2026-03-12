use crate::client::AzureKeyVaultClient;
use crate::error::{AzureError, AzureResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ── Retry configuration ────────────────────────────────────────────────────────

/// Configuration for exponential-backoff retry behaviour.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the initial attempt).
    pub max_retries: u32,
    /// Base delay before the first retry.
    pub base_delay: Duration,
    /// Multiplicative factor applied to the delay after each retry.
    pub backoff_factor: f64,
    /// Hard ceiling on the per-attempt delay.
    pub max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(30),
        }
    }
}

impl RetryConfig {
    /// Returns the delay to wait before the `attempt`-th retry (0-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let factor = self.backoff_factor.powi(attempt as i32);
        let millis = (self.base_delay.as_millis() as f64 * factor) as u64;
        let capped = std::cmp::min(millis, self.max_delay.as_millis() as u64);
        Duration::from_millis(capped)
    }
}

// ── Sync record ────────────────────────────────────────────────────────────────

/// Tracks the sync state of a single secret / credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecord {
    /// Local credential / secret name.
    pub name: String,
    /// Monotonically increasing local version counter.
    pub local_version: u64,
    /// Azure Key Vault version string at the time of the last successful sync.
    pub remote_version: Option<String>,
    /// Timestamp of the last successful sync.
    pub last_synced_at: Option<DateTime<Utc>>,
    /// Whether this record has local changes not yet pushed to Azure KV.
    pub dirty: bool,
}

// ── Conflict resolution ────────────────────────────────────────────────────────

/// Strategy used when a sync conflict is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConflictResolution {
    /// The local (Plures Vault) copy wins.
    LocalWins,
    /// The remote (Azure Key Vault) copy wins.
    RemoteWins,
    /// Whichever copy has the higher version number wins.
    HigherVersionWins,
    /// Whichever copy was modified most recently wins.
    #[default]
    LastWriteWins,
}

// ── Sync result ────────────────────────────────────────────────────────────────

/// The outcome of a single secret sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncOutcome {
    /// Secret was pushed from Plures Vault to Azure KV.
    Pushed { name: String },
    /// Secret was pulled from Azure KV into Plures Vault.
    Pulled { name: String },
    /// Conflict was detected; indicates which side won.
    Resolved {
        name: String,
        resolution: ConflictResolution,
    },
    /// No change was necessary.
    NoChange { name: String },
    /// The secret was deleted on the remote side.
    DeletedRemotely { name: String },
}

/// Summary produced by a full bidirectional sync run.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncReport {
    pub outcomes: Vec<SyncOutcome>,
    pub errors: Vec<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl SyncReport {
    pub fn pushed_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, SyncOutcome::Pushed { .. }))
            .count()
    }

    pub fn pulled_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, SyncOutcome::Pulled { .. }))
            .count()
    }

    pub fn conflict_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, SyncOutcome::Resolved { .. }))
            .count()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

// ── Local secret provider trait ────────────────────────────────────────────────

/// Abstraction over the local vault storage.  Allows the sync manager to be
/// tested independently from the concrete `VaultManager` implementation.
#[async_trait::async_trait]
pub trait LocalSecretProvider: Send + Sync {
    /// Returns all local secrets as `(name, plaintext_value, version)` tuples.
    async fn list_local_secrets(&self)
        -> AzureResult<Vec<(String, String, u64)>>;

    /// Store or update a local secret with the given plaintext value.
    async fn upsert_local_secret(
        &self,
        name: &str,
        value: &str,
    ) -> AzureResult<()>;

    /// Remove a local secret.
    async fn delete_local_secret(&self, name: &str) -> AzureResult<()>;
}

// ── Sync manager ───────────────────────────────────────────────────────────────

/// Bidirectional sync manager for Plures Vault ↔ Azure Key Vault.
///
/// Handles:
/// - Pushing local changes to Azure Key Vault
/// - Pulling remote changes into the local vault
/// - Conflict detection and resolution
/// - Exponential-backoff retry on transient failures
pub struct AzureKvSyncManager<P: LocalSecretProvider> {
    client: AzureKeyVaultClient,
    local: P,
    /// Per-secret sync state, keyed by secret name.
    records: HashMap<String, SyncRecord>,
    retry_config: RetryConfig,
    conflict_strategy: ConflictResolution,
    /// Unique identifier for this sync session.
    session_id: Uuid,
}

impl<P: LocalSecretProvider> AzureKvSyncManager<P> {
    /// Create a new sync manager.
    pub fn new(
        client: AzureKeyVaultClient,
        local: P,
        retry_config: RetryConfig,
        conflict_strategy: ConflictResolution,
    ) -> Self {
        Self {
            client,
            local,
            records: HashMap::new(),
            retry_config,
            conflict_strategy,
            session_id: Uuid::new_v4(),
        }
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    // ── Retry helper ───────────────────────────────────────────────────────────

    /// Execute `f`, retrying on transient errors up to `max_retries` times.
    async fn with_retry<F, T, Fut>(&self, f: F) -> AzureResult<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AzureResult<T>>,
    {
        let mut last_err: Option<AzureError> = None;
        for attempt in 0..=self.retry_config.max_retries {
            if attempt > 0 {
                let delay = self.retry_config.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }
            match f().await {
                Ok(v) => return Ok(v),
                Err(AzureError::RateLimited { retry_after_secs }) => {
                    tokio::time::sleep(Duration::from_secs(retry_after_secs)).await;
                    last_err = Some(AzureError::RateLimited { retry_after_secs });
                }
                Err(e) if Self::is_transient(&e) => {
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or(AzureError::ApiError {
            status: 0,
            message: "retry exhausted".to_string(),
        }))
    }

    fn is_transient(err: &AzureError) -> bool {
        matches!(
            err,
            AzureError::HttpError(_) | AzureError::RateLimited { .. }
        )
    }

    // ── Sync operations ────────────────────────────────────────────────────────

    /// Push a single local secret to Azure Key Vault.
    async fn push_secret(
        &self,
        name: &str,
        value: &str,
    ) -> AzureResult<SyncOutcome> {
        let mut tags = HashMap::new();
        tags.insert("plures-vault-sync".to_string(), "true".to_string());
        tags.insert("session-id".to_string(), self.session_id.to_string());

        self.with_retry(|| {
            let name = name.to_string();
            let value = value.to_string();
            let tags = tags.clone();
            async move {
                self.client
                    .set_secret(&name, &value, Some("text/plain"), Some(tags))
                    .await
                    .map(|_| SyncOutcome::Pushed { name: name.clone() })
            }
        })
        .await
    }

    /// Pull a single remote secret from Azure Key Vault.
    async fn pull_secret(&self, name: &str) -> AzureResult<SyncOutcome> {
        let secret = self
            .with_retry(|| async move { self.client.get_secret(name).await })
            .await?;

        self.local.upsert_local_secret(name, &secret.value).await?;
        Ok(SyncOutcome::Pulled {
            name: name.to_string(),
        })
    }

    /// Resolve a conflict between a local secret and a remote version.
    async fn resolve_conflict(
        &self,
        name: &str,
        local_value: &str,
        local_version: u64,
        remote_version: &str,
        remote_updated_at: Option<chrono::DateTime<Utc>>,
    ) -> AzureResult<SyncOutcome> {
        let resolution = self.conflict_strategy;

        match resolution {
            ConflictResolution::LocalWins => {
                self.push_secret(name, local_value).await?;
            }
            ConflictResolution::RemoteWins => {
                self.pull_secret(name).await?;
            }
            ConflictResolution::HigherVersionWins => {
                // Azure KV version identifiers are 32-character hex strings.
                // We take up to the first 8 hex digits (32 bits) as a u64 for
                // a fast, best-effort ordering.  An empty or non-hex version
                // string falls back to 0, which causes the local copy to win.
                let prefix_len = remote_version.len().min(8);
                let remote_ver = u64::from_str_radix(&remote_version[..prefix_len], 16)
                    .unwrap_or(0);
                if local_version >= remote_ver {
                    self.push_secret(name, local_value).await?;
                } else {
                    self.pull_secret(name).await?;
                }
            }
            ConflictResolution::LastWriteWins => {
                // When no remote timestamp is available we cannot determine
                // which copy is newer, so we conservatively keep the local copy.
                // UNIX_EPOCH acts as a "definitely older than now" sentinel.
                let remote_ts = remote_updated_at.unwrap_or(DateTime::UNIX_EPOCH);
                if Utc::now() >= remote_ts {
                    self.push_secret(name, local_value).await?;
                } else {
                    self.pull_secret(name).await?;
                }
            }
        }

        Ok(SyncOutcome::Resolved {
            name: name.to_string(),
            resolution,
        })
    }

    /// Run a full bidirectional sync between Plures Vault and Azure Key Vault.
    ///
    /// Algorithm:
    /// 1. Fetch the list of remote secrets.
    /// 2. For each local secret:
    ///    - If not present remotely → push.
    ///    - If present remotely and the remote version matches the cached
    ///      version → no-op.
    ///    - If the remote version has changed → resolve conflict.
    /// 3. For each remote secret not present locally → pull.
    pub async fn sync_all(&mut self) -> SyncReport {
        let mut report = SyncReport {
            started_at: Some(Utc::now()),
            ..Default::default()
        };

        // ── Step 1: collect remote secrets ────────────────────────────────────
        let remote_list = match self
            .with_retry(|| async { self.client.list_secrets().await })
            .await
        {
            Ok(list) => list,
            Err(e) => {
                report.errors.push(format!("Failed to list remote secrets: {}", e));
                report.finished_at = Some(Utc::now());
                return report;
            }
        };

        let remote_index: HashMap<String, _> = remote_list
            .into_iter()
            .filter(|s| s.enabled)
            .map(|s| (s.name.clone(), s))
            .collect();

        // ── Step 2: collect local secrets ─────────────────────────────────────
        let local_secrets = match self.local.list_local_secrets().await {
            Ok(s) => s,
            Err(e) => {
                report.errors.push(format!("Failed to list local secrets: {}", e));
                report.finished_at = Some(Utc::now());
                return report;
            }
        };

        let local_names: std::collections::HashSet<String> =
            local_secrets.iter().map(|(n, _, _)| n.clone()).collect();

        // ── Step 3: push / resolve conflicts for each local secret ────────────
        for (name, value, local_version) in &local_secrets {
            let record = self.records.get(name);

            let outcome = if let Some(remote) = remote_index.get(name) {
                // Compare the cached remote version with the current remote version
                // from the list response.  `remote.version` is extracted from the
                // secret's id URL by the Azure KV client.
                let last_known_remote = record.and_then(|r| r.remote_version.as_deref());
                let current_remote_version = remote.version.as_deref();

                if last_known_remote.is_some()
                    && last_known_remote == current_remote_version
                {
                    // Remote version has not changed since last sync → push only if dirty
                    let is_dirty = record.map(|r| r.dirty).unwrap_or(true);
                    if is_dirty {
                        self.push_secret(name, value).await
                    } else {
                        Ok(SyncOutcome::NoChange { name: name.clone() })
                    }
                } else {
                    // Remote version changed (or unknown) since last sync → conflict
                    self.resolve_conflict(
                        name,
                        value,
                        *local_version,
                        current_remote_version.unwrap_or(""),
                        None,
                    )
                    .await
                }
            } else {
                // Secret not in Azure KV yet → push
                self.push_secret(name, value).await
            };

            match outcome {
                Ok(o) => {
                    self.mark_synced(name, None);
                    report.outcomes.push(o);
                }
                Err(e) => {
                    report
                        .errors
                        .push(format!("Failed to sync '{}': {}", name, e));
                }
            }
        }

        // ── Step 4: pull secrets that exist remotely but not locally ──────────
        for remote_name in remote_index.keys() {
            if !local_names.contains(remote_name) {
                match self.pull_secret(remote_name).await {
                    Ok(o) => {
                        self.mark_synced(remote_name, None);
                        report.outcomes.push(o);
                    }
                    Err(e) => {
                        report
                            .errors
                            .push(format!("Failed to pull '{}': {}", remote_name, e));
                    }
                }
            }
        }

        report.finished_at = Some(Utc::now());
        report
    }

    /// Mark a secret as cleanly synced.
    fn mark_synced(&mut self, name: &str, remote_version: Option<String>) {
        let record = self.records.entry(name.to_string()).or_insert_with(|| {
            SyncRecord {
                name: name.to_string(),
                local_version: 0,
                remote_version: None,
                last_synced_at: None,
                dirty: false,
            }
        });
        record.remote_version = remote_version;
        record.last_synced_at = Some(Utc::now());
        record.dirty = false;
    }

    /// Mark a secret as having pending local changes that need to be pushed.
    pub fn mark_dirty(&mut self, name: &str) {
        let record = self.records.entry(name.to_string()).or_insert_with(|| {
            SyncRecord {
                name: name.to_string(),
                local_version: 0,
                remote_version: None,
                last_synced_at: None,
                dirty: true,
            }
        });
        record.dirty = true;
        record.local_version += 1;
    }

    /// Returns all current sync records.
    pub fn records(&self) -> &HashMap<String, SyncRecord> {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_delay_calculation() {
        let config = RetryConfig {
            base_delay: Duration::from_millis(500),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(30),
            max_retries: 5,
        };

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(500));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(1000));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(2000));
        // Should be capped at max_delay
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(30));
    }

    #[test]
    fn test_sync_report_counts() {
        let mut report = SyncReport::default();
        report.outcomes.push(SyncOutcome::Pushed {
            name: "a".to_string(),
        });
        report.outcomes.push(SyncOutcome::Pushed {
            name: "b".to_string(),
        });
        report.outcomes.push(SyncOutcome::Pulled {
            name: "c".to_string(),
        });
        report.outcomes.push(SyncOutcome::Resolved {
            name: "d".to_string(),
            resolution: ConflictResolution::LocalWins,
        });
        report.errors.push("err".to_string());

        assert_eq!(report.pushed_count(), 2);
        assert_eq!(report.pulled_count(), 1);
        assert_eq!(report.conflict_count(), 1);
        assert_eq!(report.error_count(), 1);
    }

    #[test]
    fn test_conflict_resolution_default() {
        assert_eq!(
            ConflictResolution::default(),
            ConflictResolution::LastWriteWins
        );
    }
}
