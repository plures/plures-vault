pub mod windows_hello;

use vault_crypto::{VaultCrypto, MasterKey, EncryptedData, CryptoError};
use argon2::{password_hash::SaltString, PasswordHasher};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use thiserror::Error;
use serde_json::json;
use std::sync::Arc;

// PluresDB imports
use pluresdb::{CrdtStore, SledStorage, MemoryStorage, StorageEngine, NodeData};

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    #[error("Credential already exists: {0}")]
    CredentialAlreadyExists(String),
    #[error("Vault not initialized")]
    VaultNotInitialized,
    #[error("Vault already initialized")]
    VaultAlreadyInitialized,
    #[error("Invalid master password")]
    InvalidMasterPassword,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

// ── Constants ────────────────────────────────────────────────────────────────

const VAULT_CONFIG_KEY: &str = "vault:config";
const CREDENTIAL_PREFIX: &str = "cred:";
const METADATA_PREFIX: &str = "meta:";
const SYNC_PREFIX: &str = "sync:";
const ACTOR_ID: &str = "vault-local";

// ── Domain types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    pub algorithm: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault_id: Uuid,
    pub version: i64,
    pub vault_name: String,
    pub salt: String,
    pub key_derivation_params: KeyDerivationParams,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub notes: Option<String>,
    pub url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub credential_id: Uuid,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMetadata {
    pub credential_id: Uuid,
    pub last_sync: DateTime<Utc>,
    pub sync_hash: String,
}

// ── Internal stored types (encrypted at rest) ────────────────────────────────

#[derive(Serialize, Deserialize)]
struct StoredVaultConfig {
    vault_id: String,
    version: i64,
    vault_name: String,
    salt: String,
    key_derivation_params: KeyDerivationParams,
    password_hash: String,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct StoredCredential {
    id: String,
    title: String,
    username: Option<String>,
    encrypted_password: String,
    encrypted_notes: Option<String>,
    url: Option<String>,
    created_at: String,
    updated_at: String,
}

// ── VaultManager ─────────────────────────────────────────────────────────────

pub struct VaultManager {
    store: Arc<CrdtStore>,
    crypto: VaultCrypto,
    master_key: Option<MasterKey>,
}

impl VaultManager {
    /// Open (or create) a vault database at `database_path`.
    ///
    /// Pass `":memory:"` for an in-memory database (tests).
    /// Uses PluresDB with SledStorage for persistence.
    pub async fn new(database_path: &str) -> Result<Self> {
        let store = if database_path == ":memory:" {
            let storage = MemoryStorage::default();
            Arc::new(
                CrdtStore::default()
                    .with_persistence(Arc::new(storage) as Arc<dyn StorageEngine>),
            )
        } else {
            let storage = SledStorage::open(database_path)
                .map_err(|e| VaultError::StorageError(e.to_string()))?;
            Arc::new(
                CrdtStore::default()
                    .with_persistence(Arc::new(storage) as Arc<dyn StorageEngine>),
            )
        };

        Ok(Self {
            store,
            crypto: VaultCrypto::new(),
            master_key: None,
        })
    }

    // ── Vault lifecycle ───────────────────────────────────────────────────────

    pub async fn init_vault(
        &mut self,
        vault_name: &str,
        master_password: &str,
    ) -> Result<VaultConfig> {
        // Guard against re-initialisation.
        if self.store.get(VAULT_CONFIG_KEY).is_some() {
            return Err(VaultError::VaultAlreadyInitialized.into());
        }

        let (master_key, salt) = self.crypto.derive_master_key(master_password, None)?;
        let salt_string = SaltString::from_b64(&salt)
            .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;
        let password_hash = self
            .crypto
            .argon2
            .hash_password(master_password.as_bytes(), &salt_string)
            .map_err(|e| CryptoError::Argon2Error(e.to_string()))?
            .to_string();

        let params = KeyDerivationParams::default();
        let now = Utc::now();
        let vault_id = Uuid::new_v4();

        let stored = StoredVaultConfig {
            vault_id: vault_id.to_string(),
            version: 1,
            vault_name: vault_name.to_string(),
            salt: salt.clone(),
            key_derivation_params: params.clone(),
            password_hash,
            created_at: now.to_rfc3339(),
        };

        let data: NodeData = serde_json::to_value(&stored)?;
        self.store.put(VAULT_CONFIG_KEY, ACTOR_ID, data);

        self.master_key = Some(master_key);

        Ok(VaultConfig {
            vault_id,
            version: 1,
            vault_name: vault_name.to_string(),
            salt,
            key_derivation_params: params,
            created_at: now,
        })
    }

    pub async fn unlock_vault(&mut self, master_password: &str) -> Result<VaultConfig> {
        let config = self.get_vault_config().await?;
        let hash = self.fetch_password_hash()?;

        let master_key = self
            .crypto
            .verify_password(master_password, &config.salt, &hash)
            .map_err(|_| VaultError::InvalidMasterPassword)?;

        self.master_key = Some(master_key);
        Ok(config)
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn lock(&mut self) {
        self.master_key = None;
    }

    pub async fn get_vault_config(&self) -> Result<VaultConfig> {
        let record = self
            .store
            .get(VAULT_CONFIG_KEY)
            .ok_or(VaultError::VaultNotInitialized)?;

        let stored: StoredVaultConfig = serde_json::from_value(record.data.clone())?;

        Ok(VaultConfig {
            vault_id: Uuid::parse_str(&stored.vault_id)?,
            version: stored.version,
            vault_name: stored.vault_name,
            salt: stored.salt,
            key_derivation_params: stored.key_derivation_params,
            created_at: DateTime::parse_from_rfc3339(&stored.created_at)?
                .with_timezone(&Utc),
        })
    }

    pub async fn check_initialization(&self) -> Result<VaultConfig> {
        self.get_vault_config().await
    }

    // ── Credential CRUD ───────────────────────────────────────────────────────

    pub async fn add_credential(
        &self,
        title: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Result<Credential> {
        let master_key = self.require_master_key()?;

        // Check for duplicate title
        if self.find_credential_key_by_title(&title).is_some() {
            return Err(VaultError::CredentialAlreadyExists(title).into());
        }

        let encrypted_password = self.encrypt_field(master_key, &password)?;
        let encrypted_notes = notes
            .as_deref()
            .map(|n| self.encrypt_field(master_key, n))
            .transpose()?;

        let id = Uuid::new_v4();
        let now = Utc::now();
        let node_key = format!("{}{}", CREDENTIAL_PREFIX, id);

        let stored = StoredCredential {
            id: id.to_string(),
            title: title.clone(),
            username: username.clone(),
            encrypted_password,
            encrypted_notes,
            url: url.clone(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        };

        let data: NodeData = serde_json::to_value(&stored)?;
        self.store.put(node_key, ACTOR_ID, data);

        Ok(Credential {
            id,
            title,
            username,
            password,
            notes,
            url,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_credential(&self, title: &str) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;

        match self.find_credential_key_by_title(title) {
            Some(key) => {
                let record = self.store.get(&key).unwrap();
                Ok(Some(self.node_to_credential(&record.data, master_key)?))
            }
            None => Ok(None),
        }
    }

    pub async fn get_credential_by_id(&self, id: &str) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;
        let key = format!("{}{}", CREDENTIAL_PREFIX, id);

        match self.store.get(&key) {
            Some(record) => Ok(Some(self.node_to_credential(&record.data, master_key)?)),
            None => Ok(None),
        }
    }

    pub async fn list_credentials(&self) -> Result<Vec<Credential>> {
        let master_key = self.require_master_key()?;

        let mut credentials: Vec<Credential> = self
            .store
            .list()
            .into_iter()
            .filter(|r| r.id.starts_with(CREDENTIAL_PREFIX))
            .map(|r| self.node_to_credential(&r.data, master_key))
            .collect::<Result<Vec<_>>>()?;

        credentials.sort_by(|a, b| a.title.cmp(&b.title));
        Ok(credentials)
    }

    pub async fn update_credential(
        &self,
        title: &str,
        new_username: Option<String>,
        new_password: Option<String>,
        new_url: Option<String>,
        new_notes: Option<String>,
    ) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;

        let key = match self.find_credential_key_by_title(title) {
            Some(k) => k,
            None => return Ok(None),
        };

        let record = self.store.get(&key).unwrap();
        let mut credential = self.node_to_credential(&record.data, master_key)?;

        Self::apply_updates(&mut credential, new_username, new_password, new_url, new_notes);
        credential.updated_at = Utc::now();

        self.store_credential(&key, &credential, master_key)?;
        Ok(Some(credential))
    }

    pub async fn update_credential_by_id(
        &self,
        id: &str,
        new_title: Option<String>,
        new_username: Option<String>,
        new_password: Option<String>,
        new_url: Option<String>,
        new_notes: Option<String>,
    ) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;
        let key = format!("{}{}", CREDENTIAL_PREFIX, id);

        let record = match self.store.get(&key) {
            Some(r) => r,
            None => return Ok(None),
        };

        let mut credential = self.node_to_credential(&record.data, master_key)?;

        if let Some(t) = new_title {
            credential.title = t;
        }
        Self::apply_updates(&mut credential, new_username, new_password, new_url, new_notes);
        credential.updated_at = Utc::now();

        self.store_credential(&key, &credential, master_key)?;
        Ok(Some(credential))
    }

    pub async fn delete_credential(&self, title: &str) -> Result<bool> {
        match self.find_credential_key_by_title(title) {
            Some(key) => {
                let id = key.strip_prefix(CREDENTIAL_PREFIX).unwrap();
                self.delete_related_data(id);
                self.store.delete(&key).map_err(|e| VaultError::StorageError(e.to_string()))?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub async fn delete_credential_by_id(&self, id: &str) -> Result<bool> {
        let key = format!("{}{}", CREDENTIAL_PREFIX, id);
        if self.store.get(&key).is_some() {
            self.delete_related_data(id);
            self.store.delete(&key).map_err(|e| VaultError::StorageError(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ── Credential metadata ───────────────────────────────────────────────────

    pub async fn set_credential_metadata(
        &self,
        credential_id: &Uuid,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let master_key = self.require_master_key()?;
        let encrypted_value = self.encrypt_field(master_key, value)?;

        let node_key = format!("{}{}:{}", METADATA_PREFIX, credential_id, key);
        let data: NodeData = json!({
            "credential_id": credential_id.to_string(),
            "key": key,
            "encrypted_value": encrypted_value,
        });
        self.store.put(node_key, ACTOR_ID, data);
        Ok(())
    }

    pub async fn get_credential_metadata(
        &self,
        credential_id: &Uuid,
    ) -> Result<Vec<CredentialMetadata>> {
        let master_key = self.require_master_key()?;
        let prefix = format!("{}{}:", METADATA_PREFIX, credential_id);

        let mut result: Vec<CredentialMetadata> = self
            .store
            .list()
            .into_iter()
            .filter(|r| r.id.starts_with(&prefix))
            .map(|r| {
                let encrypted_json = r.data["encrypted_value"].as_str().unwrap();
                let encrypted: EncryptedData = serde_json::from_str(encrypted_json)?;
                let value = self.crypto.decrypt(master_key, &encrypted)?;
                Ok(CredentialMetadata {
                    credential_id: *credential_id,
                    key: r.data["key"].as_str().unwrap().to_string(),
                    value,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        result.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(result)
    }

    pub async fn delete_credential_metadata(
        &self,
        credential_id: &Uuid,
        key: &str,
    ) -> Result<bool> {
        let node_key = format!("{}{}:{}", METADATA_PREFIX, credential_id, key);
        if self.store.get(&node_key).is_some() {
            self.store.delete(&node_key).map_err(|e| VaultError::StorageError(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ── Sync metadata ─────────────────────────────────────────────────────────

    pub async fn record_sync_metadata(
        &self,
        credential_id: &Uuid,
        sync_hash: &str,
    ) -> Result<SyncMetadata> {
        let now = Utc::now();
        let node_key = format!("{}{}", SYNC_PREFIX, credential_id);

        let data: NodeData = json!({
            "credential_id": credential_id.to_string(),
            "last_sync": now.to_rfc3339(),
            "sync_hash": sync_hash,
        });
        self.store.put(node_key, ACTOR_ID, data);

        Ok(SyncMetadata {
            credential_id: *credential_id,
            last_sync: now,
            sync_hash: sync_hash.to_string(),
        })
    }

    pub async fn get_sync_metadata(
        &self,
        credential_id: &Uuid,
    ) -> Result<Option<SyncMetadata>> {
        let node_key = format!("{}{}", SYNC_PREFIX, credential_id);

        match self.store.get(&node_key) {
            Some(record) => {
                let last_sync = DateTime::parse_from_rfc3339(
                    record.data["last_sync"].as_str().unwrap(),
                )?
                .with_timezone(&Utc);
                Ok(Some(SyncMetadata {
                    credential_id: *credential_id,
                    last_sync,
                    sync_hash: record.data["sync_hash"].as_str().unwrap().to_string(),
                }))
            }
            None => Ok(None),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn require_master_key(&self) -> Result<&MasterKey, VaultError> {
        self.master_key.as_ref().ok_or(VaultError::VaultNotInitialized)
    }

    fn encrypt_field(&self, key: &MasterKey, plaintext: &str) -> Result<String, VaultError> {
        let encrypted = self.crypto.encrypt(key, plaintext)?;
        serde_json::to_string(&encrypted).map_err(VaultError::SerializationError)
    }

    fn decrypt_field(&self, key: &MasterKey, json: &str) -> Result<String, VaultError> {
        let encrypted: EncryptedData =
            serde_json::from_str(json).map_err(VaultError::SerializationError)?;
        self.crypto.decrypt(key, &encrypted).map_err(VaultError::CryptoError)
    }

    fn node_to_credential(&self, data: &NodeData, master_key: &MasterKey) -> Result<Credential> {
        let stored: StoredCredential = serde_json::from_value(data.clone())?;

        let password = self.decrypt_field(master_key, &stored.encrypted_password)?;
        let notes = stored
            .encrypted_notes
            .as_deref()
            .map(|json| self.decrypt_field(master_key, json))
            .transpose()?;

        Ok(Credential {
            id: Uuid::parse_str(&stored.id)?,
            title: stored.title,
            username: stored.username,
            password,
            notes,
            url: stored.url,
            created_at: DateTime::parse_from_rfc3339(&stored.created_at)?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&stored.updated_at)?
                .with_timezone(&Utc),
        })
    }

    fn store_credential(
        &self,
        node_key: &str,
        credential: &Credential,
        master_key: &MasterKey,
    ) -> Result<()> {
        let enc_password = self.encrypt_field(master_key, &credential.password)?;
        let enc_notes = credential
            .notes
            .as_deref()
            .map(|n| self.encrypt_field(master_key, n))
            .transpose()?;

        let stored = StoredCredential {
            id: credential.id.to_string(),
            title: credential.title.clone(),
            username: credential.username.clone(),
            encrypted_password: enc_password,
            encrypted_notes: enc_notes,
            url: credential.url.clone(),
            created_at: credential.created_at.to_rfc3339(),
            updated_at: credential.updated_at.to_rfc3339(),
        };

        let data: NodeData = serde_json::to_value(&stored)?;
        self.store.put(node_key, ACTOR_ID, data);
        Ok(())
    }

    fn find_credential_key_by_title(&self, title: &str) -> Option<String> {
        self.store
            .list()
            .into_iter()
            .find(|r| {
                r.id.starts_with(CREDENTIAL_PREFIX)
                    && r.data.get("title").and_then(|v| v.as_str()) == Some(title)
            })
            .map(|r| r.id.clone())
    }

    /// Delete metadata and sync data associated with a credential.
    fn delete_related_data(&self, credential_id: &str) {
        let meta_prefix = format!("{}{}:", METADATA_PREFIX, credential_id);
        let sync_key = format!("{}{}", SYNC_PREFIX, credential_id);

        // Delete all metadata nodes for this credential
        let meta_keys: Vec<String> = self
            .store
            .list()
            .into_iter()
            .filter(|r| r.id.starts_with(&meta_prefix))
            .map(|r| r.id.clone())
            .collect();

        for key in meta_keys {
            let _ = self.store.delete(&key);
        }

        // Delete sync metadata
        let _ = self.store.delete(&sync_key);
    }

    fn fetch_password_hash(&self) -> Result<String, VaultError> {
        let record = self
            .store
            .get(VAULT_CONFIG_KEY)
            .ok_or(VaultError::VaultNotInitialized)?;
        let stored: StoredVaultConfig =
            serde_json::from_value(record.data.clone()).map_err(|e| VaultError::SerializationError(e))?;
        Ok(stored.password_hash)
    }

    fn apply_updates(
        credential: &mut Credential,
        new_username: Option<String>,
        new_password: Option<String>,
        new_url: Option<String>,
        new_notes: Option<String>,
    ) {
        if let Some(username) = new_username {
            credential.username = Some(username);
        }
        if let Some(password) = new_password {
            credential.password = password;
        }
        if let Some(url) = new_url {
            credential.url = Some(url);
        }
        if let Some(notes) = new_notes {
            credential.notes = Some(notes);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "test_master_password_123";

    async fn create_vault() -> VaultManager {
        VaultManager::new(":memory:").await.expect("Failed to create vault")
    }

    async fn init_vault() -> VaultManager {
        let mut vault = create_vault().await;
        vault
            .init_vault("Test Vault", TEST_PASSWORD)
            .await
            .expect("Failed to init vault");
        vault
    }

    #[tokio::test]
    async fn test_init_vault() {
        let mut vault = create_vault().await;
        let config = vault.init_vault("My Vault", TEST_PASSWORD).await.unwrap();

        assert_eq!(config.vault_name, "My Vault");
        assert_eq!(config.version, 1);
        assert_eq!(config.key_derivation_params.algorithm, "argon2id");
        assert!(vault.is_unlocked());
    }

    #[tokio::test]
    async fn test_init_vault_twice_fails() {
        let mut vault = create_vault().await;
        vault.init_vault("Vault", TEST_PASSWORD).await.unwrap();
        assert!(vault.init_vault("Vault", TEST_PASSWORD).await.is_err());
    }

    #[tokio::test]
    async fn test_unlock_vault_correct_password() {
        let mut vault = init_vault().await;
        vault.lock();
        assert!(!vault.is_unlocked());

        let config = vault.unlock_vault(TEST_PASSWORD).await.unwrap();
        assert_eq!(config.vault_name, "Test Vault");
        assert!(vault.is_unlocked());
    }

    #[tokio::test]
    async fn test_unlock_vault_wrong_password() {
        let mut vault = init_vault().await;
        vault.lock();
        assert!(vault.unlock_vault("wrong_password").await.is_err());
    }

    #[tokio::test]
    async fn test_check_initialization() {
        let mut vault = create_vault().await;
        assert!(vault.check_initialization().await.is_err());

        vault.init_vault("My Vault", TEST_PASSWORD).await.unwrap();
        let config = vault.check_initialization().await.unwrap();
        assert_eq!(config.vault_name, "My Vault");
    }

    #[tokio::test]
    async fn test_locked_vault_denies_credential_access() {
        let mut vault = init_vault().await;
        vault
            .add_credential("cred".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        vault.lock();
        assert!(!vault.is_unlocked());

        assert!(vault
            .add_credential("x".into(), None, "y".into(), None, None)
            .await
            .is_err());
        assert!(vault.get_credential("cred").await.is_err());
        assert!(vault.list_credentials().await.is_err());
    }

    #[tokio::test]
    async fn test_add_and_get_credential_by_title() {
        let vault = init_vault().await;
        vault
            .add_credential(
                "GitHub".into(),
                Some("alice".into()),
                "s3cr3t".into(),
                Some("https://github.com".into()),
                Some("Work account".into()),
            )
            .await
            .unwrap();

        let cred = vault.get_credential("GitHub").await.unwrap().unwrap();
        assert_eq!(cred.title, "GitHub");
        assert_eq!(cred.username.as_deref(), Some("alice"));
        assert_eq!(cred.password, "s3cr3t");
        assert_eq!(cred.url.as_deref(), Some("https://github.com"));
        assert_eq!(cred.notes.as_deref(), Some("Work account"));
    }

    #[tokio::test]
    async fn test_get_credential_not_found_returns_none() {
        let vault = init_vault().await;
        assert!(vault.get_credential("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_add_and_get_credential_by_id() {
        let vault = init_vault().await;
        let created = vault
            .add_credential("Twitter".into(), None, "pass123".into(), None, None)
            .await
            .unwrap();

        let cred = vault
            .get_credential_by_id(&created.id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.title, "Twitter");
        assert_eq!(cred.password, "pass123");
    }

    #[tokio::test]
    async fn test_list_credentials_sorted_by_title() {
        let vault = init_vault().await;
        vault.add_credential("Zebra".into(), None, "z".into(), None, None).await.unwrap();
        vault.add_credential("Alpha".into(), None, "a".into(), None, None).await.unwrap();
        vault.add_credential("Middle".into(), None, "m".into(), None, None).await.unwrap();

        let list = vault.list_credentials().await.unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].title, "Alpha");
        assert_eq!(list[1].title, "Middle");
        assert_eq!(list[2].title, "Zebra");
    }

    #[tokio::test]
    async fn test_update_credential_by_title() {
        let vault = init_vault().await;
        vault
            .add_credential("MyBank".into(), Some("user1".into()), "oldpass".into(), None, None)
            .await
            .unwrap();

        let updated = vault
            .update_credential(
                "MyBank",
                Some("user2".into()),
                Some("newpass".into()),
                Some("https://bank.example".into()),
                Some("savings".into()),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.username.as_deref(), Some("user2"));
        assert_eq!(updated.password, "newpass");
        assert_eq!(updated.url.as_deref(), Some("https://bank.example"));
        assert_eq!(updated.notes.as_deref(), Some("savings"));

        let fetched = vault.get_credential("MyBank").await.unwrap().unwrap();
        assert_eq!(fetched.password, "newpass");
    }

    #[tokio::test]
    async fn test_update_credential_by_id() {
        let vault = init_vault().await;
        let orig = vault
            .add_credential("Service".into(), None, "pass1".into(), None, None)
            .await
            .unwrap();

        let updated = vault
            .update_credential_by_id(
                &orig.id.to_string(),
                Some("RenamedService".into()),
                None,
                Some("pass2".into()),
                None,
                None,
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.title, "RenamedService");
        assert_eq!(updated.password, "pass2");
    }

    #[tokio::test]
    async fn test_update_credential_not_found_returns_none() {
        let vault = init_vault().await;
        let result = vault
            .update_credential("ghost", None, Some("x".into()), None, None)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_credential_by_title() {
        let vault = init_vault().await;
        vault.add_credential("ToDelete".into(), None, "pass".into(), None, None).await.unwrap();

        assert!(vault.delete_credential("ToDelete").await.unwrap());
        assert!(vault.get_credential("ToDelete").await.unwrap().is_none());
        assert!(!vault.delete_credential("ToDelete").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_credential_by_id() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("ByID".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        assert!(vault.delete_credential_by_id(&cred.id.to_string()).await.unwrap());
        assert!(vault.get_credential_by_id(&cred.id.to_string()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_credential_metadata_set_get_delete() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("Meta".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        vault.set_credential_metadata(&cred.id, "2fa_seed", "JBSWY3DPEHPK3PXP").await.unwrap();
        vault.set_credential_metadata(&cred.id, "recovery_code", "abc-123").await.unwrap();

        let meta = vault.get_credential_metadata(&cred.id).await.unwrap();
        assert_eq!(meta.len(), 2);
        let m0 = meta.iter().find(|m| m.key == "2fa_seed").unwrap();
        assert_eq!(m0.value, "JBSWY3DPEHPK3PXP");

        // Upsert
        vault.set_credential_metadata(&cred.id, "2fa_seed", "NEWSEED").await.unwrap();
        let meta2 = vault.get_credential_metadata(&cred.id).await.unwrap();
        let updated = meta2.iter().find(|m| m.key == "2fa_seed").unwrap();
        assert_eq!(updated.value, "NEWSEED");

        // Delete one key
        assert!(vault.delete_credential_metadata(&cred.id, "recovery_code").await.unwrap());
        let meta3 = vault.get_credential_metadata(&cred.id).await.unwrap();
        assert_eq!(meta3.len(), 1);

        // Cascade delete
        vault.delete_credential_by_id(&cred.id.to_string()).await.unwrap();
        let meta4 = vault.get_credential_metadata(&cred.id).await.unwrap();
        assert!(meta4.is_empty());
    }

    #[tokio::test]
    async fn test_sync_metadata_record_and_get() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("Sync".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        let sm = vault.record_sync_metadata(&cred.id, "sha256:abc123").await.unwrap();
        assert_eq!(sm.credential_id, cred.id);
        assert_eq!(sm.sync_hash, "sha256:abc123");

        let fetched = vault.get_sync_metadata(&cred.id).await.unwrap().unwrap();
        assert_eq!(fetched.sync_hash, "sha256:abc123");

        // Update
        vault.record_sync_metadata(&cred.id, "sha256:newval").await.unwrap();
        let updated = vault.get_sync_metadata(&cred.id).await.unwrap().unwrap();
        assert_eq!(updated.sync_hash, "sha256:newval");
    }

    #[tokio::test]
    async fn test_sync_metadata_none_before_first_sync() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("NoSync".into(), None, "pass".into(), None, None)
            .await
            .unwrap();
        assert!(vault.get_sync_metadata(&cred.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_sync_metadata_cascade_delete() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("CascadeSync".into(), None, "pass".into(), None, None)
            .await
            .unwrap();
        vault.record_sync_metadata(&cred.id, "hash1").await.unwrap();

        vault.delete_credential_by_id(&cred.id.to_string()).await.unwrap();
        assert!(vault.get_sync_metadata(&cred.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_password_and_notes_are_encrypted_at_rest() {
        let vault = init_vault().await;
        vault
            .add_credential(
                "Encrypted".into(),
                None,
                "plaintextpassword".into(),
                None,
                Some("sensitive notes".into()),
            )
            .await
            .unwrap();

        // Read raw data from PluresDB — must not contain plaintext
        let key = vault.find_credential_key_by_title("Encrypted").unwrap();
        let record = vault.store.get(&key).unwrap();
        let raw = record.data.to_string();

        assert!(
            !raw.contains("plaintextpassword"),
            "Password stored in plaintext"
        );
        assert!(
            !raw.contains("sensitive notes"),
            "Notes stored in plaintext"
        );

        // Round-trip through public API returns plaintext
        let cred = vault.get_credential("Encrypted").await.unwrap().unwrap();
        assert_eq!(cred.password, "plaintextpassword");
        assert_eq!(cred.notes.as_deref(), Some("sensitive notes"));
    }
}
