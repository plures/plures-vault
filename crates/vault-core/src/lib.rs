use vault_crypto::{VaultCrypto, MasterKey, EncryptedData, CryptoError};
use argon2::{password_hash::SaltString, PasswordHasher};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use anyhow::Result;
use thiserror::Error;
use std::str::FromStr;

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    #[error("Vault not initialized")]
    VaultNotInitialized,
    #[error("Vault already initialized")]
    VaultAlreadyInitialized,
    #[error("Invalid master password")]
    InvalidMasterPassword,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Migration error: {0}")]
    MigrationError(String),
}

// ── Domain types ─────────────────────────────────────────────────────────────

/// Argon2 key-derivation parameters stored in vault_config.
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

/// Vault-level configuration (one row per database).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault_id: Uuid,
    pub version: i64,
    pub vault_name: String,
    pub salt: String,
    pub key_derivation_params: KeyDerivationParams,
    pub created_at: DateTime<Utc>,
}

/// A decrypted credential entry returned to callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    /// Plaintext password (decrypted from `encrypted_password` in the database).
    pub password: String,
    /// Plaintext notes (decrypted from `encrypted_notes` in the database).
    pub notes: Option<String>,
    pub url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A decrypted custom field attached to a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub credential_id: Uuid,
    pub key: String,
    /// Plaintext value (decrypted from `encrypted_value` in the database).
    pub value: String,
}

/// P2P sync tracking record for a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMetadata {
    pub credential_id: Uuid,
    pub last_sync: DateTime<Utc>,
    pub sync_hash: String,
}

// ── VaultManager ─────────────────────────────────────────────────────────────

pub struct VaultManager {
    pool: SqlitePool,
    crypto: VaultCrypto,
    master_key: Option<MasterKey>,
}

impl VaultManager {
    /// Open (or create) a vault database at `database_path`.
    ///
    /// Pass `":memory:"` to use an in-memory database (useful in tests).
    /// Runs all pending SQL migrations and migrates any legacy schema data.
    pub async fn new(database_path: &str) -> Result<Self> {
        let pool = if database_path == ":memory:" {
            let options = SqliteConnectOptions::from_str("sqlite::memory:")?
                .foreign_keys(true);
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await?
        } else {
            let database_url = format!("sqlite:{}", database_path);
            let options = SqliteConnectOptions::from_str(&database_url)?
                .create_if_missing(true)
                .foreign_keys(true);
            SqlitePoolOptions::new()
                .connect_with(options)
                .await?
        };

        // Run embedded SQL migrations (creates new tables).
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| VaultError::MigrationError(e.to_string()))?;

        // Migrate data from legacy schema if needed.
        migrate_legacy_schema(&pool).await?;

        Ok(Self {
            pool,
            crypto: VaultCrypto::new(),
            master_key: None,
        })
    }

    // ── Vault lifecycle ───────────────────────────────────────────────────────

    /// Initialise a new vault with `vault_name` and `master_password`.
    ///
    /// Returns an error if the vault has already been initialised.
    pub async fn init_vault(
        &mut self,
        vault_name: &str,
        master_password: &str,
    ) -> Result<VaultConfig> {
        // Guard against re-initialisation.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vault_config")
                .fetch_one(&self.pool)
                .await?;
        if count > 0 {
            return Err(VaultError::VaultAlreadyInitialized.into());
        }

        // Derive master key (new random salt) and store the full Argon2 hash.
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
        let params_json = serde_json::to_string(&params)?;
        let now = Utc::now();
        let vault_id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO vault_config (id, vault_id, version, vault_name, salt, key_derivation_params, password_hash, created_at)
            VALUES (1, ?1, 1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(vault_id.to_string())
        .bind(vault_name)
        .bind(&salt)
        .bind(&params_json)
        .bind(&password_hash)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

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

    /// Unlock the vault by verifying `master_password` against the stored hash.
    pub async fn unlock_vault(&mut self, master_password: &str) -> Result<VaultConfig> {
        let config = self.get_vault_config().await?;

        let master_key = self
            .crypto
            .verify_password(master_password, &config.salt, &self.fetch_password_hash().await?)
            .map_err(|_| VaultError::InvalidMasterPassword)?;

        self.master_key = Some(master_key);
        Ok(config)
    }

    /// Return `true` if the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    /// Lock the vault (drops the in-memory master key).
    pub fn lock(&mut self) {
        self.master_key = None;
    }

    /// Return the vault configuration (does not require unlock).
    pub async fn get_vault_config(&self) -> Result<VaultConfig> {
        let row = sqlx::query("SELECT vault_id, version, vault_name, salt, key_derivation_params, created_at FROM vault_config WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
            .ok_or(VaultError::VaultNotInitialized)?;

        let params: KeyDerivationParams =
            serde_json::from_str(&row.get::<String, _>("key_derivation_params"))?;

        Ok(VaultConfig {
            vault_id: Uuid::parse_str(&row.get::<String, _>("vault_id"))?,
            version: row.get("version"),
            vault_name: row.get("vault_name"),
            salt: row.get("salt"),
            key_derivation_params: params,
            created_at: DateTime::parse_from_rfc3339(
                &row.get::<String, _>("created_at"),
            )?
            .with_timezone(&Utc),
        })
    }

    /// Alias for `get_vault_config` kept for backwards compatibility.
    pub async fn check_initialization(&self) -> Result<VaultConfig> {
        self.get_vault_config().await
    }

    // ── Credential CRUD ───────────────────────────────────────────────────────

    /// Add a new credential.  Both `password` and `notes` are encrypted at rest.
    pub async fn add_credential(
        &self,
        title: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Result<Credential> {
        let master_key = self.require_master_key()?;

        let encrypted_password = self.encrypt_field(master_key, &password)?;
        let encrypted_notes = notes
            .as_deref()
            .map(|n| self.encrypt_field(master_key, n))
            .transpose()?;

        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO credentials (id, title, username, encrypted_password, encrypted_notes, url, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(id.to_string())
        .bind(&title)
        .bind(&username)
        .bind(&encrypted_password)
        .bind(&encrypted_notes)
        .bind(&url)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

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

    /// Retrieve a credential by its unique title (case-sensitive).
    pub async fn get_credential(&self, title: &str) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;

        let row = sqlx::query("SELECT * FROM credentials WHERE title = ?1")
            .bind(title)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| self.row_to_credential(&r, master_key))
            .transpose()
    }

    /// Retrieve a credential by its UUID.
    pub async fn get_credential_by_id(&self, id: &str) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;

        let row = sqlx::query("SELECT * FROM credentials WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| self.row_to_credential(&r, master_key))
            .transpose()
    }

    /// Return all credentials, sorted by title.
    pub async fn list_credentials(&self) -> Result<Vec<Credential>> {
        let master_key = self.require_master_key()?;

        let rows = sqlx::query("SELECT * FROM credentials ORDER BY title")
            .fetch_all(&self.pool)
            .await?;

        rows.iter()
            .map(|r| self.row_to_credential(r, master_key))
            .collect()
    }

    /// Update a credential located by `title`.
    ///
    /// Only the supplied `Some(...)` fields are updated; `None` leaves them unchanged.
    pub async fn update_credential(
        &self,
        title: &str,
        new_username: Option<String>,
        new_password: Option<String>,
        new_url: Option<String>,
        new_notes: Option<String>,
    ) -> Result<Option<Credential>> {
        let master_key = self.require_master_key()?;

        let mut credential = match self.get_credential(title).await? {
            Some(c) => c,
            None => return Ok(None),
        };

        Self::apply_updates(
            &mut credential,
            new_username,
            new_password,
            new_url,
            new_notes,
        );
        credential.updated_at = Utc::now();

        let enc_password = self.encrypt_field(master_key, &credential.password)?;
        let enc_notes = credential
            .notes
            .as_deref()
            .map(|n| self.encrypt_field(master_key, n))
            .transpose()?;

        sqlx::query(
            r#"
            UPDATE credentials
            SET username = ?1, encrypted_password = ?2, encrypted_notes = ?3,
                url = ?4, updated_at = ?5
            WHERE title = ?6
            "#,
        )
        .bind(&credential.username)
        .bind(&enc_password)
        .bind(&enc_notes)
        .bind(&credential.url)
        .bind(credential.updated_at.to_rfc3339())
        .bind(title)
        .execute(&self.pool)
        .await?;

        Ok(Some(credential))
    }

    /// Update a credential located by UUID.
    ///
    /// `new_title` renames the credential; other `Some(...)` fields overwrite
    /// existing values; `None` leaves them unchanged.
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

        let mut credential = match self.get_credential_by_id(id).await? {
            Some(c) => c,
            None => return Ok(None),
        };

        if let Some(t) = new_title {
            credential.title = t;
        }
        Self::apply_updates(
            &mut credential,
            new_username,
            new_password,
            new_url,
            new_notes,
        );
        credential.updated_at = Utc::now();

        let enc_password = self.encrypt_field(master_key, &credential.password)?;
        let enc_notes = credential
            .notes
            .as_deref()
            .map(|n| self.encrypt_field(master_key, n))
            .transpose()?;

        sqlx::query(
            r#"
            UPDATE credentials
            SET title = ?1, username = ?2, encrypted_password = ?3, encrypted_notes = ?4,
                url = ?5, updated_at = ?6
            WHERE id = ?7
            "#,
        )
        .bind(&credential.title)
        .bind(&credential.username)
        .bind(&enc_password)
        .bind(&enc_notes)
        .bind(&credential.url)
        .bind(credential.updated_at.to_rfc3339())
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(Some(credential))
    }

    /// Delete a credential by title.  Returns `true` if a row was removed.
    pub async fn delete_credential(&self, title: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE title = ?1")
            .bind(title)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete a credential by UUID.  Returns `true` if a row was removed.
    pub async fn delete_credential_by_id(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Credential metadata ───────────────────────────────────────────────────

    /// Insert or replace a custom encrypted field on a credential.
    pub async fn set_credential_metadata(
        &self,
        credential_id: &Uuid,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let master_key = self.require_master_key()?;
        let encrypted_value = self.encrypt_field(master_key, value)?;

        sqlx::query(
            r#"
            INSERT INTO credential_metadata (credential_id, key, encrypted_value)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(credential_id, key) DO UPDATE SET encrypted_value = excluded.encrypted_value
            "#,
        )
        .bind(credential_id.to_string())
        .bind(key)
        .bind(&encrypted_value)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Return all custom fields for a credential, decrypted.
    pub async fn get_credential_metadata(
        &self,
        credential_id: &Uuid,
    ) -> Result<Vec<CredentialMetadata>> {
        let master_key = self.require_master_key()?;

        let rows =
            sqlx::query("SELECT * FROM credential_metadata WHERE credential_id = ?1 ORDER BY key")
                .bind(credential_id.to_string())
                .fetch_all(&self.pool)
                .await?;

        rows.iter()
            .map(|row| {
                let encrypted_json: String = row.get("encrypted_value");
                let encrypted: EncryptedData = serde_json::from_str(&encrypted_json)?;
                let value = self.crypto.decrypt(master_key, &encrypted)?;
                Ok(CredentialMetadata {
                    credential_id: *credential_id,
                    key: row.get("key"),
                    value,
                })
            })
            .collect()
    }

    /// Delete a single custom field.  Returns `true` if a row was removed.
    pub async fn delete_credential_metadata(
        &self,
        credential_id: &Uuid,
        key: &str,
    ) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM credential_metadata WHERE credential_id = ?1 AND key = ?2")
                .bind(credential_id.to_string())
                .bind(key)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Sync metadata ─────────────────────────────────────────────────────────

    /// Record or update the sync state for a credential.
    pub async fn record_sync_metadata(
        &self,
        credential_id: &Uuid,
        sync_hash: &str,
    ) -> Result<SyncMetadata> {
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO sync_metadata (credential_id, last_sync, sync_hash)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(credential_id) DO UPDATE
                SET last_sync = excluded.last_sync, sync_hash = excluded.sync_hash
            "#,
        )
        .bind(credential_id.to_string())
        .bind(now.to_rfc3339())
        .bind(sync_hash)
        .execute(&self.pool)
        .await?;

        Ok(SyncMetadata {
            credential_id: *credential_id,
            last_sync: now,
            sync_hash: sync_hash.to_string(),
        })
    }

    /// Return the sync state for a credential, or `None` if never synced.
    pub async fn get_sync_metadata(
        &self,
        credential_id: &Uuid,
    ) -> Result<Option<SyncMetadata>> {
        let row =
            sqlx::query("SELECT * FROM sync_metadata WHERE credential_id = ?1")
                .bind(credential_id.to_string())
                .fetch_optional(&self.pool)
                .await?;

        if let Some(r) = row {
            let last_sync_str: String = r.get("last_sync");
            let last_sync = DateTime::parse_from_rfc3339(&last_sync_str)
                .map_err(|e| VaultError::MigrationError(format!("Invalid last_sync timestamp: {}", e)))?
                .with_timezone(&Utc);
            Ok(Some(SyncMetadata {
                credential_id: *credential_id,
                last_sync,
                sync_hash: r.get("sync_hash"),
            }))
        } else {
            Ok(None)
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

    fn row_to_credential(
        &self,
        row: &sqlx::sqlite::SqliteRow,
        master_key: &MasterKey,
    ) -> Result<Credential> {
        let password = self.decrypt_field(master_key, &row.get::<String, _>("encrypted_password"))?;
        let notes = row
            .get::<Option<String>, _>("encrypted_notes")
            .map(|json| self.decrypt_field(master_key, &json))
            .transpose()?;

        Ok(Credential {
            id: Uuid::parse_str(&row.get::<String, _>("id"))?,
            title: row.get("title"),
            username: row.get("username"),
            password,
            notes,
            url: row.get("url"),
            created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?
                .with_timezone(&Utc),
        })
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

    async fn fetch_password_hash(&self) -> Result<String, VaultError> {
        let hash: String =
            sqlx::query_scalar("SELECT password_hash FROM vault_config WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?
                .ok_or(VaultError::VaultNotInitialized)?;
        Ok(hash)
    }
}

// ── Legacy schema migration ───────────────────────────────────────────────────

/// Migrate data from the pre-v0.2 schema (`vault_metadata` / `credentials` with
/// a `name` column) to the current schema if the new tables are empty.
async fn migrate_legacy_schema(pool: &SqlitePool) -> Result<()> {
    migrate_legacy_vault_config(pool).await?;
    migrate_legacy_credentials(pool).await?;
    Ok(())
}

async fn table_exists(pool: &SqlitePool, name: &str) -> Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1")
            .bind(name)
            .fetch_one(pool)
            .await?;
    Ok(count > 0)
}

async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool> {
    if !table_exists(pool, table).await? {
        return Ok(false);
    }
    let rows = sqlx::query(&format!("PRAGMA table_info({})", table))
        .fetch_all(pool)
        .await?;
    for row in &rows {
        let col: String = row.get("name");
        if col == column {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn migrate_legacy_vault_config(pool: &SqlitePool) -> Result<()> {
    if !table_exists(pool, "vault_metadata").await? {
        return Ok(());
    }
    // Only migrate if vault_config is empty.
    let cfg_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_config")
        .fetch_one(pool)
        .await?;
    if cfg_count > 0 {
        return Ok(());
    }

    let row = sqlx::query("SELECT * FROM vault_metadata LIMIT 1")
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let params = KeyDerivationParams::default();
        let params_json = serde_json::to_string(&params)?;
        // Prefer the legacy vault_metadata.id to keep sync identity stable.
        // Fall back to a new UUID only if the legacy ID is missing or invalid.
        let vault_id = row
            .try_get::<String, _>("id")
            .ok()
            .and_then(|legacy_id| Uuid::parse_str(&legacy_id).ok())
            .unwrap_or_else(Uuid::new_v4);
        sqlx::query(
            r#"
            INSERT INTO vault_config (id, vault_id, version, vault_name, salt, key_derivation_params, password_hash, created_at)
            VALUES (1, ?1, 1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(vault_id.to_string())
        .bind(row.get::<String, _>("name"))
        .bind(row.get::<String, _>("salt"))
        .bind(&params_json)
        .bind(row.get::<String, _>("password_hash"))
        .bind(row.get::<String, _>("created_at"))
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn migrate_legacy_credentials(pool: &SqlitePool) -> Result<()> {
    // The old credentials table used `name` and `password` columns.
    if !column_exists(pool, "credentials", "name").await? {
        return Ok(());
    }

    // Read legacy rows.
    let rows = sqlx::query("SELECT * FROM credentials WHERE 1=1")
        .fetch_all(pool)
        .await?;

    if rows.is_empty() {
        return Ok(());
    }

    // Only attempt migration when the new-schema table does not exist yet.
    let new_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='credentials_v2'",
    )
    .fetch_one(pool)
    .await?;
    if new_count > 0 {
        return Ok(());
    }

    // Wrap the entire table-swap in a transaction to prevent data loss if a
    // crash or error occurs between the DROP and RENAME steps.
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        CREATE TABLE credentials_v2 (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL UNIQUE,
            username TEXT,
            encrypted_password TEXT NOT NULL,
            encrypted_notes TEXT,
            url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&mut *tx)
    .await?;

    for row in &rows {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO credentials_v2
                (id, title, username, encrypted_password, encrypted_notes, url, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)
            "#,
        )
        .bind(row.get::<String, _>("id"))
        .bind(row.get::<String, _>("name"))
        .bind(row.get::<Option<String>, _>("username"))
        // `password` column held an EncryptedData JSON blob — keep as encrypted_password.
        .bind(row.get::<String, _>("password"))
        // Old `notes` were stored as plaintext; we cannot re-encrypt without the master
        // key at migration time, so they are dropped rather than stored as corrupt ciphertext.
        .bind(row.get::<Option<String>, _>("url"))
        .bind(row.get::<String, _>("created_at"))
        .bind(row.get::<String, _>("updated_at"))
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query("DROP TABLE credentials")
        .execute(&mut *tx)
        .await?;
    sqlx::query("ALTER TABLE credentials_v2 RENAME TO credentials")
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
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

    // ── Vault lifecycle tests ─────────────────────────────────────────────────

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

        // Lock the same vault instance.
        vault.lock();
        assert!(!vault.is_unlocked());

        // All credential operations must fail while the vault is locked.
        assert!(vault
            .add_credential("x".into(), None, "y".into(), None, None)
            .await
            .is_err());
        assert!(vault.get_credential("cred").await.is_err());
        assert!(vault.list_credentials().await.is_err());
    }

    // ── Credential CRUD tests ─────────────────────────────────────────────────

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
        vault
            .add_credential("Zebra".into(), None, "z".into(), None, None)
            .await
            .unwrap();
        vault
            .add_credential("Alpha".into(), None, "a".into(), None, None)
            .await
            .unwrap();
        vault
            .add_credential("Middle".into(), None, "m".into(), None, None)
            .await
            .unwrap();

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

        // Verify persisted.
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
        vault
            .add_credential("ToDelete".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        assert!(vault.delete_credential("ToDelete").await.unwrap());
        assert!(vault.get_credential("ToDelete").await.unwrap().is_none());
        // Second delete returns false.
        assert!(!vault.delete_credential("ToDelete").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_credential_by_id() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("ByID".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        assert!(vault
            .delete_credential_by_id(&cred.id.to_string())
            .await
            .unwrap());
        assert!(vault
            .get_credential_by_id(&cred.id.to_string())
            .await
            .unwrap()
            .is_none());
    }

    // ── Credential metadata tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_credential_metadata_set_get_delete() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("Meta".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        vault
            .set_credential_metadata(&cred.id, "2fa_seed", "JBSWY3DPEHPK3PXP")
            .await
            .unwrap();
        vault
            .set_credential_metadata(&cred.id, "recovery_code", "abc-123")
            .await
            .unwrap();

        let meta = vault.get_credential_metadata(&cred.id).await.unwrap();
        assert_eq!(meta.len(), 2);
        let m0 = meta.iter().find(|m| m.key == "2fa_seed").unwrap();
        assert_eq!(m0.value, "JBSWY3DPEHPK3PXP");

        // Upsert.
        vault
            .set_credential_metadata(&cred.id, "2fa_seed", "NEWSEED")
            .await
            .unwrap();
        let meta2 = vault.get_credential_metadata(&cred.id).await.unwrap();
        let updated = meta2.iter().find(|m| m.key == "2fa_seed").unwrap();
        assert_eq!(updated.value, "NEWSEED");

        // Delete one key.
        assert!(vault
            .delete_credential_metadata(&cred.id, "recovery_code")
            .await
            .unwrap());
        let meta3 = vault.get_credential_metadata(&cred.id).await.unwrap();
        assert_eq!(meta3.len(), 1);

        // Cascade delete: removing the credential deletes its metadata.
        vault.delete_credential_by_id(&cred.id.to_string()).await.unwrap();
        let meta4 = vault.get_credential_metadata(&cred.id).await.unwrap();
        assert!(meta4.is_empty());
    }

    // ── Sync metadata tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_sync_metadata_record_and_get() {
        let vault = init_vault().await;
        let cred = vault
            .add_credential("Sync".into(), None, "pass".into(), None, None)
            .await
            .unwrap();

        let sm = vault
            .record_sync_metadata(&cred.id, "sha256:abc123")
            .await
            .unwrap();
        assert_eq!(sm.credential_id, cred.id);
        assert_eq!(sm.sync_hash, "sha256:abc123");

        let fetched = vault.get_sync_metadata(&cred.id).await.unwrap().unwrap();
        assert_eq!(fetched.sync_hash, "sha256:abc123");

        // Update idempotency.
        vault
            .record_sync_metadata(&cred.id, "sha256:newval")
            .await
            .unwrap();
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
        vault
            .record_sync_metadata(&cred.id, "hash1")
            .await
            .unwrap();

        vault.delete_credential_by_id(&cred.id.to_string()).await.unwrap();
        assert!(vault.get_sync_metadata(&cred.id).await.unwrap().is_none());
    }

    // ── Encryption at rest ────────────────────────────────────────────────────

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

        // Read raw bytes from the database — must not contain plaintext.
        let enc_password: String =
            sqlx::query_scalar("SELECT encrypted_password FROM credentials WHERE title = 'Encrypted'")
                .fetch_one(&vault.pool)
                .await
                .unwrap();
        let enc_notes: String =
            sqlx::query_scalar("SELECT encrypted_notes FROM credentials WHERE title = 'Encrypted'")
                .fetch_one(&vault.pool)
                .await
                .unwrap();

        assert!(
            !enc_password.contains("plaintextpassword"),
            "Password stored in plaintext"
        );
        assert!(
            !enc_notes.contains("sensitive notes"),
            "Notes stored in plaintext"
        );

        // Round-trip through the public API returns plaintext.
        let cred = vault.get_credential("Encrypted").await.unwrap().unwrap();
        assert_eq!(cred.password, "plaintextpassword");
        assert_eq!(cred.notes.as_deref(), Some("sensitive notes"));
    }
}