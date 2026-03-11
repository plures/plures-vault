use vault_crypto::{VaultCrypto, MasterKey, EncryptedData, CryptoError};
use argon2::{password_hash::SaltString, PasswordHasher};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, Row};
use anyhow::Result;
use thiserror::Error;

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
    #[error("Invalid master password")]
    InvalidMasterPassword,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub password: String, // Always encrypted
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub password_hash: String,
    pub salt: String,
}

pub struct VaultManager {
    pool: SqlitePool,
    crypto: VaultCrypto,
    master_key: Option<MasterKey>,
}

impl VaultManager {
    pub async fn new(database_path: &str) -> Result<Self> {
        let database_url = format!("sqlite:{}", database_path);
        let pool = SqlitePool::connect(&database_url).await?;
        
        // Create tables if they don't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                username TEXT,
                password TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            pool,
            crypto: VaultCrypto::new(),
            master_key: None,
        })
    }

    pub async fn init_vault(&mut self, vault_name: &str, master_password: &str) -> Result<VaultMetadata> {
        // Check if vault already exists
        let existing = sqlx::query("SELECT COUNT(*) as count FROM vault_metadata")
            .fetch_one(&self.pool)
            .await?;
        
        if existing.get::<i64, _>("count") > 0 {
            return Err(VaultError::DatabaseError(sqlx::Error::Protocol("Vault already initialized".to_string())).into());
        }

        // Derive master key and get salt
        let (master_key, salt) = self.crypto.derive_master_key(master_password, None)?;
        
        // Create password hash for verification (store the full argon2 hash)
        let salt_string = SaltString::from_b64(&salt).map_err(|e: argon2::password_hash::Error| CryptoError::Argon2Error(e.to_string()))?;
        let password_hash = self.crypto.argon2.hash_password(master_password.as_bytes(), &salt_string).map_err(|e| CryptoError::Argon2Error(e.to_string()))?;
        let password_hash_string = password_hash.to_string();

        let metadata = VaultMetadata {
            id: Uuid::new_v4(),
            name: vault_name.to_string(),
            created_at: Utc::now(),
            password_hash: password_hash_string,
            salt,
        };

        // Store vault metadata
        sqlx::query(
            r#"
            INSERT INTO vault_metadata (id, name, created_at, password_hash, salt)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(metadata.id.to_string())
        .bind(&metadata.name)
        .bind(metadata.created_at.to_rfc3339())
        .bind(&metadata.password_hash)
        .bind(&metadata.salt)
        .execute(&self.pool)
        .await?;

        // Store the master key for this session
        self.master_key = Some(master_key);

        Ok(metadata)
    }

    pub async fn unlock_vault(&mut self, master_password: &str) -> Result<VaultMetadata> {
        // Get vault metadata
        let row = sqlx::query("SELECT * FROM vault_metadata LIMIT 1")
            .fetch_optional(&self.pool)
            .await?
            .ok_or(VaultError::VaultNotInitialized)?;

        let metadata = VaultMetadata {
            id: Uuid::parse_str(&row.get::<String, _>("id"))?,
            name: row.get("name"),
            created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
            password_hash: row.get("password_hash"),
            salt: row.get("salt"),
        };

        // Verify password and derive master key
        let master_key = self.crypto.verify_password(master_password, &metadata.salt, &metadata.password_hash)
            .map_err(|_| VaultError::InvalidMasterPassword)?;

        self.master_key = Some(master_key);
        Ok(metadata)
    }

    pub async fn add_credential(
        &self,
        name: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Result<Credential> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultNotInitialized)?;

        // Encrypt the password
        let encrypted_password = self.crypto.encrypt(master_key, &password)?;
        let encrypted_password_json = serde_json::to_string(&encrypted_password)?;

        let credential = Credential {
            id: Uuid::new_v4(),
            name: name.clone(),
            username,
            password: encrypted_password_json,
            url,
            notes,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
        };

        sqlx::query(
            r#"
            INSERT INTO credentials (id, name, username, password, url, notes, created_at, updated_at, version)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        )
        .bind(credential.id.to_string())
        .bind(&credential.name)
        .bind(&credential.username)
        .bind(&credential.password)
        .bind(&credential.url)
        .bind(&credential.notes)
        .bind(credential.created_at.to_rfc3339())
        .bind(credential.updated_at.to_rfc3339())
        .bind(credential.version as i64)
        .execute(&self.pool)
        .await?;

        Ok(credential)
    }

    pub async fn get_credential(&self, name: &str) -> Result<Option<Credential>> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultNotInitialized)?;

        let row = sqlx::query("SELECT * FROM credentials WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let encrypted_password_json: String = row.get("password");
            let encrypted_password: EncryptedData = serde_json::from_str(&encrypted_password_json)?;
            let decrypted_password = self.crypto.decrypt(master_key, &encrypted_password)?;

            Ok(Some(Credential {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                name: row.get("name"),
                username: row.get("username"),
                password: decrypted_password,
                url: row.get("url"),
                notes: row.get("notes"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?.with_timezone(&Utc),
                version: row.get::<i64, _>("version") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn list_credentials(&self) -> Result<Vec<Credential>> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultNotInitialized)?;

        let rows = sqlx::query("SELECT * FROM credentials ORDER BY name")
            .fetch_all(&self.pool)
            .await?;

        let mut credentials = Vec::new();
        
        for row in rows {
            let encrypted_password_json: String = row.get("password");
            let encrypted_password: EncryptedData = serde_json::from_str(&encrypted_password_json)?;
            let decrypted_password = self.crypto.decrypt(master_key, &encrypted_password)?;

            credentials.push(Credential {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                name: row.get("name"),
                username: row.get("username"),
                password: decrypted_password,
                url: row.get("url"),
                notes: row.get("notes"),
                created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))?.with_timezone(&Utc),
                version: row.get::<i64, _>("version") as u64,
            });
        }

        Ok(credentials)
    }

    pub async fn delete_credential(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn update_credential(
        &self,
        name: &str,
        new_username: Option<String>,
        new_password: Option<String>,
        new_url: Option<String>,
        new_notes: Option<String>,
    ) -> Result<Option<Credential>> {
        let master_key = self.master_key.as_ref().ok_or(VaultError::VaultNotInitialized)?;

        // First check if credential exists
        let existing = self.get_credential(name).await?;
        let mut credential = existing.ok_or_else(|| VaultError::CredentialNotFound(name.to_string()))?;

        // Update fields if provided
        if let Some(username) = new_username {
            credential.username = Some(username);
        }
        if let Some(url) = new_url {
            credential.url = Some(url);
        }
        if let Some(notes) = new_notes {
            credential.notes = Some(notes);
        }

        let encrypted_password_json = if let Some(new_password) = new_password {
            let encrypted_password = self.crypto.encrypt(master_key, &new_password)?;
            serde_json::to_string(&encrypted_password)?
        } else {
            // Re-encrypt existing password (to update with any crypto changes)
            let encrypted_password = self.crypto.encrypt(master_key, &credential.password)?;
            serde_json::to_string(&encrypted_password)?
        };

        credential.updated_at = Utc::now();
        credential.version += 1;
        credential.password = encrypted_password_json.clone();

        sqlx::query(
            r#"
            UPDATE credentials 
            SET username = ?1, password = ?2, url = ?3, notes = ?4, updated_at = ?5, version = ?6
            WHERE name = ?7
            "#,
        )
        .bind(&credential.username)
        .bind(&encrypted_password_json)
        .bind(&credential.url)
        .bind(&credential.notes)
        .bind(credential.updated_at.to_rfc3339())
        .bind(credential.version as i64)
        .bind(name)
        .execute(&self.pool)
        .await?;

        Ok(Some(credential))
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn lock(&mut self) {
        self.master_key = None;
    }

    pub async fn get_vault_metadata(&self) -> Result<VaultMetadata> {
        // Get vault metadata  
        let row = sqlx::query("SELECT * FROM vault_metadata LIMIT 1")
            .fetch_optional(&self.pool)
            .await?
            .ok_or(VaultError::VaultNotInitialized)?;

        let metadata = VaultMetadata {
            id: Uuid::parse_str(&row.get::<String, _>("id"))?,
            name: row.get("name"),
            created_at: DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))?.with_timezone(&Utc),
            password_hash: row.get("password_hash"),
            salt: row.get("salt"),
        };

        Ok(metadata)
    }

    pub async fn check_initialization(&self) -> Result<VaultMetadata> {
        // Same as get_vault_metadata but for backward compatibility
        self.get_vault_metadata().await
    }
}