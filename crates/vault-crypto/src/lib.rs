use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, AeadCore};
use zeroize::ZeroizeOnDrop;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use base64::{Engine as _, engine::general_purpose};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Argon2 password hashing failed: {0}")]
    Argon2Error(String),
    #[error("AES encryption failed")]
    EncryptionError,
    #[error("AES decryption failed")]
    DecryptionError,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

impl From<argon2::password_hash::Error> for CryptoError {
    fn from(err: argon2::password_hash::Error) -> Self {
        CryptoError::Argon2Error(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct MasterKey {
    #[zeroize(skip)]
    key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: String,
    pub nonce: String,
}

pub struct VaultCrypto {
    pub argon2: Argon2<'static>,
}

impl VaultCrypto {
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Derive master key from password using Argon2
    pub fn derive_master_key(&self, password: &str, salt: Option<&str>) -> Result<(MasterKey, String), CryptoError> {
        let salt = if let Some(s) = salt {
            SaltString::from_b64(s)?
        } else {
            SaltString::generate(&mut OsRng)
        };

        let password_hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        
        // Extract the raw hash bytes for the key
        let hash = password_hash.hash.ok_or(CryptoError::InvalidKeyLength)?;
        let key_bytes = hash.as_bytes().to_vec();
        
        Ok((
            MasterKey { key: key_bytes },
            salt.as_str().to_string()
        ))
    }

    /// Verify password against stored salt
    pub fn verify_password(&self, password: &str, salt: &str, expected_hash: &str) -> Result<MasterKey, CryptoError> {
        let salt = SaltString::from_b64(salt)?;
        let password_hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        
        // Create PasswordHash from the expected hash string
        let expected = PasswordHash::new(expected_hash)?;
        
        // Verify the password
        self.argon2.verify_password(password.as_bytes(), &expected)?;
        
        // If verification succeeds, return the derived key
        let hash = password_hash.hash.ok_or(CryptoError::InvalidKeyLength)?;
        Ok(MasterKey { 
            key: hash.as_bytes().to_vec() 
        })
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(&self, master_key: &MasterKey, plaintext: &str) -> Result<EncryptedData, CryptoError> {
        // Ensure we have exactly 32 bytes for AES-256
        let mut key_bytes = [0u8; 32];
        let len = std::cmp::min(master_key.key.len(), 32);
        key_bytes[..len].copy_from_slice(&master_key.key[..len]);
        
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionError)?;

        Ok(EncryptedData {
            ciphertext: general_purpose::STANDARD.encode(&ciphertext),
            nonce: general_purpose::STANDARD.encode(nonce),
        })
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(&self, master_key: &MasterKey, encrypted: &EncryptedData) -> Result<String, CryptoError> {
        // Ensure we have exactly 32 bytes for AES-256
        let mut key_bytes = [0u8; 32];
        let len = std::cmp::min(master_key.key.len(), 32);
        key_bytes[..len].copy_from_slice(&master_key.key[..len]);
        
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        
        let ciphertext = general_purpose::STANDARD.decode(&encrypted.ciphertext)?;
        let nonce_bytes = general_purpose::STANDARD.decode(&encrypted.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionError)?;

        String::from_utf8(plaintext)
            .map_err(|_| CryptoError::DecryptionError)
    }
}

impl Default for VaultCrypto {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_and_encryption() {
        let crypto = VaultCrypto::new();
        let password = "test_password_123";
        
        // Derive master key
        let (master_key, salt) = crypto.derive_master_key(password, None).unwrap();
        
        // Test encryption/decryption
        let plaintext = "secret credential data";
        let encrypted = crypto.encrypt(&master_key, plaintext).unwrap();
        let decrypted = crypto.decrypt(&master_key, &encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
        
        // Generate a proper password hash for verification
        let salt_string = SaltString::from_b64(&salt).unwrap();
        let password_hash = crypto.argon2.hash_password(password.as_bytes(), &salt_string).unwrap();
        let password_hash_string = password_hash.to_string();

        let verified_key = crypto.verify_password(password, &salt, &password_hash_string);
        assert!(verified_key.is_ok());
    }

    #[test]
    fn test_wrong_password_fails() {
        let crypto = VaultCrypto::new();
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let (_, salt) = crypto.derive_master_key(password, None).unwrap();
        let password_hash = format!("$argon2id$v=19$m=19456,t=2,p=1${}", salt);
        
        let result = crypto.verify_password(wrong_password, &salt, &password_hash);
        assert!(result.is_err());
    }
}