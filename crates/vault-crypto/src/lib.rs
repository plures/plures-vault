use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::{OsRng, RngCore}, SaltString};
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

    /// Encrypt data using AES-256-GCM with a caller-supplied nonce.
    ///
    /// Reusing a nonce with the same key is catastrophic for AES-GCM security.
    /// This method is test-only and not compiled into release builds.
    #[cfg(test)]
    fn encrypt_with_nonce(
        &self,
        master_key: &MasterKey,
        plaintext: &str,
        nonce_bytes: &[u8; 12],
    ) -> Result<EncryptedData, CryptoError> {
        // Require exactly 32 bytes for AES-256
        let key_bytes: [u8; 32] = master_key
            .key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
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

/// Generate a cryptographically random recovery key (32 bytes, base64-encoded).
pub fn generate_recovery_key() -> String {
    let mut key = [0u8; 32];
    RngCore::fill_bytes(&mut OsRng, &mut key);
    general_purpose::STANDARD.encode(key)
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

// ---------------------------------------------------------------------------
// Deterministic Test Vectors & Cryptographic Validation Suite
// ---------------------------------------------------------------------------
#[cfg(test)]
mod deterministic_vectors {
    use super::*;

    /// Fixed salt for deterministic Argon2 key derivation tests.
    /// 16 bytes, base64-encoded without padding as required by PHC string format.
    const FIXED_SALT: &str = "c2FsdHNhbHRzYWx0c2FsdA";

    // -- Argon2 deterministic key derivation --------------------------------

    #[test]
    fn argon2_derivation_is_deterministic_with_fixed_salt() {
        let crypto = VaultCrypto::new();
        let password = "deterministic_test_password";

        let (key_a, salt_a) = crypto.derive_master_key(password, Some(FIXED_SALT)).unwrap();
        let (key_b, salt_b) = crypto.derive_master_key(password, Some(FIXED_SALT)).unwrap();

        assert_eq!(salt_a, salt_b, "salts must match when provided explicitly");
        assert_eq!(key_a.key, key_b.key, "derived keys must be identical for same password+salt");
    }

    #[test]
    fn argon2_different_passwords_yield_different_keys() {
        let crypto = VaultCrypto::new();

        let (key_a, _) = crypto.derive_master_key("password_one", Some(FIXED_SALT)).unwrap();
        let (key_b, _) = crypto.derive_master_key("password_two", Some(FIXED_SALT)).unwrap();

        assert_ne!(key_a.key, key_b.key, "different passwords must produce different keys");
    }

    #[test]
    fn argon2_different_salts_yield_different_keys() {
        let crypto = VaultCrypto::new();
        let alt_salt = "YW5vdGhlcnNhbHR2YWx1ZQ";

        let (key_a, _) = crypto.derive_master_key("same_password", Some(FIXED_SALT)).unwrap();
        let (key_b, _) = crypto.derive_master_key("same_password", Some(alt_salt)).unwrap();

        assert_ne!(key_a.key, key_b.key, "different salts must produce different keys");
    }

    #[test]
    fn argon2_key_length_is_32_bytes() {
        let crypto = VaultCrypto::new();
        let (key, _) = crypto.derive_master_key("any_password", Some(FIXED_SALT)).unwrap();

        assert_eq!(key.key.len(), 32, "Argon2 output must be 32 bytes for AES-256");
    }

    #[test]
    fn argon2_snapshot_vector() {
        // Hardcoded expected value for Argon2id with default params, fixed salt, and
        // password "snapshot_password". If this breaks, Argon2 params or lib changed.
        const EXPECTED_KEY_B64: &str = "NWhFTVssGiDZvl4utXUim1C/hZ2w7KheSo8SJ+3tby0=";

        let crypto = VaultCrypto::new();
        let (key, _) = crypto.derive_master_key("snapshot_password", Some(FIXED_SALT)).unwrap();
        let encoded = general_purpose::STANDARD.encode(&key.key);

        assert_eq!(encoded, EXPECTED_KEY_B64, "Argon2 snapshot vector changed — check params/library version");
    }

    // -- AES-256-GCM deterministic encryption --------------------------------

    fn fixed_nonce() -> [u8; 12] {
        // 12-byte all-zero nonce — for deterministic test vectors only (never reuse a nonce with the same key in production).
        [0u8; 12]
    }

    fn test_master_key() -> MasterKey {
        // Deterministic 32-byte key for AES test vectors.
        MasterKey {
            key: vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ],
        }
    }

    #[test]
    fn aes_gcm_deterministic_roundtrip() {
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();
        let plaintext = "hello world";

        let encrypted = crypto.encrypt_with_nonce(&key, plaintext, &nonce).unwrap();
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_ciphertext_is_deterministic() {
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();
        let plaintext = "deterministic payload";

        let enc_a = crypto.encrypt_with_nonce(&key, plaintext, &nonce).unwrap();
        let enc_b = crypto.encrypt_with_nonce(&key, plaintext, &nonce).unwrap();

        assert_eq!(enc_a.ciphertext, enc_b.ciphertext, "ciphertext must be identical for same key+nonce+plaintext");
        assert_eq!(enc_a.nonce, enc_b.nonce);
    }

    #[test]
    fn aes_gcm_snapshot_vector() {
        // Record the expected ciphertext for a known key/nonce/plaintext triple.
        // If this test breaks, the AES-GCM implementation has changed.
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();
        let plaintext = "snapshot";

        let encrypted = crypto.encrypt_with_nonce(&key, plaintext, &nonce).unwrap();

        // Hardcoded expected ciphertext for key 0x00..0x1f, zero nonce, plaintext "snapshot".
        const EXPECTED_CT: &str = "fdLUrsZE7Mk4OC4/CP+0RN3mtlUYVVgs";
        const EXPECTED_NONCE: &str = "AAAAAAAAAAAAAAAA";

        assert_eq!(encrypted.ciphertext, EXPECTED_CT, "AES-GCM snapshot ciphertext changed — check library version");
        assert_eq!(encrypted.nonce, EXPECTED_NONCE);

        // Verify decryption of the snapshot.
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // -- Tamper / integrity validation --------------------------------------

    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();

        let encrypted = crypto.encrypt_with_nonce(&key, "integrity check", &nonce).unwrap();

        // Flip a byte in the ciphertext.
        let mut raw = general_purpose::STANDARD.decode(&encrypted.ciphertext).unwrap();
        raw[0] ^= 0xff;
        let tampered = EncryptedData {
            ciphertext: general_purpose::STANDARD.encode(&raw),
            nonce: encrypted.nonce.clone(),
        };

        let result = crypto.decrypt(&key, &tampered);
        assert!(result.is_err(), "decryption must fail on tampered ciphertext");
    }

    #[test]
    fn aes_gcm_tampered_nonce_fails() {
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();

        let encrypted = crypto.encrypt_with_nonce(&key, "nonce check", &nonce).unwrap();

        // Flip a byte in the nonce.
        let mut raw_nonce = general_purpose::STANDARD.decode(&encrypted.nonce).unwrap();
        raw_nonce[0] ^= 0xff;
        let tampered = EncryptedData {
            ciphertext: encrypted.ciphertext.clone(),
            nonce: general_purpose::STANDARD.encode(&raw_nonce),
        };

        let result = crypto.decrypt(&key, &tampered);
        assert!(result.is_err(), "decryption must fail with wrong nonce");
    }

    #[test]
    fn aes_gcm_wrong_key_fails() {
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();

        let encrypted = crypto.encrypt_with_nonce(&key, "key check", &nonce).unwrap();

        let wrong_key = MasterKey {
            key: vec![0xffu8; 32],
        };

        let result = crypto.decrypt(&wrong_key, &encrypted);
        assert!(result.is_err(), "decryption must fail with wrong key");
    }

    #[test]
    fn aes_gcm_empty_plaintext_roundtrip() {
        let crypto = VaultCrypto::new();
        let key = test_master_key();
        let nonce = fixed_nonce();

        let encrypted = crypto.encrypt_with_nonce(&key, "", &nonce).unwrap();
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, "");
    }

    // -- End-to-end: derive key then encrypt --------------------------------

    #[test]
    fn end_to_end_derive_then_encrypt_decrypt() {
        let crypto = VaultCrypto::new();
        let (key, _) = crypto.derive_master_key("e2e_password", Some(FIXED_SALT)).unwrap();
        let nonce = fixed_nonce();

        let plaintext = "end-to-end secret";
        let encrypted = crypto.encrypt_with_nonce(&key, plaintext, &nonce).unwrap();

        // Re-derive the same key and decrypt.
        let (key2, _) = crypto.derive_master_key("e2e_password", Some(FIXED_SALT)).unwrap();
        let decrypted = crypto.decrypt(&key2, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn end_to_end_wrong_password_cannot_decrypt() {
        let crypto = VaultCrypto::new();
        let (key, _) = crypto.derive_master_key("right_password", Some(FIXED_SALT)).unwrap();
        let nonce = fixed_nonce();

        let encrypted = crypto.encrypt_with_nonce(&key, "private data", &nonce).unwrap();

        // Derive key from a different password.
        let (wrong_key, _) = crypto.derive_master_key("wrong_password", Some(FIXED_SALT)).unwrap();
        let result = crypto.decrypt(&wrong_key, &encrypted);
        assert!(result.is_err(), "wrong-password-derived key must not decrypt");
    }
}