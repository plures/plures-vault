//! Security tests for the vault-crypto crate.
//!
//! These tests validate that cryptographic primitives behave correctly
//! and that common attack vectors are mitigated.

use vault_crypto::{CryptoError, VaultCrypto};

// ─── Key Derivation ───────────────────────────────────────────────────────────

#[test]
fn test_key_derivation_produces_32_byte_key() {
    let crypto = VaultCrypto::new();
    let (master_key, _salt) = crypto.derive_master_key("password", None).unwrap();
    // Internal key must be exactly 32 bytes (AES-256 requirement).
    // We verify indirectly: encrypting and decrypting must succeed.
    let encrypted = crypto.encrypt(&master_key, "test").unwrap();
    let decrypted = crypto.decrypt(&master_key, &encrypted).unwrap();
    assert_eq!(decrypted, "test");
}

#[test]
fn test_key_derivation_is_deterministic_with_same_salt() {
    let crypto = VaultCrypto::new();
    let password = "deterministic_password";

    let (key1, salt) = crypto.derive_master_key(password, None).unwrap();
    let (key2, _) = crypto.derive_master_key(password, Some(&salt)).unwrap();

    // Both keys derived from the same password + salt must produce the same
    // ciphertext when re-encrypted (indirectly tests key equality).
    let plaintext = "verify_determinism";
    let enc1 = crypto.encrypt(&key1, plaintext).unwrap();
    let dec2 = crypto.decrypt(&key2, &enc1).unwrap();
    assert_eq!(dec2, plaintext);
}

#[test]
fn test_different_passwords_produce_different_keys() {
    let crypto = VaultCrypto::new();
    let (key1, salt) = crypto.derive_master_key("password_a", None).unwrap();
    let (key2, _) = crypto.derive_master_key("password_b", Some(&salt)).unwrap();

    let plaintext = "cross_key_test";
    let encrypted = crypto.encrypt(&key1, plaintext).unwrap();

    // Decrypting with a different key must fail.
    let result = crypto.decrypt(&key2, &encrypted);
    assert!(
        result.is_err(),
        "Decryption with wrong key should fail but succeeded"
    );
}

#[test]
fn test_empty_password_is_rejected_by_verification_with_wrong_hash() {
    let crypto = VaultCrypto::new();
    let (_, salt) = crypto.derive_master_key("real_password", None).unwrap();

    // An empty-string password should not verify against a hash for a non-empty password.
    let fake_hash = format!(
        "$argon2id$v=19$m=19456,t=2,p=1${}$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        salt
    );
    let result = crypto.verify_password("", &salt, &fake_hash);
    assert!(result.is_err(), "Empty password should not verify");
}

// ─── Encryption / Decryption ──────────────────────────────────────────────────

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let crypto = VaultCrypto::new();
    let (key, _) = crypto.derive_master_key("roundtrip_password", None).unwrap();

    let cases = [
        "simple",
        "password with spaces",
        "sp€ci@l chars: 日本語 🔐",
        &"a".repeat(10_000),
    ];

    for plaintext in &cases {
        let encrypted = crypto.encrypt(&key, plaintext).unwrap();
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();
        assert_eq!(&decrypted, plaintext, "Roundtrip failed for: {plaintext:.40}");
    }
}

#[test]
fn test_encryption_is_non_deterministic() {
    // AES-256-GCM must use a fresh random nonce for every encryption.
    let crypto = VaultCrypto::new();
    let (key, _) = crypto.derive_master_key("nonce_test", None).unwrap();
    let plaintext = "same_plaintext";

    let enc1 = crypto.encrypt(&key, plaintext).unwrap();
    let enc2 = crypto.encrypt(&key, plaintext).unwrap();

    // Different nonces → different ciphertexts.
    assert_ne!(enc1.nonce, enc2.nonce, "Nonces must not be reused");
    assert_ne!(
        enc1.ciphertext, enc2.ciphertext,
        "Ciphertexts must differ when nonces differ"
    );

    // But both must still decrypt to the original plaintext.
    assert_eq!(crypto.decrypt(&key, &enc1).unwrap(), plaintext);
    assert_eq!(crypto.decrypt(&key, &enc2).unwrap(), plaintext);
}

#[test]
fn test_tampered_ciphertext_fails_decryption() {
    let crypto = VaultCrypto::new();
    let (key, _) = crypto.derive_master_key("tamper_test", None).unwrap();
    let mut encrypted = crypto.encrypt(&key, "sensitive_data").unwrap();

    // Flip a byte in the base64 ciphertext.
    let mut bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted.ciphertext,
    )
    .unwrap();
    bytes[0] ^= 0xFF;
    encrypted.ciphertext =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);

    let result = crypto.decrypt(&key, &encrypted);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail authentication"
    );
}

#[test]
fn test_tampered_nonce_fails_decryption() {
    let crypto = VaultCrypto::new();
    let (key, _) = crypto.derive_master_key("nonce_tamper", None).unwrap();
    let mut encrypted = crypto.encrypt(&key, "sensitive").unwrap();

    let mut nonce_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted.nonce,
    )
    .unwrap();
    nonce_bytes[0] ^= 0x01;
    encrypted.nonce =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce_bytes);

    let result = crypto.decrypt(&key, &encrypted);
    assert!(result.is_err(), "Tampered nonce should fail authentication");
}

#[test]
fn test_invalid_base64_ciphertext_returns_error() {
    use vault_crypto::EncryptedData;

    let crypto = VaultCrypto::new();
    let (key, _) = crypto.derive_master_key("b64_test", None).unwrap();

    let bad = EncryptedData {
        ciphertext: "not_valid_base64!!!".to_string(),
        nonce: "also_bad!!!".to_string(),
    };

    let result = crypto.decrypt(&key, &bad);
    assert!(
        matches!(result, Err(CryptoError::Base64Error(_))),
        "Invalid base64 should return Base64Error"
    );
}

// ─── Password Verification ────────────────────────────────────────────────────

#[test]
fn test_correct_password_verifies_successfully() {
    let crypto = VaultCrypto::new();
    let password = "correct_horse_battery_staple";

    // Derive key + get real argon2 hash string via init_vault flow (simplified):
    let (_, salt) = crypto.derive_master_key(password, None).unwrap();

    // Build the expected hash using the same argon2 instance.
    use argon2::{password_hash::SaltString, PasswordHasher};
    let salt_str = SaltString::from_b64(&salt).unwrap();
    let hash = crypto
        .argon2
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap()
        .to_string();

    let result = crypto.verify_password(password, &salt, &hash);
    assert!(result.is_ok(), "Correct password should verify: {result:?}");
}

#[test]
fn test_wrong_password_fails_verification() {
    let crypto = VaultCrypto::new();
    let password = "correct_password";
    let wrong = "wrong_password";

    let (_, salt) = crypto.derive_master_key(password, None).unwrap();

    use argon2::{password_hash::SaltString, PasswordHasher};
    let salt_str = SaltString::from_b64(&salt).unwrap();
    let hash = crypto
        .argon2
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap()
        .to_string();

    let result = crypto.verify_password(wrong, &salt, &hash);
    assert!(result.is_err(), "Wrong password must not verify");
    assert!(
        matches!(result, Err(CryptoError::Argon2Error(_))),
        "Should return Argon2Error for wrong password"
    );
}
