//! Integration tests for the vault-core crate.
//!
//! These tests exercise the full CRUD lifecycle of the VaultManager,
//! including encryption, decryption, and database persistence.

use std::path::PathBuf;
use vault_core::VaultManager;

/// Return a temporary in-memory SQLite database path unique to this test.
fn temp_db() -> String {
    // SQLite supports in-memory databases per connection; using a unique file-based
    // path per test avoids cross-test state while still exercising real I/O.
    let dir = std::env::temp_dir();
    let unique = uuid::Uuid::new_v4();
    let path: PathBuf = dir.join(format!("plures_vault_test_{unique}.db"));
    path.to_string_lossy().to_string()
}

// ─── Vault Initialisation ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_init_vault_succeeds() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();

    let metadata = vault.init_vault("Test Vault", "master_password").await.unwrap();
    assert_eq!(metadata.name, "Test Vault");
    assert!(!metadata.id.is_nil());
    assert!(!metadata.password_hash.is_empty());
    assert!(!metadata.salt.is_empty());
}

#[tokio::test]
async fn test_init_vault_twice_fails() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();

    vault.init_vault("Vault A", "password").await.unwrap();
    let second = vault.init_vault("Vault B", "password").await;
    assert!(
        second.is_err(),
        "Second initialisation should fail — vault already exists"
    );
}

// ─── Vault Unlock ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_unlock_with_correct_password() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "correct_password").await.unwrap();

    // Re-open (simulates a fresh session).
    let mut vault2 = VaultManager::new(&db).await.unwrap();
    assert!(!vault2.is_unlocked());
    let metadata = vault2.unlock_vault("correct_password").await.unwrap();
    assert!(vault2.is_unlocked());
    assert_eq!(metadata.name, "Vault");
}

#[tokio::test]
async fn test_unlock_with_wrong_password_fails() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "correct_password").await.unwrap();

    let mut vault2 = VaultManager::new(&db).await.unwrap();
    let result = vault2.unlock_vault("wrong_password").await;
    assert!(result.is_err(), "Wrong password must not unlock the vault");
    assert!(!vault2.is_unlocked());
}

#[tokio::test]
async fn test_unlock_uninitialised_vault_fails() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    let result = vault.unlock_vault("any_password").await;
    assert!(result.is_err(), "Unlocking an uninitialised vault must fail");
}

// ─── Lock / Unlock Cycle ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_lock_clears_master_key() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    assert!(vault.is_unlocked());
    vault.lock();
    assert!(!vault.is_unlocked());
}

// ─── Credential CRUD ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_add_and_get_credential() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    vault
        .add_credential(
            "github".to_string(),
            Some("alice".to_string()),
            "s3cr3t".to_string(),
            Some("https://github.com".to_string()),
            Some("work account".to_string()),
        )
        .await
        .unwrap();

    let cred = vault.get_credential("github").await.unwrap().expect("credential should exist");
    assert_eq!(cred.name, "github");
    assert_eq!(cred.username.as_deref(), Some("alice"));
    assert_eq!(cred.password, "s3cr3t");
    assert_eq!(cred.url.as_deref(), Some("https://github.com"));
    assert_eq!(cred.notes.as_deref(), Some("work account"));
    assert_eq!(cred.version, 1);
}

#[tokio::test]
async fn test_get_nonexistent_credential_returns_none() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    let result = vault.get_credential("does_not_exist").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_add_credential_requires_unlock() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();
    vault.lock();

    let result = vault
        .add_credential("key".to_string(), None, "value".to_string(), None, None)
        .await;
    assert!(result.is_err(), "Adding a credential on a locked vault must fail");
}

#[tokio::test]
async fn test_list_credentials() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    vault
        .add_credential("b_service".to_string(), None, "pw_b".to_string(), None, None)
        .await
        .unwrap();
    vault
        .add_credential("a_service".to_string(), None, "pw_a".to_string(), None, None)
        .await
        .unwrap();

    let list = vault.list_credentials().await.unwrap();
    assert_eq!(list.len(), 2);
    // Should be returned in alphabetical order.
    assert_eq!(list[0].name, "a_service");
    assert_eq!(list[1].name, "b_service");
    // Passwords must be decrypted in the list view.
    assert_eq!(list[0].password, "pw_a");
    assert_eq!(list[1].password, "pw_b");
}

#[tokio::test]
async fn test_update_credential() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    vault
        .add_credential(
            "service".to_string(),
            Some("old_user".to_string()),
            "old_pass".to_string(),
            None,
            None,
        )
        .await
        .unwrap();

    let updated = vault
        .update_credential(
            "service",
            Some("new_user".to_string()),
            Some("new_pass".to_string()),
            Some("https://example.com".to_string()),
            None,
        )
        .await
        .unwrap()
        .expect("updated credential should be returned");

    assert_eq!(updated.username.as_deref(), Some("new_user"));
    assert_eq!(updated.version, 2);

    // Verify persisted correctly.
    let fetched = vault.get_credential("service").await.unwrap().unwrap();
    assert_eq!(fetched.password, "new_pass");
    assert_eq!(fetched.username.as_deref(), Some("new_user"));
    assert_eq!(fetched.url.as_deref(), Some("https://example.com"));
}

#[tokio::test]
async fn test_update_nonexistent_credential_fails() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    let result = vault
        .update_credential("ghost", None, Some("pw".to_string()), None, None)
        .await;
    assert!(result.is_err(), "Updating a non-existent credential must fail");
}

#[tokio::test]
async fn test_delete_credential() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    vault
        .add_credential("to_delete".to_string(), None, "pw".to_string(), None, None)
        .await
        .unwrap();

    let deleted = vault.delete_credential("to_delete").await.unwrap();
    assert!(deleted, "delete should return true for an existing credential");

    let not_found = vault.get_credential("to_delete").await.unwrap();
    assert!(not_found.is_none(), "Deleted credential should not be retrievable");
}

#[tokio::test]
async fn test_delete_nonexistent_credential_returns_false() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "password").await.unwrap();

    let result = vault.delete_credential("ghost").await.unwrap();
    assert!(!result, "Deleting a non-existent credential must return false");
}

// ─── Encryption Persistence ───────────────────────────────────────────────────

#[tokio::test]
async fn test_password_is_stored_encrypted_and_decrypts_correctly() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Vault", "master").await.unwrap();

    let plaintext = "my_super_secret_password";
    vault
        .add_credential("acme".to_string(), None, plaintext.to_string(), None, None)
        .await
        .unwrap();

    // Re-open and unlock to confirm round-trip persistence.
    let mut vault2 = VaultManager::new(&db).await.unwrap();
    vault2.unlock_vault("master").await.unwrap();

    let cred = vault2.get_credential("acme").await.unwrap().unwrap();
    assert_eq!(
        cred.password, plaintext,
        "Persisted + re-opened credential must decrypt to original plaintext"
    );
}

// ─── Vault Metadata ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_vault_metadata() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("My Vault", "password").await.unwrap();

    let metadata = vault.get_vault_metadata().await.unwrap();
    assert_eq!(metadata.name, "My Vault");
    assert!(!metadata.id.is_nil());
}
