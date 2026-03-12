//! Performance tests for the vault-core crate.
//!
//! These tests validate that core operations meet the minimum performance
//! requirements for production use with 1000+ credentials.
//!
//! Thresholds:
//! - Encrypt 1 credential  : < 100 ms
//! - Add 100 credentials   : < 10 s
//! - Add 1 000 credentials : < 60 s
//! - List 1 000 credentials: < 5 s
//! - Get single credential : < 500 ms

use std::path::PathBuf;
use std::time::{Duration, Instant};
use vault_core::VaultManager;

fn temp_db() -> String {
    let dir = std::env::temp_dir();
    let unique = uuid::Uuid::new_v4();
    let path: PathBuf = dir.join(format!("plures_vault_perf_{unique}.db"));
    path.to_string_lossy().to_string()
}

fn assert_within(label: &str, elapsed: Duration, threshold: Duration) {
    println!("[perf] {label}: {:.3}s (threshold: {:.3}s)", elapsed.as_secs_f64(), threshold.as_secs_f64());
    if elapsed > threshold {
        // Print a clearly parseable marker so the CI workflow can grep for it.
        eprintln!("PERFORMANCE REGRESSION: {label} took {:.3}s but threshold is {:.3}s",
            elapsed.as_secs_f64(), threshold.as_secs_f64());
        panic!(
            "PERFORMANCE REGRESSION: '{label}' took {:.3}s, expected < {:.3}s",
            elapsed.as_secs_f64(),
            threshold.as_secs_f64()
        );
    }
}

// ─── Single Operation ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_single_encryption_under_100ms() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Perf Vault", "password").await.unwrap();

    let start = Instant::now();
    vault
        .add_credential(
            "benchmark_cred".to_string(),
            Some("user".to_string()),
            "password123".to_string(),
            Some("https://example.com".to_string()),
            None,
        )
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_within("single credential encryption+insert", elapsed, Duration::from_millis(100));
}

#[tokio::test]
async fn test_get_credential_under_500ms() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Perf Vault", "password").await.unwrap();

    vault
        .add_credential("target".to_string(), None, "secret".to_string(), None, None)
        .await
        .unwrap();

    let start = Instant::now();
    let result = vault.get_credential("target").await.unwrap();
    let elapsed = start.elapsed();

    assert!(result.is_some());
    assert_within("get single credential", elapsed, Duration::from_millis(500));
}

// ─── Bulk Operations ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_add_100_credentials_under_10s() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Perf Vault", "password").await.unwrap();

    let start = Instant::now();
    for i in 0..100 {
        vault
            .add_credential(
                format!("service_{i:03}"),
                Some(format!("user_{i}")),
                format!("password_{i}"),
                Some(format!("https://service{i}.example.com")),
                None,
            )
            .await
            .unwrap();
    }
    let elapsed = start.elapsed();

    assert_within("add 100 credentials", elapsed, Duration::from_secs(10));
}

#[tokio::test]
async fn test_add_1000_credentials_under_60s() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Perf Vault", "password").await.unwrap();

    let start = Instant::now();
    for i in 0..1000 {
        vault
            .add_credential(
                format!("bulk_service_{i:04}"),
                Some(format!("user_{i}")),
                format!("password_{i}_{}", uuid::Uuid::new_v4()),
                None,
                None,
            )
            .await
            .unwrap();
    }
    let elapsed = start.elapsed();

    assert_within("add 1000 credentials", elapsed, Duration::from_secs(60));
}

#[tokio::test]
async fn test_list_1000_credentials_under_5s() {
    let db = temp_db();
    let mut vault = VaultManager::new(&db).await.unwrap();
    vault.init_vault("Perf Vault", "password").await.unwrap();

    // Populate the vault.
    for i in 0..1000 {
        vault
            .add_credential(
                format!("list_service_{i:04}"),
                None,
                format!("pw_{i}"),
                None,
                None,
            )
            .await
            .unwrap();
    }

    let start = Instant::now();
    let credentials = vault.list_credentials().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(credentials.len(), 1000);
    assert_within("list 1000 credentials", elapsed, Duration::from_secs(5));
}
