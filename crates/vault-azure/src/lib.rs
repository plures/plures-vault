//! Azure Key Vault integration for Plures Vault.
//!
//! This crate provides:
//! - [`auth::AzureAdAuthenticator`] – Azure AD client-credentials OAuth2 flow
//! - [`client::AzureKeyVaultClient`] – Azure Key Vault REST API client
//! - [`sync::AzureKvSyncManager`] – Bidirectional Plures ↔ Azure KV sync

pub mod auth;
pub mod client;
pub mod error;
pub mod sync;

pub use auth::{AzureAdAuthenticator, AzureAdConfig};
pub use client::{AzureKeyVaultClient, KeyVaultSecret, SecretListItem};
pub use error::{AzureError, AzureResult};
pub use sync::{
    AzureKvSyncManager, ConflictResolution, LocalSecretProvider, RetryConfig,
    SyncOutcome, SyncRecord, SyncReport,
};
