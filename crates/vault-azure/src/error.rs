use thiserror::Error;

/// Errors that can occur during Azure Key Vault operations.
#[derive(Error, Debug)]
pub enum AzureError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Azure Key Vault API error (status {status}): {message}")]
    ApiError { status: u16, message: String },

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("HTTP client error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Sync conflict: local version {local} vs remote version {remote}")]
    SyncConflict { local: u64, remote: u64 },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    #[error("Token expired or invalid")]
    TokenExpired,

    #[error("Partition not found: {0}")]
    PartitionNotFound(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] vault_crypto::CryptoError),
}

/// Result alias for Azure operations.
pub type AzureResult<T> = Result<T, AzureError>;
