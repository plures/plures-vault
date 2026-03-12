use thiserror::Error;

/// Errors that can occur during enterprise operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum EnterpriseError {
    #[error("License is invalid: {0}")]
    InvalidLicense(String),

    #[error("License has expired")]
    LicenseExpired,

    #[error("License limit exceeded: {0}")]
    LicenseLimitExceeded(String),

    #[error("Partition not found: {0}")]
    PartitionNotFound(String),

    #[error("Partition already exists: {0}")]
    PartitionAlreadyExists(String),

    #[error("Audit log error: {0}")]
    AuditError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

pub type EnterpriseResult<T> = Result<T, EnterpriseError>;
