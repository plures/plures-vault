//! Enterprise features for Plures Vault.
//!
//! This crate provides:
//! - [`license`] – License validation, tier enforcement, and graceful degradation
//! - [`audit`] – Structured audit logging with pluggable sinks
//! - [`partition`] – Multi-partition / multi-Key-Vault management

pub mod audit;
pub mod error;
pub mod license;
pub mod partition;

pub use audit::{
    AuditCategory, AuditEntry, AuditLogger, AuditOutcome, AuditSink, InMemoryAuditSink,
    JsonLineAuditSink,
};
pub use error::{EnterpriseError, EnterpriseResult};
pub use license::{Feature, License, LicenseManager, LicenseTier};
pub use partition::{
    CreatePartitionRequest, Partition, PartitionIsolation, PartitionManager, PartitionStatus,
};
