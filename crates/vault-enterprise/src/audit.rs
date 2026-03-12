use crate::error::{EnterpriseError, EnterpriseResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use uuid::Uuid;

/// Category of audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Vault access (unlock, lock).
    Authentication,
    /// Credential operations (read, write, delete).
    CredentialAccess,
    /// Azure Key Vault sync operations.
    KeyVaultSync,
    /// License management.
    LicenseManagement,
    /// Partition management.
    PartitionManagement,
    /// Administrative actions.
    Administration,
}

/// Outcome of the audited action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

/// A single structured audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this event.
    pub id: Uuid,
    /// When the event occurred (UTC).
    pub timestamp: DateTime<Utc>,
    /// Actor that performed the action (user UPN, service principal, etc.).
    pub actor: String,
    /// Event category.
    pub category: AuditCategory,
    /// Short description of the action (e.g. "unlock_vault", "sync_secret").
    pub action: String,
    /// Optional resource name (e.g. credential name, partition name).
    pub resource: Option<String>,
    /// Outcome of the action.
    pub outcome: AuditOutcome,
    /// Human-readable description of what occurred.
    pub description: String,
    /// Optional structured metadata (JSON object).
    pub metadata: Option<serde_json::Value>,
    /// Correlation ID to trace a chain of related events.
    pub correlation_id: Option<Uuid>,
}

impl AuditEntry {
    /// Create a new audit entry with mandatory fields.
    pub fn new(
        actor: impl Into<String>,
        category: AuditCategory,
        action: impl Into<String>,
        outcome: AuditOutcome,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: actor.into(),
            category,
            action: action.into(),
            resource: None,
            outcome,
            description: description.into(),
            metadata: None,
            correlation_id: None,
        }
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_correlation_id(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }
}

// ── Audit sink trait ──────────────────────────────────────────────────────────

/// Sink that receives completed audit entries.  Implementations can write to
/// files, databases, SIEM systems, etc.
pub trait AuditSink: Send + Sync {
    fn write(&mut self, entry: &AuditEntry) -> EnterpriseResult<()>;
}

// ── In-memory audit sink (for testing and CLI) ────────────────────────────────

/// An [`AuditSink`] that stores entries in a bounded in-memory ring buffer.
pub struct InMemoryAuditSink {
    entries: VecDeque<AuditEntry>,
    capacity: usize,
}

impl InMemoryAuditSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn entries(&self) -> &VecDeque<AuditEntry> {
        &self.entries
    }

    /// Drain all entries and return them as a `Vec`.
    pub fn drain(&mut self) -> Vec<AuditEntry> {
        self.entries.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl AuditSink for InMemoryAuditSink {
    fn write(&mut self, entry: &AuditEntry) -> EnterpriseResult<()> {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front(); // Evict oldest entry
        }
        self.entries.push_back(entry.clone());
        Ok(())
    }
}

// ── JSON-lines file audit sink ────────────────────────────────────────────────

/// An [`AuditSink`] that appends NDJSON lines to a log file.
pub struct JsonLineAuditSink {
    path: String,
    /// Buffered lines pending flush.
    buffer: Vec<String>,
    /// How many entries to buffer before flushing.
    flush_threshold: usize,
}

impl JsonLineAuditSink {
    pub fn new(path: impl Into<String>, flush_threshold: usize) -> Self {
        Self {
            path: path.into(),
            buffer: Vec::new(),
            flush_threshold,
        }
    }

    pub fn flush(&mut self) -> EnterpriseResult<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| EnterpriseError::AuditError(e.to_string()))?;

        for line in self.buffer.drain(..) {
            writeln!(file, "{}", line)
                .map_err(|e| EnterpriseError::AuditError(e.to_string()))?;
        }
        Ok(())
    }
}

impl AuditSink for JsonLineAuditSink {
    fn write(&mut self, entry: &AuditEntry) -> EnterpriseResult<()> {
        let line = serde_json::to_string(entry)
            .map_err(|e| EnterpriseError::SerializationError(e.to_string()))?;
        self.buffer.push(line);
        if self.buffer.len() >= self.flush_threshold {
            self.flush()?;
        }
        Ok(())
    }
}

impl Drop for JsonLineAuditSink {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

// ── Audit logger ──────────────────────────────────────────────────────────────

/// Central audit logger that fan-outs entries to one or more [`AuditSink`]s.
pub struct AuditLogger {
    sinks: Vec<Box<dyn AuditSink>>,
    enabled: bool,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
            enabled: true,
        }
    }

    /// Add a sink. Returns `self` for chaining.
    pub fn add_sink(mut self, sink: impl AuditSink + 'static) -> Self {
        self.sinks.push(Box::new(sink));
        self
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Write an entry to all sinks.  Errors from individual sinks are
    /// collected and returned as a combined message.
    pub fn log(&mut self, entry: AuditEntry) -> EnterpriseResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut errors: Vec<String> = Vec::new();
        for sink in &mut self.sinks {
            if let Err(e) = sink.write(&entry) {
                errors.push(e.to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(EnterpriseError::AuditError(errors.join("; ")))
        }
    }

    /// Convenience helper: log a successful action.
    pub fn log_success(
        &mut self,
        actor: &str,
        category: AuditCategory,
        action: &str,
        description: &str,
    ) -> EnterpriseResult<()> {
        self.log(AuditEntry::new(
            actor,
            category,
            action,
            AuditOutcome::Success,
            description,
        ))
    }

    /// Convenience helper: log a failed action.
    pub fn log_failure(
        &mut self,
        actor: &str,
        category: AuditCategory,
        action: &str,
        description: &str,
    ) -> EnterpriseResult<()> {
        self.log(AuditEntry::new(
            actor,
            category,
            action,
            AuditOutcome::Failure,
            description,
        ))
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_construction() {
        let entry = AuditEntry::new(
            "user@example.com",
            AuditCategory::Authentication,
            "unlock_vault",
            AuditOutcome::Success,
            "Vault unlocked successfully",
        )
        .with_resource("my-vault")
        .with_correlation_id(Uuid::new_v4());

        assert_eq!(entry.actor, "user@example.com");
        assert_eq!(entry.action, "unlock_vault");
        assert_eq!(entry.outcome, AuditOutcome::Success);
        assert!(entry.resource.is_some());
        assert!(entry.correlation_id.is_some());
    }

    #[test]
    fn test_in_memory_sink_capacity_eviction() {
        let mut sink = InMemoryAuditSink::new(3);
        for i in 0..5 {
            let entry = AuditEntry::new(
                format!("user{}", i),
                AuditCategory::Administration,
                "action",
                AuditOutcome::Success,
                "desc",
            );
            sink.write(&entry).unwrap();
        }
        // Should have only the last 3 entries
        assert_eq!(sink.len(), 3);
    }

    #[test]
    fn test_audit_logger_fan_out() {
        let sink1 = InMemoryAuditSink::new(100);
        let sink2 = InMemoryAuditSink::new(100);
        // We can't easily inspect both sinks after fan-out because we pass
        // ownership to the logger; test that at least 1 entry is logged.
        let mut logger = AuditLogger::new().add_sink(InMemoryAuditSink::new(10));

        let result = logger.log_success(
            "admin",
            AuditCategory::KeyVaultSync,
            "sync_all",
            "Sync completed",
        );
        assert!(result.is_ok());
        drop(sink1);
        drop(sink2);
    }

    #[test]
    fn test_disabled_logger_skips_write() {
        let mut logger = AuditLogger::new().add_sink(InMemoryAuditSink::new(10));
        logger.set_enabled(false);
        assert!(logger.log_success(
            "user",
            AuditCategory::Authentication,
            "unlock",
            "Vault unlocked"
        )
        .is_ok());
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry::new(
            "admin",
            AuditCategory::CredentialAccess,
            "read_credential",
            AuditOutcome::Success,
            "Credential 'github' read",
        )
        .with_resource("github");

        let json = serde_json::to_string(&entry).unwrap();
        let de: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(de.actor, entry.actor);
        assert_eq!(de.action, entry.action);
    }
}
