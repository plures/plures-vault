use crate::error::{EnterpriseError, EnterpriseResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Isolation level for a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionIsolation {
    /// Partition is fully isolated – credentials are not shared with other
    /// partitions in the same tenant.
    Full,
    /// Read-only access can be granted to other partitions within the tenant.
    SharedReadOnly,
}

/// Current status of a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionStatus {
    /// Partition is active and healthy.
    Active,
    /// Partition is provisioned but not yet connected to Azure Key Vault.
    Pending,
    /// Partition is suspended (e.g. license issue).
    Suspended,
    /// Partition has been deleted (soft-delete).
    Deleted,
}

/// A vault partition mapped to a single Azure Key Vault instance.
///
/// In enterprise deployments each department, team, or environment (dev /
/// staging / prod) gets its own partition so that credentials are isolated and
/// can be managed with independent RBAC policies in Azure AD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    /// Unique partition identifier.
    pub id: Uuid,
    /// Human-readable partition name (e.g. "engineering-prod").
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Azure Key Vault name (subdomain only, e.g. "my-vault").
    pub azure_vault_name: Option<String>,
    /// Azure AD tenant ID for this partition.
    pub tenant_id: String,
    /// Partition isolation policy.
    pub isolation: PartitionIsolation,
    /// Current status.
    pub status: PartitionStatus,
    /// When this partition was provisioned.
    pub created_at: DateTime<Utc>,
    /// When this partition was last modified.
    pub updated_at: DateTime<Utc>,
    /// Arbitrary key-value tags for organisational metadata.
    pub tags: HashMap<String, String>,
}

impl Partition {
    /// Returns true if this partition can sync with Azure Key Vault.
    pub fn can_sync(&self) -> bool {
        self.status == PartitionStatus::Active && self.azure_vault_name.is_some()
    }
}

/// Configuration request used when creating a new partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePartitionRequest {
    pub name: String,
    pub description: Option<String>,
    pub tenant_id: String,
    pub azure_vault_name: Option<String>,
    pub isolation: PartitionIsolation,
    pub tags: HashMap<String, String>,
}

/// Multi-partition manager.
///
/// Tracks all vault partitions for an enterprise tenant and enforces the
/// partition limits imposed by the active license.
pub struct PartitionManager {
    partitions: HashMap<Uuid, Partition>,
    /// Maximum number of concurrent partitions allowed.
    max_partitions: u32,
}

impl PartitionManager {
    /// Create a new partition manager.
    ///
    /// `max_partitions` should be supplied from
    /// [`LicenseManager::require_partition_capacity`].
    pub fn new(max_partitions: u32) -> Self {
        Self {
            partitions: HashMap::new(),
            max_partitions,
        }
    }

    /// Update the maximum number of allowed partitions (e.g. after a license
    /// upgrade).
    pub fn set_max_partitions(&mut self, max: u32) {
        self.max_partitions = max;
    }

    /// Returns the number of non-deleted partitions.
    pub fn active_count(&self) -> u32 {
        self.partitions
            .values()
            .filter(|p| p.status != PartitionStatus::Deleted)
            .count() as u32
    }

    /// Create and register a new partition.
    pub fn create_partition(
        &mut self,
        req: CreatePartitionRequest,
    ) -> EnterpriseResult<Partition> {
        // Check name uniqueness
        if self
            .partitions
            .values()
            .any(|p| p.name == req.name && p.status != PartitionStatus::Deleted)
        {
            return Err(EnterpriseError::PartitionAlreadyExists(req.name));
        }

        // Enforce partition limit
        if self.active_count() >= self.max_partitions {
            return Err(EnterpriseError::LicenseLimitExceeded(format!(
                "cannot exceed {} partitions",
                self.max_partitions
            )));
        }

        let now = Utc::now();
        let partition = Partition {
            id: Uuid::new_v4(),
            name: req.name,
            description: req.description,
            azure_vault_name: req.azure_vault_name,
            tenant_id: req.tenant_id,
            isolation: req.isolation,
            status: PartitionStatus::Pending,
            created_at: now,
            updated_at: now,
            tags: req.tags,
        };

        self.partitions.insert(partition.id, partition.clone());
        Ok(partition)
    }

    /// Retrieve a partition by ID.
    pub fn get_partition(&self, id: Uuid) -> EnterpriseResult<&Partition> {
        self.partitions
            .get(&id)
            .filter(|p| p.status != PartitionStatus::Deleted)
            .ok_or_else(|| EnterpriseError::PartitionNotFound(id.to_string()))
    }

    /// List all non-deleted partitions.
    pub fn list_partitions(&self) -> Vec<&Partition> {
        let mut partitions: Vec<&Partition> = self
            .partitions
            .values()
            .filter(|p| p.status != PartitionStatus::Deleted)
            .collect();
        partitions.sort_by_key(|p| p.created_at);
        partitions
    }

    /// Activate a partition (e.g. once Azure KV connectivity is confirmed).
    pub fn activate_partition(&mut self, id: Uuid) -> EnterpriseResult<()> {
        let partition = self
            .partitions
            .get_mut(&id)
            .ok_or_else(|| EnterpriseError::PartitionNotFound(id.to_string()))?;

        if partition.azure_vault_name.is_none() {
            return Err(EnterpriseError::InvalidLicense(
                "cannot activate a partition without an Azure Key Vault name".to_string(),
            ));
        }

        partition.status = PartitionStatus::Active;
        partition.updated_at = Utc::now();
        Ok(())
    }

    /// Suspend a partition (e.g. due to license expiry).
    pub fn suspend_partition(&mut self, id: Uuid) -> EnterpriseResult<()> {
        let partition = self
            .partitions
            .get_mut(&id)
            .ok_or_else(|| EnterpriseError::PartitionNotFound(id.to_string()))?;

        partition.status = PartitionStatus::Suspended;
        partition.updated_at = Utc::now();
        Ok(())
    }

    /// Soft-delete a partition.
    pub fn delete_partition(&mut self, id: Uuid) -> EnterpriseResult<()> {
        let partition = self
            .partitions
            .get_mut(&id)
            .ok_or_else(|| EnterpriseError::PartitionNotFound(id.to_string()))?;

        partition.status = PartitionStatus::Deleted;
        partition.updated_at = Utc::now();
        Ok(())
    }

    /// Update the Azure Key Vault name for a partition.
    pub fn set_vault_name(
        &mut self,
        id: Uuid,
        vault_name: impl Into<String>,
    ) -> EnterpriseResult<()> {
        let partition = self
            .partitions
            .get_mut(&id)
            .ok_or_else(|| EnterpriseError::PartitionNotFound(id.to_string()))?;

        partition.azure_vault_name = Some(vault_name.into());
        partition.updated_at = Utc::now();
        Ok(())
    }

    /// Suspend all partitions (used during license enforcement).
    pub fn suspend_all(&mut self) {
        for partition in self.partitions.values_mut() {
            if partition.status == PartitionStatus::Active {
                partition.status = PartitionStatus::Suspended;
                partition.updated_at = Utc::now();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(name: &str) -> CreatePartitionRequest {
        CreatePartitionRequest {
            name: name.to_string(),
            description: None,
            tenant_id: "tenant-abc".to_string(),
            azure_vault_name: Some("my-vault".to_string()),
            isolation: PartitionIsolation::Full,
            tags: HashMap::new(),
        }
    }

    #[test]
    fn test_create_and_list_partitions() {
        let mut mgr = PartitionManager::new(5);
        let p = mgr.create_partition(make_request("eng-prod")).unwrap();

        assert_eq!(p.name, "eng-prod");
        assert_eq!(p.status, PartitionStatus::Pending);
        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.list_partitions().len(), 1);
    }

    #[test]
    fn test_partition_limit_enforced() {
        let mut mgr = PartitionManager::new(2);
        mgr.create_partition(make_request("p1")).unwrap();
        mgr.create_partition(make_request("p2")).unwrap();

        let result = mgr.create_partition(make_request("p3"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnterpriseError::LicenseLimitExceeded(_)
        ));
    }

    #[test]
    fn test_activate_partition() {
        let mut mgr = PartitionManager::new(5);
        let p = mgr.create_partition(make_request("eng-dev")).unwrap();

        mgr.activate_partition(p.id).unwrap();
        let activated = mgr.get_partition(p.id).unwrap();
        assert_eq!(activated.status, PartitionStatus::Active);
        assert!(activated.can_sync());
    }

    #[test]
    fn test_soft_delete_hides_partition() {
        let mut mgr = PartitionManager::new(5);
        let p = mgr.create_partition(make_request("to-delete")).unwrap();

        mgr.delete_partition(p.id).unwrap();

        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.list_partitions().len(), 0);
        let result = mgr.get_partition(p.id);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_name_rejected() {
        let mut mgr = PartitionManager::new(5);
        mgr.create_partition(make_request("dup")).unwrap();

        let result = mgr.create_partition(make_request("dup"));
        assert!(matches!(
            result.unwrap_err(),
            EnterpriseError::PartitionAlreadyExists(_)
        ));
    }

    #[test]
    fn test_suspend_all() {
        let mut mgr = PartitionManager::new(5);
        let p1 = mgr.create_partition(make_request("a")).unwrap();
        let p2 = mgr.create_partition(make_request("b")).unwrap();

        mgr.activate_partition(p1.id).unwrap();
        mgr.activate_partition(p2.id).unwrap();
        mgr.suspend_all();

        for partition in mgr.list_partitions() {
            assert_eq!(partition.status, PartitionStatus::Suspended);
        }
    }
}
