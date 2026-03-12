use crate::error::{EnterpriseError, EnterpriseResult};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ── Feature flags ─────────────────────────────────────────────────────────────

/// Set of features that can be toggled by a license.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// Bidirectional Azure Key Vault sync.
    AzureKeyVaultSync,
    /// Multi-partition management (more than one Key Vault mapping).
    MultiPartition,
    /// Compliance audit logs.
    AuditLogging,
    /// Azure AD single sign-on.
    AzureAdSso,
    /// Priority support SLA.
    PrioritySupport,
}

// ── License tiers ─────────────────────────────────────────────────────────────

/// Enterprise subscription tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    /// Free / community tier – no enterprise features.
    Community,
    /// Single Key Vault integration, audit logs.
    Professional,
    /// Unlimited partitions, SSO, priority support.
    Enterprise,
}

impl LicenseTier {
    /// Returns the default set of [`Feature`]s included at this tier.
    pub fn included_features(&self) -> HashSet<Feature> {
        match self {
            Self::Community => HashSet::new(),
            Self::Professional => [
                Feature::AzureKeyVaultSync,
                Feature::AuditLogging,
            ]
            .into_iter()
            .collect(),
            Self::Enterprise => [
                Feature::AzureKeyVaultSync,
                Feature::MultiPartition,
                Feature::AuditLogging,
                Feature::AzureAdSso,
                Feature::PrioritySupport,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Returns the maximum number of Azure Key Vault partitions allowed.
    pub fn max_partitions(&self) -> u32 {
        match self {
            Self::Community => 0,
            Self::Professional => 1,
            Self::Enterprise => u32::MAX,
        }
    }
}

// ── License data ──────────────────────────────────────────────────────────────

/// Representation of a Plures Vault enterprise license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// Unique license identifier.
    pub id: Uuid,
    /// Azure AD tenant ID this license is bound to.
    pub tenant_id: String,
    /// Human-readable organisation name.
    pub organisation: String,
    /// Subscription tier.
    pub tier: LicenseTier,
    /// Feature flags – overrides the tier defaults (additive).
    pub extra_features: HashSet<Feature>,
    /// Maximum number of Azure Key Vault partitions allowed.
    /// `None` means use the tier default.
    pub max_partitions_override: Option<u32>,
    /// Timestamp after which the license is no longer valid.
    pub expires_at: DateTime<Utc>,
    /// When the license was issued.
    pub issued_at: DateTime<Utc>,
    /// HMAC-SHA256 signature (hex-encoded) over the canonical license fields,
    /// computed by the licensing server.  Verified during validation.
    pub signature: String,
}

impl License {
    /// Returns the effective maximum number of Key Vault partitions.
    pub fn effective_max_partitions(&self) -> u32 {
        self.max_partitions_override
            .unwrap_or_else(|| self.tier.max_partitions())
    }

    /// Returns the effective set of enabled features.
    pub fn effective_features(&self) -> HashSet<Feature> {
        let mut features = self.tier.included_features();
        features.extend(self.extra_features.iter().cloned());
        features
    }

    /// Returns true if the license has not yet expired.
    pub fn is_active(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

// ── License manager ───────────────────────────────────────────────────────────

/// Validates and enforces enterprise licenses.
///
/// On expiry the manager degrades gracefully to `LicenseTier::Community`
/// rather than hard-erroring, so users keep read access to their vault.
pub struct LicenseManager {
    license: Option<License>,
    /// A shared secret used to verify license signatures.  In production this
    /// would be the public key of the licensing server.
    signing_secret: Vec<u8>,
}

impl LicenseManager {
    /// Create a new manager.  `signing_secret` is the HMAC key used to verify
    /// license signatures.
    pub fn new(signing_secret: Vec<u8>) -> Self {
        Self {
            license: None,
            signing_secret,
        }
    }

    /// Load and validate a license.  Returns an error if the license is
    /// structurally invalid or the signature doesn't verify.  An *expired*
    /// license is accepted but the manager will report degraded features.
    pub fn load_license(&mut self, license: License) -> EnterpriseResult<()> {
        self.verify_signature(&license)?;
        self.license = Some(license);
        Ok(())
    }

    /// Remove the current license (revert to Community tier).
    pub fn revoke_license(&mut self) {
        self.license = None;
    }

    /// Returns the current license, if any.
    pub fn current_license(&self) -> Option<&License> {
        self.license.as_ref()
    }

    /// Returns true if a valid, non-expired license is loaded.
    pub fn is_licensed(&self) -> bool {
        self.license.as_ref().map(|l| l.is_active()).unwrap_or(false)
    }

    /// Returns the effective [`LicenseTier`].  Falls back to `Community` if no
    /// license is loaded *or* if the loaded license has expired.
    pub fn effective_tier(&self) -> LicenseTier {
        self.license
            .as_ref()
            .filter(|l| l.is_active())
            .map(|l| l.tier)
            .unwrap_or(LicenseTier::Community)
    }

    /// Returns the effective set of enabled features.
    pub fn effective_features(&self) -> HashSet<Feature> {
        self.license
            .as_ref()
            .filter(|l| l.is_active())
            .map(|l| l.effective_features())
            .unwrap_or_default()
    }

    /// Checks whether the given feature is available with the current license.
    pub fn is_feature_enabled(&self, feature: &Feature) -> bool {
        self.effective_features().contains(feature)
    }

    /// Asserts that a feature is available, returning an error suitable for
    /// surfacing to callers when it is not.
    pub fn require_feature(&self, feature: &Feature) -> EnterpriseResult<()> {
        if self.is_feature_enabled(feature) {
            Ok(())
        } else if self.license.as_ref().map(|l| !l.is_active()).unwrap_or(false) {
            Err(EnterpriseError::LicenseExpired)
        } else {
            Err(EnterpriseError::InvalidLicense(format!(
                "feature {:?} is not included in the current license tier",
                feature
            )))
        }
    }

    /// Asserts that the current license allows adding more Key Vault partitions.
    pub fn require_partition_capacity(
        &self,
        current_count: u32,
    ) -> EnterpriseResult<()> {
        let max = self
            .license
            .as_ref()
            .filter(|l| l.is_active())
            .map(|l| l.effective_max_partitions())
            .unwrap_or(0);

        if current_count < max {
            Ok(())
        } else {
            Err(EnterpriseError::LicenseLimitExceeded(format!(
                "partition limit of {} reached",
                max
            )))
        }
    }

    // ── Signature verification ─────────────────────────────────────────────────

    /// Verifies the HMAC-SHA256 signature of the license.
    ///
    /// The canonical message is:
    /// `<id>|<tenant_id>|<tier>|<expires_at_rfc3339>|<issued_at_rfc3339>`
    fn verify_signature(&self, license: &License) -> EnterpriseResult<()> {
        let canonical = Self::canonical_message(license);
        let expected_sig = Self::hmac_sha256(&self.signing_secret, canonical.as_bytes());
        if expected_sig != license.signature {
            return Err(EnterpriseError::InvalidLicense(
                "signature verification failed".to_string(),
            ));
        }
        Ok(())
    }

    fn canonical_message(license: &License) -> String {
        format!(
            "{}|{}|{:?}|{}|{}",
            license.id,
            license.tenant_id,
            license.tier,
            license.expires_at.to_rfc3339(),
            license.issued_at.to_rfc3339(),
        )
    }

    /// Compute HMAC-SHA256 over `message` using `key`, returning a lowercase hex string.
    fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(message);
        let result = mac.finalize().into_bytes();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Generates a valid license signature for the given license data.
    /// Only used by the licensing server / in tests.
    pub fn sign_license(signing_secret: &[u8], license: &License) -> String {
        let canonical = Self::canonical_message(license);
        Self::hmac_sha256(signing_secret, canonical.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_license(
        tier: LicenseTier,
        expires_at: DateTime<Utc>,
        signing_secret: &[u8],
    ) -> License {
        let id = Uuid::new_v4();
        let issued_at = Utc::now();
        let mut lic = License {
            id,
            tenant_id: "test-tenant".to_string(),
            organisation: "Acme Corp".to_string(),
            tier,
            extra_features: HashSet::new(),
            max_partitions_override: None,
            expires_at,
            issued_at,
            signature: String::new(),
        };
        lic.signature = LicenseManager::sign_license(signing_secret, &lic);
        lic
    }

    #[test]
    fn test_valid_enterprise_license() {
        let secret = b"my-signing-secret";
        let mut mgr = LicenseManager::new(secret.to_vec());
        let lic = make_license(
            LicenseTier::Enterprise,
            Utc::now() + Duration::days(365),
            secret,
        );

        assert!(mgr.load_license(lic).is_ok());
        assert!(mgr.is_licensed());
        assert_eq!(mgr.effective_tier(), LicenseTier::Enterprise);
        assert!(mgr.is_feature_enabled(&Feature::AzureKeyVaultSync));
        assert!(mgr.is_feature_enabled(&Feature::MultiPartition));
        assert!(mgr.is_feature_enabled(&Feature::AuditLogging));
    }

    #[test]
    fn test_expired_license_degrades_to_community() {
        let secret = b"my-signing-secret";
        let mut mgr = LicenseManager::new(secret.to_vec());
        let lic = make_license(
            LicenseTier::Enterprise,
            Utc::now() - Duration::days(1),
            secret,
        );

        assert!(mgr.load_license(lic).is_ok());
        assert!(!mgr.is_licensed());
        assert_eq!(mgr.effective_tier(), LicenseTier::Community);
        assert!(!mgr.is_feature_enabled(&Feature::AzureKeyVaultSync));
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let secret = b"my-signing-secret";
        let wrong_secret = b"wrong-secret";
        let mut mgr = LicenseManager::new(secret.to_vec());
        let lic = make_license(
            LicenseTier::Enterprise,
            Utc::now() + Duration::days(365),
            wrong_secret,
        );

        let result = mgr.load_license(lic);
        assert!(result.is_err());
        matches!(result.unwrap_err(), EnterpriseError::InvalidLicense(_));
    }

    #[test]
    fn test_partition_capacity_check() {
        let secret = b"sec";
        let mut mgr = LicenseManager::new(secret.to_vec());
        // Professional: max 1 partition
        let lic = make_license(
            LicenseTier::Professional,
            Utc::now() + Duration::days(365),
            secret,
        );
        mgr.load_license(lic).unwrap();

        assert!(mgr.require_partition_capacity(0).is_ok());
        assert!(mgr.require_partition_capacity(1).is_err());
    }

    #[test]
    fn test_feature_gating_no_license() {
        let mgr = LicenseManager::new(b"sec".to_vec());
        assert!(!mgr.is_feature_enabled(&Feature::AzureKeyVaultSync));
        let err = mgr.require_feature(&Feature::AzureKeyVaultSync).unwrap_err();
        assert!(matches!(err, EnterpriseError::InvalidLicense(_)));
    }

    #[test]
    fn test_tier_ordering() {
        assert!(LicenseTier::Enterprise > LicenseTier::Professional);
        assert!(LicenseTier::Professional > LicenseTier::Community);
    }

    #[test]
    fn test_revoke_license() {
        let secret = b"sec";
        let mut mgr = LicenseManager::new(secret.to_vec());
        let lic = make_license(
            LicenseTier::Enterprise,
            Utc::now() + Duration::days(365),
            secret,
        );
        mgr.load_license(lic).unwrap();
        assert!(mgr.is_licensed());
        mgr.revoke_license();
        assert!(!mgr.is_licensed());
    }

    #[test]
    fn test_hmac_sha256_is_deterministic() {
        let key = b"test-key";
        let msg = b"test-message";
        let sig1 = LicenseManager::hmac_sha256(key, msg);
        let sig2 = LicenseManager::hmac_sha256(key, msg);
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_different_keys_produce_different_signatures() {
        let msg = b"same-message";
        let sig1 = LicenseManager::hmac_sha256(b"key1", msg);
        let sig2 = LicenseManager::hmac_sha256(b"key2", msg);
        assert_ne!(sig1, sig2);
    }
}
