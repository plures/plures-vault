use crate::auth::AzureAdAuthenticator;
use crate::error::{AzureError, AzureResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::Duration;

const KEY_VAULT_API_VERSION: &str = "7.4";

/// A single secret retrieved from Azure Key Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultSecret {
    /// Secret name.
    pub name: String,
    /// Decrypted secret value.
    pub value: String,
    /// Secret version identifier assigned by Azure.
    pub version: String,
    /// When the secret was last updated.
    pub updated_at: Option<DateTime<Utc>>,
    /// When the secret was created.
    pub created_at: Option<DateTime<Utc>>,
    /// Custom content type, if set.
    pub content_type: Option<String>,
    /// Arbitrary tags attached to the secret.
    pub tags: HashMap<String, String>,
    /// Whether the secret is currently enabled.
    pub enabled: bool,
}

/// Minimal list item returned by the Key Vault list-secrets endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretListItem {
    /// Secret name derived from the secret `id` URL.
    pub name: String,
    /// Whether the secret is currently enabled.
    pub enabled: bool,
    /// Optional content type.
    pub content_type: Option<String>,
    /// Version identifier extracted from the secret `id` URL, if present.
    /// Azure returns the latest version URL in the list response.
    pub version: Option<String>,
}

// ── Raw Azure Key Vault response shapes ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawSecretBundle {
    id: String,
    value: String,
    attributes: RawSecretAttributes,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    tags: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct RawSecretAttributes {
    enabled: bool,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    updated: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RawSecretItem {
    id: String,
    attributes: RawSecretAttributes,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawListResponse {
    value: Vec<RawSecretItem>,
    #[serde(rename = "nextLink", default)]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawErrorResponse {
    error: RawErrorDetail,
}

#[derive(Debug, Deserialize)]
struct RawErrorDetail {
    code: String,
    message: String,
}

// ── Helper: parse secret name / version from URL ─────────────────────────────

/// Extracts the secret name from an Azure secret id URL.
///
/// URL format: `https://<vault>.vault.azure.net/secrets/<name>[/<version>]`
fn secret_name_from_url(url: &str) -> String {
    url.split("/secrets/")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

/// Extracts the version identifier from an Azure secret id URL, if present.
///
/// Returns `None` when the URL contains only a name and no version segment.
fn version_from_url(url: &str) -> Option<String> {
    let after_secrets = url.split("/secrets/").nth(1)?;
    let mut parts = after_secrets.split('/');
    let _name = parts.next()?; // skip name
    let version = parts.next()?;
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

// ── Azure Key Vault client ─────────────────────────────────────────────────────

/// HTTP client for the Azure Key Vault REST API.
///
/// All mutating operations transparently acquire a bearer token via the
/// embedded [`AzureAdAuthenticator`].
pub struct AzureKeyVaultClient {
    vault_url: String,
    auth: AzureAdAuthenticator,
    http: Client,
}

impl AzureKeyVaultClient {
    /// Construct a new client.
    ///
    /// # Arguments
    /// * `vault_name` – The Key Vault name (just the subdomain, e.g.
    ///   `"my-vault"`).  The full URL is derived as
    ///   `https://<vault_name>.vault.azure.net`.
    /// * `auth` – Pre-configured Azure AD authenticator.
    pub fn new(vault_name: &str, auth: AzureAdAuthenticator) -> AzureResult<Self> {
        if vault_name.is_empty() {
            return Err(AzureError::InvalidConfig(
                "vault_name must not be empty".to_string(),
            ));
        }

        let http = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(AzureError::HttpError)?;

        Ok(Self {
            vault_url: format!("https://{}.vault.azure.net", vault_name),
            auth,
            http,
        })
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    async fn bearer(&self) -> AzureResult<String> {
        self.auth.get_access_token().await
    }

    async fn handle_error_response(response: reqwest::Response) -> AzureError {
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "could not read response body".to_string());

        if let Ok(err) = serde_json::from_str::<RawErrorResponse>(&body) {
            if err.error.code == "SecretNotFound" || err.error.code == "ItemNotFound" {
                return AzureError::SecretNotFound(err.error.message);
            }
        }

        if status == 429 {
            return AzureError::RateLimited {
                retry_after_secs: 60,
            };
        }
        if status == 401 || status == 403 {
            return AzureError::AuthenticationFailed(format!(
                "HTTP {}: {}",
                status, body
            ));
        }

        AzureError::ApiError {
            status,
            message: body,
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /// Retrieve a secret by name.
    pub async fn get_secret(&self, secret_name: &str) -> AzureResult<KeyVaultSecret> {
        let token = self.bearer().await?;
        let url = format!(
            "{}/secrets/{}?api-version={}",
            self.vault_url, secret_name, KEY_VAULT_API_VERSION
        );

        let response = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AzureError::HttpError)?;

        if !response.status().is_success() {
            return Err(Self::handle_error_response(response).await);
        }

        let raw: RawSecretBundle = response.json().await.map_err(AzureError::HttpError)?;
        Ok(Self::map_bundle(raw))
    }

    /// Create or update a secret.
    pub async fn set_secret(
        &self,
        secret_name: &str,
        value: &str,
        content_type: Option<&str>,
        tags: Option<HashMap<String, String>>,
    ) -> AzureResult<KeyVaultSecret> {
        let token = self.bearer().await?;
        let url = format!(
            "{}/secrets/{}?api-version={}",
            self.vault_url, secret_name, KEY_VAULT_API_VERSION
        );

        #[derive(Serialize)]
        struct SetSecretRequest<'a> {
            value: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            content_type: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            tags: Option<HashMap<String, String>>,
        }

        let body = SetSecretRequest {
            value,
            content_type,
            tags,
        };

        let response = self
            .http
            .put(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(AzureError::HttpError)?;

        if !response.status().is_success() {
            return Err(Self::handle_error_response(response).await);
        }

        let raw: RawSecretBundle = response.json().await.map_err(AzureError::HttpError)?;
        Ok(Self::map_bundle(raw))
    }

    /// Delete a secret (moves it to the soft-delete state).
    pub async fn delete_secret(&self, secret_name: &str) -> AzureResult<()> {
        let token = self.bearer().await?;
        let url = format!(
            "{}/secrets/{}?api-version={}",
            self.vault_url, secret_name, KEY_VAULT_API_VERSION
        );

        let response = self
            .http
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(AzureError::HttpError)?;

        if !response.status().is_success() {
            return Err(Self::handle_error_response(response).await);
        }

        Ok(())
    }

    /// List all secrets in the vault, handling pagination automatically.
    pub async fn list_secrets(&self) -> AzureResult<Vec<SecretListItem>> {
        let token = self.bearer().await?;
        let mut results = Vec::new();
        let mut next_url: Option<String> = Some(format!(
            "{}/secrets?api-version={}",
            self.vault_url, KEY_VAULT_API_VERSION
        ));

        while let Some(url) = next_url {
            let response = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(AzureError::HttpError)?;

            if !response.status().is_success() {
                return Err(Self::handle_error_response(response).await);
            }

            let raw: RawListResponse = response.json().await.map_err(AzureError::HttpError)?;
            for item in raw.value {
                // The list API returns URLs of the form
                // https://<vault>.vault.azure.net/secrets/<name>/<version>
                // We extract both the name and, if present, the version.
                let version = version_from_url(&item.id);
                results.push(SecretListItem {
                    name: secret_name_from_url(&item.id),
                    enabled: item.attributes.enabled,
                    content_type: item.content_type,
                    version,
                });
            }
            next_url = raw.next_link;
        }

        Ok(results)
    }

    // ── Private mapping helpers ────────────────────────────────────────────────

    fn map_bundle(raw: RawSecretBundle) -> KeyVaultSecret {
        let version = raw
            .id
            .split('/')
            .next_back()
            .unwrap_or("")
            .to_string();

        let name = secret_name_from_url(&raw.id);

        let created_at = raw
            .attributes
            .created
            // Azure timestamps are Unix seconds; an invalid/zero timestamp
            // maps to DateTime::UNIX_EPOCH (1970-01-01T00:00:00Z), which is a
            // safe sentinel value indicating an unknown creation time.
            .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_default());
        let updated_at = raw
            .attributes
            .updated
            .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_default());

        KeyVaultSecret {
            name,
            value: raw.value,
            version,
            created_at,
            updated_at,
            content_type: raw.content_type,
            tags: raw.tags.unwrap_or_default(),
            enabled: raw.attributes.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_name_extraction() {
        assert_eq!(
            secret_name_from_url(
                "https://my-vault.vault.azure.net/secrets/my-secret/abc123"
            ),
            "my-secret"
        );
        assert_eq!(
            secret_name_from_url(
                "https://my-vault.vault.azure.net/secrets/my-secret"
            ),
            "my-secret"
        );
        // Fallback: returns the input unchanged if no `/secrets/` segment is found
        assert_eq!(
            secret_name_from_url("my-secret"),
            "my-secret"
        );
    }
}
