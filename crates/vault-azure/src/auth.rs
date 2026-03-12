use crate::error::{AzureError, AzureResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};

/// Azure AD OAuth2 token response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

/// Cached access token with expiry tracking.
#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CachedToken {
    /// Returns true if the token is still valid with a 60-second safety margin.
    fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at - Duration::seconds(60)
    }
}

/// Azure AD configuration required for authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct AzureAdConfig {
    /// Azure Active Directory tenant ID (GUID or domain).
    pub tenant_id: String,
    /// Application (client) ID registered in Azure AD.
    pub client_id: String,
    /// Client secret for the registered application.
    pub client_secret: String,
}

impl std::fmt::Debug for AzureAdConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureAdConfig")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Azure AD authenticator using the client credentials OAuth2 flow.
///
/// Acquires and caches access tokens for the Azure Key Vault scope
/// (`https://vault.azure.net/.default`). Tokens are refreshed automatically
/// before expiry.
pub struct AzureAdAuthenticator {
    config: AzureAdConfig,
    http: Client,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

impl AzureAdAuthenticator {
    /// Create a new authenticator with the given Azure AD configuration.
    pub fn new(config: AzureAdConfig) -> AzureResult<Self> {
        if config.tenant_id.is_empty() {
            return Err(AzureError::InvalidConfig(
                "tenant_id must not be empty".to_string(),
            ));
        }
        if config.client_id.is_empty() {
            return Err(AzureError::InvalidConfig(
                "client_id must not be empty".to_string(),
            ));
        }
        if config.client_secret.is_empty() {
            return Err(AzureError::InvalidConfig(
                "client_secret must not be empty".to_string(),
            ));
        }

        let http = Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(AzureError::HttpError)?;

        Ok(Self {
            config,
            http,
            cached_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Returns a valid access token, refreshing it if necessary.
    pub async fn get_access_token(&self) -> AzureResult<String> {
        // Fast path: check cache with read lock
        {
            let guard = self.cached_token.read().await;
            if let Some(ref cached) = *guard {
                if cached.is_valid() {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Slow path: acquire write lock and refresh token
        let mut guard = self.cached_token.write().await;
        // Double-check after acquiring write lock
        if let Some(ref cached) = *guard {
            if cached.is_valid() {
                return Ok(cached.access_token.clone());
            }
        }

        let token = self.fetch_new_token().await?;
        *guard = Some(token.clone());
        Ok(token.access_token)
    }

    /// Fetches a new access token from the Azure AD token endpoint.
    async fn fetch_new_token(&self) -> AzureResult<CachedToken> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("scope", "https://vault.azure.net/.default"),
        ];

        let response = self
            .http
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(AzureError::HttpError)?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(AzureError::AuthenticationFailed(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(AzureError::HttpError)?;

        if token_response.token_type.to_lowercase() != "bearer" {
            return Err(AzureError::AuthenticationFailed(format!(
                "unexpected token type: {}",
                token_response.token_type
            )));
        }

        let expires_at =
            Utc::now() + Duration::seconds(token_response.expires_in as i64);

        Ok(CachedToken {
            access_token: token_response.access_token,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_token_validity() {
        let future = Utc::now() + Duration::seconds(120);
        let token = CachedToken {
            access_token: "tok".to_string(),
            expires_at: future,
        };
        assert!(token.is_valid());

        let past = Utc::now() - Duration::seconds(1);
        let expired = CachedToken {
            access_token: "tok".to_string(),
            expires_at: past,
        };
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_config_validation_rejects_empty_fields() {
        let result = AzureAdAuthenticator::new(AzureAdConfig {
            tenant_id: String::new(),
            client_id: "cid".to_string(),
            client_secret: "cs".to_string(),
        });
        assert!(result.is_err());

        let result = AzureAdAuthenticator::new(AzureAdConfig {
            tenant_id: "tid".to_string(),
            client_id: String::new(),
            client_secret: "cs".to_string(),
        });
        assert!(result.is_err());

        let result = AzureAdAuthenticator::new(AzureAdConfig {
            tenant_id: "tid".to_string(),
            client_id: "cid".to_string(),
            client_secret: String::new(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_config_succeeds() {
        let result = AzureAdAuthenticator::new(AzureAdConfig {
            tenant_id: "my-tenant".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "my-secret".to_string(),
        });
        assert!(result.is_ok());
    }
}
