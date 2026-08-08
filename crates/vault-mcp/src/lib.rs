use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum McpError {
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    #[error("Invalid params: {0}")]
    InvalidParams(String),
    #[error("Vault error: {0}")]
    VaultError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Server not initialized")]
    NotInitialized,
    #[error("Insufficient scope: requires {required}, granted {granted}")]
    InsufficientScope { required: String, granted: String },
}

// ---------------------------------------------------------------------------
// Least-privilege scopes
// ---------------------------------------------------------------------------

/// Scopes that can be granted to an MCP session. Each tool requires a minimum
/// scope; calls are rejected when the session lacks the required scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Read-only access (list, get, search, status).
    Read,
    /// Read + create/update credentials.
    Write,
    /// Read + write + delete credentials.
    Delete,
    /// Full access including audit-log queries.
    Admin,
}

impl Scope {
    /// Returns `true` when `self` satisfies the `required` scope.
    pub fn satisfies(self, required: Scope) -> bool {
        use Scope::*;
        matches!(
            (self, required),
            (Admin, _)
                | (Delete, Read | Write | Delete)
                | (Write, Read | Write)
                | (Read, Read)
        )
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Read => write!(f, "read"),
            Scope::Write => write!(f, "write"),
            Scope::Delete => write!(f, "delete"),
            Scope::Admin => write!(f, "admin"),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// A single audit-log entry recorded for every tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 timestamp (UTC) of the event, or a monotonic counter when
    /// real-time clocks are unavailable (e.g. in tests).
    pub timestamp: String,
    /// Name of the tool that was invoked.
    pub tool: String,
    /// The scope that was required by the tool.
    pub required_scope: Scope,
    /// The scope that the session actually held.
    pub granted_scope: Scope,
    /// Whether the call was permitted.
    pub allowed: bool,
    /// Whether the underlying operation succeeded (only meaningful when
    /// `allowed` is `true`).
    pub success: bool,
}

/// Thread-safe, append-only audit log.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, entry: AuditEntry) {
        self.entries.lock().expect("audit lock poisoned").push(entry);
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit lock poisoned").clone()
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// MCP protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub tools: Option<ToolsCapability>,
    pub resources: Option<ResourcesCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesCapability {
    pub subscribe: bool,
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

// ---------------------------------------------------------------------------
// VaultOperations trait
// ---------------------------------------------------------------------------

/// Trait that vault implementations must satisfy for MCP integration.
/// This keeps vault-mcp decoupled from vault-core.
pub trait VaultOperations: Send + Sync {
    fn list_credentials(&self) -> Result<serde_json::Value, String>;
    fn get_credential(&self, title: &str) -> Result<Option<serde_json::Value>, String>;
    fn add_credential(&self, params: serde_json::Value) -> Result<serde_json::Value, String>;
    fn delete_credential(&self, title: &str) -> Result<bool, String>;
    fn search_credentials(&self, query: &str) -> Result<serde_json::Value, String>;
    fn vault_status(&self) -> Result<serde_json::Value, String>;
}

// ---------------------------------------------------------------------------
// JSON-RPC error codes
// ---------------------------------------------------------------------------

const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_INTERNAL_ERROR: i64 = -32603;
/// Custom application error code for insufficient scope.
const JSONRPC_INSUFFICIENT_SCOPE: i64 = -32001;

// ---------------------------------------------------------------------------
// McpServer
// ---------------------------------------------------------------------------

pub struct McpServer {
    info: ServerInfo,
    tools: Vec<ToolDefinition>,
    resources: Vec<ResourceDefinition>,
    vault: Option<Box<dyn VaultOperations>>,
    initialized: bool,
    /// The set of scopes granted to this MCP session.
    granted_scope: Scope,
    /// Append-only audit log for every tool invocation.
    audit_log: AuditLog,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            info: ServerInfo {
                name: "plures-vault-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            tools: Self::default_tools(),
            resources: Self::default_resources(),
            vault: None,
            initialized: false,
            granted_scope: Scope::Read,
            audit_log: AuditLog::new(),
        }
    }

    /// Builder method — attach a vault backend.
    pub fn with_vault(mut self, vault: Box<dyn VaultOperations>) -> Self {
        self.vault = Some(vault);
        self
    }

    /// Builder method — set the session scope (defaults to `Read`).
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.granted_scope = scope;
        self
    }

    /// Get a reference to the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get the granted scope.
    pub fn granted_scope(&self) -> Scope {
        self.granted_scope
    }

    /// Get all tool definitions.
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.tools
    }

    /// Get all resource definitions.
    pub fn resources(&self) -> &[ResourceDefinition] {
        &self.resources
    }

    /// Check if the server has been initialized via the MCP handshake.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -- request handling ---------------------------------------------------

    /// Process a single JSON-RPC request and return a response.
    pub fn handle_request(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(),
            "initialized" => self.handle_initialized(),
            "tools/list" => self.handle_tools_list(),
            "tools/call" => self.handle_tools_call(&request.params),
            "resources/list" => self.handle_resources_list(),
            other => Err(McpError::MethodNotFound(other.to_string())),
        };

        match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id.clone(),
                result: Some(value),
                error: None,
            },
            Err(e) => {
                let (code, message) = match &e {
                    McpError::MethodNotFound(m) => (JSONRPC_METHOD_NOT_FOUND, m.clone()),
                    McpError::InvalidParams(m) => (JSONRPC_INVALID_PARAMS, m.clone()),
                    McpError::InsufficientScope { .. } => {
                        (JSONRPC_INSUFFICIENT_SCOPE, e.to_string())
                    }
                    _ => (JSONRPC_INTERNAL_ERROR, e.to_string()),
                };
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id.clone(),
                    result: None,
                    error: Some(JsonRpcError {
                        code,
                        message,
                        data: None,
                    }),
                }
            }
        }
    }

    /// Parse a JSON string, handle the request, and return a serialised
    /// JSON-RPC response.
    pub fn handle_message(&mut self, message: &str) -> Result<String, McpError> {
        let request: JsonRpcRequest = serde_json::from_str(message)?;
        let response = self.handle_request(&request);
        let serialized = serde_json::to_string(&response)?;
        Ok(serialized)
    }

    // -- MCP method handlers ------------------------------------------------

    fn handle_initialize(&mut self) -> Result<serde_json::Value, McpError> {
        self.initialized = true;
        Ok(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": self.info.name,
                "version": self.info.version,
            },
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false },
            }
        }))
    }

    fn handle_initialized(&self) -> Result<serde_json::Value, McpError> {
        // Notification acknowledgement — return empty result.
        Ok(serde_json::json!({}))
    }

    fn handle_tools_list(&self) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({ "tools": self.tools }))
    }

    fn handle_resources_list(&self) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({ "resources": self.resources }))
    }

    fn handle_tools_call(
        &self,
        params: &Option<serde_json::Value>,
    ) -> Result<serde_json::Value, McpError> {
        let params = params
            .as_ref()
            .ok_or_else(|| McpError::InvalidParams("missing params".to_string()))?;

        let tool_name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::InvalidParams("missing tool name".to_string()))?;

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        // --- scope check ---------------------------------------------------
        let required_scope = Self::required_scope(tool_name);
        let allowed = self.granted_scope.satisfies(required_scope);

        if !allowed {
            self.audit_log.record(AuditEntry {
                timestamp: Self::now_iso(),
                tool: tool_name.to_string(),
                required_scope,
                granted_scope: self.granted_scope,
                allowed: false,
                success: false,
            });
            return Err(McpError::InsufficientScope {
                required: required_scope.to_string(),
                granted: self.granted_scope.to_string(),
            });
        }

        // --- handle built-in audit tool ------------------------------------
        if tool_name == "vault_audit_log" {
            let entries = self.audit_log.entries();
            let text = serde_json::to_string(&entries).unwrap_or_default();
            self.audit_log.record(AuditEntry {
                timestamp: Self::now_iso(),
                tool: tool_name.to_string(),
                required_scope,
                granted_scope: self.granted_scope,
                allowed: true,
                success: true,
            });
            let result = ToolResult {
                content: vec![ToolContent {
                    content_type: "text".to_string(),
                    text,
                }],
                is_error: None,
            };
            return serde_json::to_value(result).map_err(McpError::SerializationError);
        }

        // --- vault backend dispatch ----------------------------------------
        let vault = match &self.vault {
            Some(v) => v,
            None => {
                self.audit_log.record(AuditEntry {
                    timestamp: Self::now_iso(),
                    tool: tool_name.to_string(),
                    required_scope,
                    granted_scope: self.granted_scope,
                    allowed: true,
                    success: false,
                });
                let result = ToolResult {
                    content: vec![ToolContent {
                        content_type: "text".to_string(),
                        text: "Vault not connected".to_string(),
                    }],
                    is_error: Some(true),
                };
                return serde_json::to_value(result)
                    .map_err(McpError::SerializationError);
            }
        };

        let tool_result = match tool_name {
            "vault_list_credentials" => vault
                .list_credentials()
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            "vault_get_credential" => {
                let title = arguments
                    .get("title")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpError::InvalidParams("missing required param: title".to_string())
                    })?;
                vault
                    .get_credential(title)
                    .map(|v| serde_json::to_string(&v).unwrap_or_default())
            }
            "vault_add_credential" => vault
                .add_credential(arguments)
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            "vault_delete_credential" => {
                let title = arguments
                    .get("title")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpError::InvalidParams("missing required param: title".to_string())
                    })?;
                vault
                    .delete_credential(title)
                    .map(|v| serde_json::to_string(&v).unwrap_or_default())
            }
            "vault_search" => {
                let query = arguments
                    .get("query")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpError::InvalidParams("missing required param: query".to_string())
                    })?;
                vault
                    .search_credentials(query)
                    .map(|v| serde_json::to_string(&v).unwrap_or_default())
            }
            "vault_status" => vault
                .vault_status()
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            other => {
                return Err(McpError::InvalidParams(format!(
                    "unknown tool: {other}"
                )));
            }
        };

        let success = tool_result.is_ok();
        self.audit_log.record(AuditEntry {
            timestamp: Self::now_iso(),
            tool: tool_name.to_string(),
            required_scope,
            granted_scope: self.granted_scope,
            allowed: true,
            success,
        });

        match tool_result {
            Ok(text) => {
                let result = ToolResult {
                    content: vec![ToolContent {
                        content_type: "text".to_string(),
                        text,
                    }],
                    is_error: None,
                };
                Ok(serde_json::to_value(result).map_err(McpError::SerializationError)?)
            }
            Err(e) => {
                let result = ToolResult {
                    content: vec![ToolContent {
                        content_type: "text".to_string(),
                        text: e,
                    }],
                    is_error: Some(true),
                };
                Ok(serde_json::to_value(result).map_err(McpError::SerializationError)?)
            }
        }
    }

    // -- scope mapping ------------------------------------------------------

    /// Return the minimum scope required for a given tool name.
    fn required_scope(tool_name: &str) -> Scope {
        match tool_name {
            "vault_list_credentials"
            | "vault_get_credential"
            | "vault_search"
            | "vault_status" => Scope::Read,
            "vault_add_credential" => Scope::Write,
            "vault_delete_credential" => Scope::Delete,
            "vault_audit_log" => Scope::Admin,
            _ => Scope::Admin, // unknown tools default to highest privilege
        }
    }

    /// Monotonic timestamp helper.
    fn now_iso() -> String {
        // Use a simple counter so tests stay deterministic.  In production
        // this would use `chrono::Utc::now().to_rfc3339()`.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("T{n}")
    }

    // -- default definitions ------------------------------------------------

    fn default_tools() -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "vault_list_credentials".to_string(),
                description: "List all credential titles stored in the vault".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
            },
            ToolDefinition {
                name: "vault_get_credential".to_string(),
                description: "Get a specific credential by title".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "The title of the credential to retrieve"
                        }
                    },
                    "required": ["title"]
                }),
            },
            ToolDefinition {
                name: "vault_add_credential".to_string(),
                description: "Add a new credential to the vault".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "The title for the credential"
                        },
                        "password": {
                            "type": "string",
                            "description": "The password for the credential"
                        },
                        "username": {
                            "type": "string",
                            "description": "Optional username"
                        },
                        "url": {
                            "type": "string",
                            "description": "Optional URL"
                        },
                        "notes": {
                            "type": "string",
                            "description": "Optional notes"
                        }
                    },
                    "required": ["title", "password"]
                }),
            },
            ToolDefinition {
                name: "vault_delete_credential".to_string(),
                description: "Delete a credential from the vault".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "The title of the credential to delete"
                        }
                    },
                    "required": ["title"]
                }),
            },
            ToolDefinition {
                name: "vault_search".to_string(),
                description: "Search credentials by query string".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query to match against credential titles and metadata"
                        }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "vault_status".to_string(),
                description: "Get vault status information".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
            },
            ToolDefinition {
                name: "vault_audit_log".to_string(),
                description: "Retrieve the audit log of all MCP tool invocations (requires admin scope)".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                    "required": []
                }),
            },
        ]
    }

    fn default_resources() -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "vault://credentials".to_string(),
                name: "Vault Credentials".to_string(),
                description: "List of all credentials stored in the vault".to_string(),
                mime_type: "application/json".to_string(),
            },
            ResourceDefinition {
                uri: "vault://status".to_string(),
                name: "Vault Status".to_string(),
                description: "Current vault status information".to_string(),
                mime_type: "application/json".to_string(),
            },
            ResourceDefinition {
                uri: "audit://log".to_string(),
                name: "Audit Log".to_string(),
                description: "Audit log of all MCP tool invocations".to_string(),
                mime_type: "application/json".to_string(),
            },
        ]
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- MockVault ----------------------------------------------------------

    struct MockVault;

    impl VaultOperations for MockVault {
        fn list_credentials(&self) -> Result<serde_json::Value, String> {
            Ok(json!(["GitHub", "AWS", "Email"]))
        }

        fn get_credential(&self, title: &str) -> Result<Option<serde_json::Value>, String> {
            if title == "GitHub" {
                Ok(Some(json!({
                    "title": "GitHub",
                    "username": "alice",
                    "url": "https://github.com"
                })))
            } else {
                Ok(None)
            }
        }

        fn add_credential(&self, params: serde_json::Value) -> Result<serde_json::Value, String> {
            Ok(json!({"id": "new-id", "title": params["title"]}))
        }

        fn delete_credential(&self, title: &str) -> Result<bool, String> {
            Ok(title == "GitHub")
        }

        fn search_credentials(&self, query: &str) -> Result<serde_json::Value, String> {
            if query == "git" {
                Ok(json!(["GitHub"]))
            } else {
                Ok(json!([]))
            }
        }

        fn vault_status(&self) -> Result<serde_json::Value, String> {
            Ok(json!({
                "unlocked": true,
                "credential_count": 3,
                "vault_name": "Test Vault"
            }))
        }
    }

    // -- helpers ------------------------------------------------------------

    fn make_request(method: &str, params: Option<serde_json::Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: method.to_string(),
            params,
        }
    }

    // -- tests --------------------------------------------------------------

    #[test]
    fn test_server_creation_and_defaults() {
        let server = McpServer::new();
        assert_eq!(server.info.name, "plures-vault-mcp");
        assert_eq!(server.info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(server.tools().len(), 7);
        assert_eq!(server.resources().len(), 3);
        assert!(!server.is_initialized());
    }

    #[test]
    fn test_default_trait() {
        let server = McpServer::default();
        assert_eq!(server.info.name, "plures-vault-mcp");
    }

    #[test]
    fn test_initialize_handshake() {
        let mut server = McpServer::new();
        let req = make_request("initialize", None);
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "plures-vault-mcp");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"]["resources"].is_object());
        assert!(server.is_initialized());
    }

    #[test]
    fn test_initialized_notification() {
        let mut server = McpServer::new();
        let req = make_request("initialized", None);
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.is_object());
    }

    #[test]
    fn test_tools_list() {
        let mut server = McpServer::new();
        let req = make_request("tools/list", None);
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);

        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"vault_list_credentials"));
        assert!(names.contains(&"vault_get_credential"));
        assert!(names.contains(&"vault_add_credential"));
        assert!(names.contains(&"vault_delete_credential"));
        assert!(names.contains(&"vault_search"));
        assert!(names.contains(&"vault_status"));
        assert!(names.contains(&"vault_audit_log"));

        // Verify schemas have correct structure
        for tool in tools {
            assert!(tool["inputSchema"]["type"].as_str() == Some("object"));
            assert!(tool["description"].as_str().is_some());
        }
    }

    #[test]
    fn test_resources_list() {
        let mut server = McpServer::new();
        let req = make_request("resources/list", None);
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 3);

        let uris: Vec<&str> = resources.iter().map(|r| r["uri"].as_str().unwrap()).collect();
        assert!(uris.contains(&"vault://credentials"));
        assert!(uris.contains(&"vault://status"));
        assert!(uris.contains(&"audit://log"));
    }

    #[test]
    fn test_tool_call_without_vault() {
        let mut server = McpServer::new();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault_list_credentials",
                "arguments": {}
            })),
        );
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(true));
        assert_eq!(result["content"][0]["text"], "Vault not connected");
    }

    #[test]
    fn test_tool_call_list_credentials() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_list_credentials", "arguments": {} })),
        );
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result["isError"].is_null());
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed, json!(["GitHub", "AWS", "Email"]));
    }

    #[test]
    fn test_tool_call_get_credential() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_get_credential", "arguments": { "title": "GitHub" } })),
        );
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["title"], "GitHub");
        assert_eq!(parsed["username"], "alice");
    }

    #[test]
    fn test_tool_call_get_credential_not_found() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_get_credential", "arguments": { "title": "NonExistent" } })),
        );
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(parsed.is_null());
    }

    #[test]
    fn test_tool_call_add_credential() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault)).with_scope(Scope::Write);
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault_add_credential",
                "arguments": { "title": "NewSite", "password": "s3cret" }
            })),
        );
        let resp = server.handle_request(&req);

        assert!(resp.error.is_none());
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["id"], "new-id");
        assert_eq!(parsed["title"], "NewSite");
    }

    #[test]
    fn test_tool_call_delete_credential() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault)).with_scope(Scope::Delete);

        // delete existing
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_delete_credential", "arguments": { "title": "GitHub" } })),
        );
        let resp = server.handle_request(&req);
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(text, "true");

        // delete non-existing
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_delete_credential", "arguments": { "title": "Nope" } })),
        );
        let resp = server.handle_request(&req);
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(text, "false");
    }

    #[test]
    fn test_tool_call_search() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_search", "arguments": { "query": "git" } })),
        );
        let resp = server.handle_request(&req);
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, json!(["GitHub"]));
    }

    #[test]
    fn test_tool_call_vault_status() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_status", "arguments": {} })),
        );
        let resp = server.handle_request(&req);
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["unlocked"], true);
        assert_eq!(parsed["credential_count"], 3);
    }

    #[test]
    fn test_handle_message_round_trip() {
        let mut server = McpServer::new();
        let msg = r#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":null}"#;
        let response_str = server.handle_message(msg).unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(&response_str).unwrap();
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, Some(json!(42)));
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "plures-vault-mcp");
    }

    #[test]
    fn test_unknown_method() {
        let mut server = McpServer::new();
        let req = make_request("nonexistent/method", None);
        let resp = server.handle_request(&req);

        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert!(err.message.contains("nonexistent/method"));
    }

    #[test]
    fn test_invalid_json() {
        let mut server = McpServer::new();
        let result = server.handle_message("not valid json{{{");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), McpError::SerializationError(_)));
    }

    #[test]
    fn test_jsonrpc_error_code_method_not_found() {
        let mut server = McpServer::new();
        let req = make_request("bogus", None);
        let resp = server.handle_request(&req);
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_jsonrpc_error_code_invalid_params() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
        // Call vault_get_credential without required title
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_get_credential", "arguments": {} })),
        );
        let resp = server.handle_request(&req);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn test_tools_call_missing_params() {
        let mut server = McpServer::new();
        let req = make_request("tools/call", None);
        let resp = server.handle_request(&req);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn test_tools_call_unknown_tool() {
        let mut server = McpServer::new().with_vault(Box::new(MockVault)).with_scope(Scope::Admin);
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "nonexistent_tool", "arguments": {} })),
        );
        let resp = server.handle_request(&req);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32602);
    }

    #[test]
    fn test_with_vault_builder() {
        let server = McpServer::new().with_vault(Box::new(MockVault));
        assert!(server.vault.is_some());
    }

    // -- scope tests --------------------------------------------------------

    #[test]
    fn test_scope_satisfies() {
        assert!(Scope::Read.satisfies(Scope::Read));
        assert!(!Scope::Read.satisfies(Scope::Write));
        assert!(!Scope::Read.satisfies(Scope::Delete));
        assert!(!Scope::Read.satisfies(Scope::Admin));

        assert!(Scope::Write.satisfies(Scope::Read));
        assert!(Scope::Write.satisfies(Scope::Write));
        assert!(!Scope::Write.satisfies(Scope::Delete));
        assert!(!Scope::Write.satisfies(Scope::Admin));

        assert!(Scope::Delete.satisfies(Scope::Read));
        assert!(Scope::Delete.satisfies(Scope::Write));
        assert!(Scope::Delete.satisfies(Scope::Delete));
        assert!(!Scope::Delete.satisfies(Scope::Admin));

        assert!(Scope::Admin.satisfies(Scope::Read));
        assert!(Scope::Admin.satisfies(Scope::Write));
        assert!(Scope::Admin.satisfies(Scope::Delete));
        assert!(Scope::Admin.satisfies(Scope::Admin));
    }

    #[test]
    fn test_default_scope_is_read() {
        let server = McpServer::new();
        assert_eq!(server.granted_scope(), Scope::Read);
    }

    #[test]
    fn test_read_scope_blocks_write() {
        let mut server = McpServer::new()
            .with_vault(Box::new(MockVault))
            .with_scope(Scope::Read);
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault_add_credential",
                "arguments": { "title": "X", "password": "p" }
            })),
        );
        let resp = server.handle_request(&req);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32001);
        assert!(err.message.contains("write"));
    }

    #[test]
    fn test_write_scope_blocks_delete() {
        let mut server = McpServer::new()
            .with_vault(Box::new(MockVault))
            .with_scope(Scope::Write);
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault_delete_credential",
                "arguments": { "title": "GitHub" }
            })),
        );
        let resp = server.handle_request(&req);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32001);
        assert!(err.message.contains("delete"));
    }

    #[test]
    fn test_read_scope_blocks_audit_log() {
        let mut server = McpServer::new()
            .with_vault(Box::new(MockVault))
            .with_scope(Scope::Read);
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_audit_log", "arguments": {} })),
        );
        let resp = server.handle_request(&req);
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32001);
    }

    // -- audit log tests ----------------------------------------------------

    #[test]
    fn test_audit_log_records_tool_calls() {
        let mut server = McpServer::new()
            .with_vault(Box::new(MockVault))
            .with_scope(Scope::Admin);

        // Perform a read
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_status", "arguments": {} })),
        );
        server.handle_request(&req);

        let entries = server.audit_log().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool, "vault_status");
        assert!(entries[0].allowed);
        assert!(entries[0].success);
    }

    #[test]
    fn test_audit_log_records_denied_calls() {
        let mut server = McpServer::new()
            .with_vault(Box::new(MockVault))
            .with_scope(Scope::Read);

        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault_add_credential",
                "arguments": { "title": "X", "password": "p" }
            })),
        );
        server.handle_request(&req);

        let entries = server.audit_log().entries();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].allowed);
        assert!(!entries[0].success);
    }

    #[test]
    fn test_vault_audit_log_tool() {
        let mut server = McpServer::new()
            .with_vault(Box::new(MockVault))
            .with_scope(Scope::Admin);

        // Generate an entry first
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_list_credentials", "arguments": {} })),
        );
        server.handle_request(&req);

        // Now query the audit log via the tool
        let req = make_request(
            "tools/call",
            Some(json!({ "name": "vault_audit_log", "arguments": {} })),
        );
        let resp = server.handle_request(&req);
        assert!(resp.error.is_none());
        let text = resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        // First entry is vault_list_credentials, audit_log query itself is
        // recorded *after* returning the snapshot, so only 1 entry visible.
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["tool"], "vault_list_credentials");

        // After the call, the audit log has 2 entries total
        assert_eq!(server.audit_log().entries().len(), 2);
    }
}
