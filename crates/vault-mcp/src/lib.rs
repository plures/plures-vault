use serde::{Deserialize, Serialize};
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

// ---------------------------------------------------------------------------
// McpServer
// ---------------------------------------------------------------------------

pub struct McpServer {
    info: ServerInfo,
    tools: Vec<ToolDefinition>,
    resources: Vec<ResourceDefinition>,
    vault: Option<Box<dyn VaultOperations>>,
    initialized: bool,
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
        }
    }

    /// Builder method — attach a vault backend.
    pub fn with_vault(mut self, vault: Box<dyn VaultOperations>) -> Self {
        self.vault = Some(vault);
        self
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

        let vault = match &self.vault {
            Some(v) => v,
            None => {
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
        assert_eq!(server.tools().len(), 6);
        assert_eq!(server.resources().len(), 2);
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
        assert_eq!(tools.len(), 6);

        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"vault_list_credentials"));
        assert!(names.contains(&"vault_get_credential"));
        assert!(names.contains(&"vault_add_credential"));
        assert!(names.contains(&"vault_delete_credential"));
        assert!(names.contains(&"vault_search"));
        assert!(names.contains(&"vault_status"));

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
        assert_eq!(resources.len(), 2);

        let uris: Vec<&str> = resources.iter().map(|r| r["uri"].as_str().unwrap()).collect();
        assert!(uris.contains(&"vault://credentials"));
        assert!(uris.contains(&"vault://status"));
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
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
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
        let mut server = McpServer::new().with_vault(Box::new(MockVault));

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
        let mut server = McpServer::new().with_vault(Box::new(MockVault));
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
}
