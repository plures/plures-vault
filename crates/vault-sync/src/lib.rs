use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Sync conflict detected")]
    ConflictError,
    #[error("Invalid sync message")]
    InvalidMessage,
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMessage {
    pub id: Uuid,
    pub msg_type: MessageType,
    pub sender: PeerIdentity,
    pub recipient: Option<PeerIdentity>,
    pub timestamp: DateTime<Utc>,
    pub payload: SyncPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    HandshakeRequest,
    HandshakeResponse,
    CredentialSync,
    ConflictResolution,
    Heartbeat,
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub id: Uuid,
    pub public_key: String, // For authentication
    pub last_seen: DateTime<Utc>,
    pub address: Option<String>, // IP:Port for TCP connection
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncPayload {
    Handshake {
        vault_id: Uuid,
        protocol_version: String,
        public_key: String,
    },
    CredentialUpdate {
        credential_id: Uuid,
        encrypted_data: String,
        version: u64,
        operation: OperationType,
    },
    VectorClock {
        entries: Vec<(Uuid, u64)>, // peer_id -> clock_value
    },
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    Create,
    Update,
    Delete,
}

pub struct SyncManager {
    peers: Arc<Mutex<HashMap<Uuid, PeerIdentity>>>,
    local_clock: Arc<Mutex<u64>>,
    vault_id: Uuid,
    local_peer_id: Uuid,
    #[allow(dead_code)] // Reserved for Phase 2: bound listener handle
    listener: Option<TcpListener>,
}

impl SyncManager {
    pub fn new(vault_id: Uuid) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            local_clock: Arc::new(Mutex::new(0)),
            vault_id,
            local_peer_id: Uuid::new_v4(),
            listener: None,
        }
    }

    pub async fn start_sync_server(&mut self, port: u16) -> Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        
        println!("🔄 P2P sync server started on {}", addr);
        
        let peers = Arc::clone(&self.peers);
        let clock = Arc::clone(&self.local_clock);
        let vault_id = self.vault_id;
        let local_peer_id = self.local_peer_id;

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        println!("📡 New peer connection from: {}", addr);
                        let peers_clone = Arc::clone(&peers);
                        let clock_clone = Arc::clone(&clock);
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_peer_connection(
                                stream, 
                                peers_clone, 
                                clock_clone, 
                                vault_id,
                                local_peer_id
                            ).await {
                                println!("❌ Peer connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        println!("❌ Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_peer_connection(
        mut stream: TcpStream,
        peers: Arc<Mutex<HashMap<Uuid, PeerIdentity>>>,
        clock: Arc<Mutex<u64>>,
        vault_id: Uuid,
        local_peer_id: Uuid,
    ) -> Result<()> {
        let mut buffer = [0; 1024];
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    println!("📡 Peer disconnected");
                    break;
                }
                Ok(n) => {
                    let data = &buffer[..n];
                    
                    // Try to parse as JSON message
                    if let Ok(message_str) = String::from_utf8(data.to_vec()) {
                        if let Ok(message) = serde_json::from_str::<SyncMessage>(&message_str) {
                            Self::handle_sync_message(
                                &message,
                                &mut stream,
                                Arc::clone(&peers),
                                Arc::clone(&clock),
                                vault_id,
                                local_peer_id,
                            ).await?;
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Read error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }

    async fn handle_sync_message(
        message: &SyncMessage,
        stream: &mut TcpStream,
        peers: Arc<Mutex<HashMap<Uuid, PeerIdentity>>>,
        clock: Arc<Mutex<u64>>,
        vault_id: Uuid,
        local_peer_id: Uuid,
    ) -> Result<()> {
        match message.msg_type {
            MessageType::HandshakeRequest => {
                // Respond with handshake
                let response = SyncMessage {
                    id: Uuid::new_v4(),
                    msg_type: MessageType::HandshakeResponse,
                    sender: PeerIdentity {
                        id: local_peer_id,
                        public_key: "local_pubkey".to_string(), // TODO: Real crypto
                        last_seen: Utc::now(),
                        address: None,
                    },
                    recipient: Some(message.sender.clone()),
                    timestamp: Utc::now(),
                    payload: SyncPayload::Handshake {
                        vault_id,
                        protocol_version: "1.0".to_string(),
                        public_key: "local_pubkey".to_string(),
                    },
                };

                let response_json = serde_json::to_string(&response)?;
                stream.write_all(response_json.as_bytes()).await?;

                // Store peer
                peers.lock().await.insert(message.sender.id, message.sender.clone());
                println!("🤝 Handshake completed with peer: {}", message.sender.id);
            }
            MessageType::Ping => {
                let pong = SyncMessage {
                    id: Uuid::new_v4(),
                    msg_type: MessageType::Pong,
                    sender: PeerIdentity {
                        id: local_peer_id,
                        public_key: "local_pubkey".to_string(),
                        last_seen: Utc::now(),
                        address: None,
                    },
                    recipient: Some(message.sender.clone()),
                    timestamp: Utc::now(),
                    payload: SyncPayload::Pong,
                };

                let pong_json = serde_json::to_string(&pong)?;
                stream.write_all(pong_json.as_bytes()).await?;
            }
            MessageType::CredentialSync => {
                // Handle credential synchronization
                Self::increment_clock_static(Arc::clone(&clock)).await;
                println!("📤 Credential sync received: {:?}", message.payload);
                
                // TODO: Apply credential changes to local vault
                // This will integrate with vault-core to update credentials
            }
            _ => {
                println!("📬 Received message: {:?}", message.msg_type);
            }
        }

        Ok(())
    }

    pub async fn connect_to_peer(&mut self, peer_address: &str) -> Result<PeerIdentity> {
        println!("🔗 Connecting to peer: {}", peer_address);
        
        let mut stream = TcpStream::connect(peer_address).await?;
        
        // Send handshake
        let handshake = SyncMessage {
            id: Uuid::new_v4(),
            msg_type: MessageType::HandshakeRequest,
            sender: PeerIdentity {
                id: self.local_peer_id,
                public_key: "local_pubkey".to_string(),
                last_seen: Utc::now(),
                address: None,
            },
            recipient: None,
            timestamp: Utc::now(),
            payload: SyncPayload::Handshake {
                vault_id: self.vault_id,
                protocol_version: "1.0".to_string(),
                public_key: "local_pubkey".to_string(),
            },
        };

        let handshake_json = serde_json::to_string(&handshake)?;
        stream.write_all(handshake_json.as_bytes()).await?;
        
        // Read response
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;
        let response_data = &buffer[..n];
        
        if let Ok(response_str) = String::from_utf8(response_data.to_vec()) {
            if let Ok(response) = serde_json::from_str::<SyncMessage>(&response_str) {
                if let MessageType::HandshakeResponse = response.msg_type {
                    let peer = response.sender.clone();
                    self.peers.lock().await.insert(peer.id, peer.clone());
                    println!("✅ Successfully connected to peer: {}", peer.id);
                    return Ok(peer);
                }
            }
        }

        Err(SyncError::NetworkError("Invalid handshake response".to_string()).into())
    }

    pub async fn increment_clock(&self) {
        let mut clock_guard = self.local_clock.lock().await;
        *clock_guard += 1;
    }

    async fn increment_clock_static(clock: Arc<Mutex<u64>>) {
        let mut clock_guard = clock.lock().await;
        *clock_guard += 1;
    }

    pub async fn get_clock(&self) -> u64 {
        *self.local_clock.lock().await
    }

    pub async fn list_peers(&self) -> Vec<PeerIdentity> {
        self.peers.lock().await.values().cloned().collect()
    }

    pub async fn sync_credential(
        &mut self,
        credential_id: Uuid,
        encrypted_data: String,
        operation: OperationType,
    ) -> Result<()> {
        self.increment_clock().await;
        
        let message = SyncMessage {
            id: Uuid::new_v4(),
            msg_type: MessageType::CredentialSync,
            sender: PeerIdentity {
                id: self.local_peer_id,
                public_key: "local_pubkey".to_string(),
                last_seen: Utc::now(),
                address: None,
            },
            recipient: None, // Broadcast to all peers
            timestamp: Utc::now(),
            payload: SyncPayload::CredentialUpdate {
                credential_id,
                encrypted_data,
                version: self.get_clock().await,
                operation,
            },
        };

        // TODO: Send to all connected peers
        println!("📤 Credential sync initiated: {:?}", message.payload);
        
        Ok(())
    }

    pub fn get_local_peer_id(&self) -> Uuid {
        self.local_peer_id
    }

    pub fn get_vault_id(&self) -> Uuid {
        self.vault_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let vault_id = Uuid::new_v4();
        let sync_manager = SyncManager::new(vault_id);
        
        assert_eq!(sync_manager.get_vault_id(), vault_id);
        assert_eq!(sync_manager.get_clock().await, 0);
        assert_eq!(sync_manager.list_peers().await.len(), 0);
    }

    #[tokio::test]
    async fn test_clock_increment() {
        let vault_id = Uuid::new_v4();
        let sync_manager = SyncManager::new(vault_id);
        
        assert_eq!(sync_manager.get_clock().await, 0);
        sync_manager.increment_clock().await;
        assert_eq!(sync_manager.get_clock().await, 1);
    }
}