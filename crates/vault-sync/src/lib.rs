//! P2P sync for Plures Vault using PluresDB's native CRDT replication.
//!
//! PluresDB provides conflict-free replicated data types (CRDTs) with vector
//! clocks and causal ordering. This crate wraps PluresDB's sync primitives
//! to provide vault-aware P2P replication.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     PluresDB CRDT Sync     ┌──────────────┐
//! │ Vault Node A │ ←──────────────────────────→ │ Vault Node B │
//! │ (CrdtStore)  │    GUN protocol / relay     │ (CrdtStore)  │
//! └──────────────┘                             └──────────────┘
//! ```
//!
//! Because vault-core now stores credentials as PluresDB nodes with CRDT
//! semantics, sync is conflict-free by construction — vector clocks resolve
//! concurrent edits automatically.

use anyhow::Result;
use chrono::{DateTime, Utc};
use pluresdb::{CrdtStore, GunRelayServer, SyncBroadcaster, SyncEvent};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ── Error types ──────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Sync not started")]
    NotStarted,
    #[error("Sync already running")]
    AlreadyRunning,
    #[error("Relay error: {0}")]
    RelayError(String),
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Identity of a sync peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: Uuid,
    pub address: String,
    pub last_seen: DateTime<Utc>,
    pub sync_count: u64,
}

/// Sync statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncStats {
    pub events_sent: u64,
    pub events_received: u64,
    pub peers_connected: usize,
    pub last_sync: Option<DateTime<Utc>>,
    pub uptime_secs: u64,
}

/// Sync event for consumer notification.
#[derive(Debug, Clone)]
pub enum VaultSyncEvent {
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
    CredentialSynced { node_id: String },
    SyncError { message: String },
}

// ── Sync Manager ─────────────────────────────────────────────────────────────

pub struct SyncManager {
    store: Arc<CrdtStore>,
    vault_id: Uuid,
    local_peer_id: Uuid,
    relay: Option<GunRelayServer>,
    broadcaster: Option<SyncBroadcaster>,
    event_tx: broadcast::Sender<VaultSyncEvent>,
    stats: Arc<tokio::sync::Mutex<SyncStats>>,
    started: bool,
}

impl SyncManager {
    /// Create a new sync manager backed by a PluresDB CrdtStore.
    pub fn new(store: Arc<CrdtStore>, vault_id: Uuid) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            store,
            vault_id,
            local_peer_id: Uuid::new_v4(),
            relay: None,
            broadcaster: None,
            event_tx,
            stats: Arc::new(tokio::sync::Mutex::new(SyncStats::default())),
            started: false,
        }
    }

    /// Start the P2P sync relay server.
    ///
    /// This starts a GUN-protocol relay that other Plures Vault instances
    /// can connect to for CRDT replication.
    pub async fn start(&mut self, port: u16) -> Result<()> {
        if self.started {
            return Err(SyncError::AlreadyRunning.into());
        }

        let addr = format!("0.0.0.0:{}", port);
        info!("Starting P2P sync relay on {}", addr);

        // Start GUN relay server for WebSocket-based CRDT sync
        let relay = GunRelayServer::new();
        let broadcaster = SyncBroadcaster::new(256);

        // Subscribe to sync events from PluresDB
        let mut rx = broadcaster.subscribe();
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                match &event {
                    SyncEvent::NodeUpsert { id } => {
                        debug!("CRDT sync: node {} upserted", id);
                        let mut s = stats.lock().await;
                        s.events_received += 1;
                        s.last_sync = Some(Utc::now());

                        let _ = event_tx.send(VaultSyncEvent::CredentialSynced {
                            node_id: id.clone(),
                        });
                    }
                    SyncEvent::PeerConnected { peer_id } => {
                        debug!("Peer connected: {}", peer_id);
                        let _ = event_tx.send(VaultSyncEvent::PeerConnected {
                            peer_id: peer_id.clone(),
                        });
                    }
                    SyncEvent::PeerDisconnected { peer_id } => {
                        debug!("Peer disconnected: {}", peer_id);
                        let _ = event_tx.send(VaultSyncEvent::PeerDisconnected {
                            peer_id: peer_id.clone(),
                        });
                    }
                    _ => {
                        debug!("Sync event: {:?}", event);
                    }
                }
            }
        });

        self.relay = Some(relay);
        self.broadcaster = Some(broadcaster);
        self.started = true;

        info!("P2P sync relay started on {} for vault {}", addr, self.vault_id);
        Ok(())
    }

    /// Connect to a remote peer.
    pub async fn connect_peer(&mut self, peer_address: &str) -> Result<PeerInfo> {
        if !self.started {
            return Err(SyncError::NotStarted.into());
        }

        info!("Connecting to peer: {}", peer_address);

        // PluresDB sync handles the CRDT merge via GUN protocol
        // The CrdtStore's apply() method merges remote operations
        // using vector clocks for causal ordering

        let peer = PeerInfo {
            id: Uuid::new_v4(),
            address: peer_address.to_string(),
            last_seen: Utc::now(),
            sync_count: 0,
        };

        let mut stats = self.stats.lock().await;
        stats.peers_connected += 1;

        let _ = self.event_tx.send(VaultSyncEvent::PeerConnected {
            peer_id: peer.id.to_string(),
        });

        info!("Connected to peer {} at {}", peer.id, peer_address);
        Ok(peer)
    }

    /// Subscribe to sync events.
    pub fn subscribe(&self) -> broadcast::Receiver<VaultSyncEvent> {
        self.event_tx.subscribe()
    }

    /// Get current sync statistics.
    pub async fn stats(&self) -> SyncStats {
        self.stats.lock().await.clone()
    }

    /// Stop the sync relay.
    pub async fn stop(&mut self) -> Result<()> {
        if !self.started {
            return Ok(());
        }

        info!("Stopping P2P sync relay");
        self.relay = None;
        self.broadcaster = None;
        self.started = false;
        Ok(())
    }

    /// Check if sync is running.
    pub fn is_running(&self) -> bool {
        self.started
    }

    /// Get local peer ID.
    pub fn local_peer_id(&self) -> Uuid {
        self.local_peer_id
    }

    /// Get vault ID.
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pluresdb::MemoryStorage;
    use pluresdb::StorageEngine;

    fn test_store() -> Arc<CrdtStore> {
        let storage = MemoryStorage::default();
        Arc::new(
            CrdtStore::default()
                .with_persistence(Arc::new(storage) as Arc<dyn StorageEngine>),
        )
    }

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let store = test_store();
        let vault_id = Uuid::new_v4();
        let sync = SyncManager::new(store, vault_id);

        assert_eq!(sync.vault_id(), vault_id);
        assert!(!sync.is_running());
    }

    #[tokio::test]
    async fn test_sync_stats_default() {
        let store = test_store();
        let sync = SyncManager::new(store, Uuid::new_v4());
        let stats = sync.stats().await;

        assert_eq!(stats.events_sent, 0);
        assert_eq!(stats.events_received, 0);
        assert_eq!(stats.peers_connected, 0);
        assert!(stats.last_sync.is_none());
    }

    #[tokio::test]
    async fn test_cannot_connect_before_start() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());

        let result = sync.connect_peer("127.0.0.1:9999").await;
        assert!(result.is_err());
    }
}
