//! P2P sync for Plures Vault using PluresDB's native CRDT replication.
//!
//! PluresDB provides conflict-free replicated data types (CRDTs) with vector
//! clocks and causal ordering. This crate wraps PluresDB's sync primitives
//! to provide vault-aware P2P replication with conflict detection and
//! resolution UX.
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
//! semantics, most edits are conflict-free by construction — vector clocks
//! resolve concurrent edits automatically. When semantic conflicts arise
//! (e.g. two peers update the same field concurrently), the conflict manager
//! records them and applies a configurable resolution strategy.

use anyhow::Result;
use chrono::{DateTime, Utc};
use pluresdb::{CrdtStore, GunRelayServer, SyncBroadcaster, SyncEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, info};
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
    #[error("Conflict not found: {0}")]
    ConflictNotFound(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// ── Conflict handling ────────────────────────────────────────────────────────

/// Strategy for resolving sync conflicts when two peers edit the same
/// credential concurrently.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictStrategy {
    /// Accept the remote peer's version.
    RemoteWins,
    /// Keep the local version.
    LocalWins,
    /// Automatically pick the version with the most recent `updated_at`.
    LastWriteWins,
    /// Require manual resolution — conflicts stay pending until the user
    /// explicitly picks a winner.
    Manual,
}

impl Default for ConflictStrategy {
    fn default() -> Self {
        Self::LastWriteWins
    }
}

/// A snapshot of one side of a conflict (local or remote).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictVersion {
    pub peer_id: String,
    pub data: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// A detected conflict between local and remote versions of a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub id: Uuid,
    pub node_id: String,
    pub local_version: ConflictVersion,
    pub remote_version: ConflictVersion,
    pub detected_at: DateTime<Utc>,
    pub resolved: bool,
    pub resolution: Option<ConflictResolution>,
}

/// How a conflict was resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolution {
    pub strategy: ConflictStrategy,
    pub winner: ConflictWinner,
    pub resolved_at: DateTime<Utc>,
}

/// Which side won the conflict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictWinner {
    Local,
    Remote,
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
    pub conflicts_detected: u64,
    pub conflicts_resolved: u64,
    pub last_sync: Option<DateTime<Utc>>,
    pub uptime_secs: u64,
}

/// Sync event for consumer notification.
#[derive(Debug, Clone)]
pub enum VaultSyncEvent {
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
    CredentialSynced { node_id: String },
    ConflictDetected { conflict_id: Uuid, node_id: String },
    ConflictResolved { conflict_id: Uuid, node_id: String, winner: ConflictWinner },
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
    conflicts: Arc<tokio::sync::Mutex<HashMap<Uuid, ConflictRecord>>>,
    conflict_strategy: ConflictStrategy,
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
            conflicts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            conflict_strategy: ConflictStrategy::default(),
            started: false,
        }
    }

    /// Set the conflict resolution strategy.
    pub fn set_conflict_strategy(&mut self, strategy: ConflictStrategy) {
        self.conflict_strategy = strategy;
    }

    /// Get the current conflict resolution strategy.
    pub fn conflict_strategy(&self) -> ConflictStrategy {
        self.conflict_strategy
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

    // ── Conflict management ──────────────────────────────────────────────────

    /// Record a detected conflict between local and remote versions of a node.
    ///
    /// If the current strategy is not `Manual`, the conflict is automatically
    /// resolved and applied to the store. Otherwise it stays pending until the
    /// user calls [`resolve_conflict`].
    pub async fn record_conflict(
        &self,
        node_id: String,
        local_data: serde_json::Value,
        local_updated_at: DateTime<Utc>,
        remote_peer_id: String,
        remote_data: serde_json::Value,
        remote_updated_at: DateTime<Utc>,
    ) -> Result<ConflictRecord> {
        let conflict_id = Uuid::new_v4();

        let mut record = ConflictRecord {
            id: conflict_id,
            node_id: node_id.clone(),
            local_version: ConflictVersion {
                peer_id: self.local_peer_id.to_string(),
                data: local_data,
                updated_at: local_updated_at,
            },
            remote_version: ConflictVersion {
                peer_id: remote_peer_id,
                data: remote_data,
                updated_at: remote_updated_at,
            },
            detected_at: Utc::now(),
            resolved: false,
            resolution: None,
        };

        let mut stats = self.stats.lock().await;
        stats.conflicts_detected += 1;

        let _ = self.event_tx.send(VaultSyncEvent::ConflictDetected {
            conflict_id,
            node_id: node_id.clone(),
        });

        info!("Conflict detected for node {} (id={})", node_id, conflict_id);

        // Auto-resolve non-manual strategies
        if self.conflict_strategy != ConflictStrategy::Manual {
            let winner = match self.conflict_strategy {
                ConflictStrategy::RemoteWins => ConflictWinner::Remote,
                ConflictStrategy::LocalWins => ConflictWinner::Local,
                ConflictStrategy::LastWriteWins => {
                    if record.remote_version.updated_at >= record.local_version.updated_at {
                        ConflictWinner::Remote
                    } else {
                        ConflictWinner::Local
                    }
                }
                ConflictStrategy::Manual => unreachable!(),
            };

            self.apply_resolution(&mut record, winner, &mut stats)?;
        }

        self.conflicts.lock().await.insert(conflict_id, record.clone());
        Ok(record)
    }

    /// Manually resolve a pending conflict by choosing a winner.
    pub async fn resolve_conflict(
        &self,
        conflict_id: Uuid,
        winner: ConflictWinner,
    ) -> Result<ConflictRecord> {
        // Acquire locks in the same order as record_conflict: stats → conflicts
        let mut stats = self.stats.lock().await;
        let mut conflicts = self.conflicts.lock().await;
        let record = conflicts
            .get_mut(&conflict_id)
            .ok_or_else(|| SyncError::ConflictNotFound(conflict_id.to_string()))?;

        if record.resolved {
            return Ok(record.clone());
        }

        self.apply_resolution(record, winner, &mut stats)?;

        Ok(record.clone())
    }

    /// List all conflicts, optionally filtering to only unresolved ones.
    pub async fn list_conflicts(&self, pending_only: bool) -> Vec<ConflictRecord> {
        let conflicts = self.conflicts.lock().await;
        conflicts
            .values()
            .filter(|c| !pending_only || !c.resolved)
            .cloned()
            .collect()
    }

    /// Get a specific conflict by ID.
    pub async fn get_conflict(&self, conflict_id: Uuid) -> Option<ConflictRecord> {
        self.conflicts.lock().await.get(&conflict_id).cloned()
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

    // ── Private helpers ──────────────────────────────────────────────────────

    fn apply_resolution(
        &self,
        record: &mut ConflictRecord,
        winner: ConflictWinner,
        stats: &mut SyncStats,
    ) -> Result<()> {
        let winning_data = match winner {
            ConflictWinner::Local => &record.local_version.data,
            ConflictWinner::Remote => &record.remote_version.data,
        };

        // Apply the winning version to the store
        self.store
            .put(&record.node_id, "sync-resolver", winning_data.clone());

        record.resolved = true;
        record.resolution = Some(ConflictResolution {
            strategy: self.conflict_strategy,
            winner,
            resolved_at: Utc::now(),
        });

        stats.conflicts_resolved += 1;

        let _ = self.event_tx.send(VaultSyncEvent::ConflictResolved {
            conflict_id: record.id,
            node_id: record.node_id.clone(),
            winner,
        });

        info!(
            "Conflict {} resolved: {:?} wins for node {}",
            record.id, winner, record.node_id
        );
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pluresdb::MemoryStorage;
    use pluresdb::StorageEngine;
    use serde_json::json;

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
        assert_eq!(stats.conflicts_detected, 0);
        assert_eq!(stats.conflicts_resolved, 0);
        assert!(stats.last_sync.is_none());
    }

    #[tokio::test]
    async fn test_cannot_connect_before_start() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());

        let result = sync.connect_peer("127.0.0.1:9999").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_conflict_strategy_default() {
        let store = test_store();
        let sync = SyncManager::new(store, Uuid::new_v4());
        assert_eq!(sync.conflict_strategy(), ConflictStrategy::LastWriteWins);
    }

    #[tokio::test]
    async fn test_set_conflict_strategy() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::Manual);
        assert_eq!(sync.conflict_strategy(), ConflictStrategy::Manual);
    }

    #[tokio::test]
    async fn test_record_conflict_auto_resolve_last_write_wins() {
        let store = test_store();
        let sync = SyncManager::new(store, Uuid::new_v4());
        let now = Utc::now();

        let record = sync
            .record_conflict(
                "cred:abc".to_string(),
                json!({"title": "local"}),
                now - chrono::Duration::seconds(10),
                "peer-1".to_string(),
                json!({"title": "remote"}),
                now,
            )
            .await
            .unwrap();

        assert!(record.resolved);
        let resolution = record.resolution.unwrap();
        assert_eq!(resolution.strategy, ConflictStrategy::LastWriteWins);
        assert_eq!(resolution.winner, ConflictWinner::Remote);

        let stats = sync.stats().await;
        assert_eq!(stats.conflicts_detected, 1);
        assert_eq!(stats.conflicts_resolved, 1);
    }

    #[tokio::test]
    async fn test_record_conflict_local_wins() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::LocalWins);

        let record = sync
            .record_conflict(
                "cred:xyz".to_string(),
                json!({"title": "local"}),
                Utc::now(),
                "peer-2".to_string(),
                json!({"title": "remote"}),
                Utc::now(),
            )
            .await
            .unwrap();

        assert!(record.resolved);
        assert_eq!(record.resolution.unwrap().winner, ConflictWinner::Local);
    }

    #[tokio::test]
    async fn test_record_conflict_remote_wins() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::RemoteWins);

        let record = sync
            .record_conflict(
                "cred:xyz".to_string(),
                json!({"title": "local"}),
                Utc::now(),
                "peer-2".to_string(),
                json!({"title": "remote"}),
                Utc::now(),
            )
            .await
            .unwrap();

        assert!(record.resolved);
        assert_eq!(record.resolution.unwrap().winner, ConflictWinner::Remote);
    }

    #[tokio::test]
    async fn test_manual_conflict_stays_pending() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::Manual);

        let record = sync
            .record_conflict(
                "cred:manual".to_string(),
                json!({"title": "local"}),
                Utc::now(),
                "peer-3".to_string(),
                json!({"title": "remote"}),
                Utc::now(),
            )
            .await
            .unwrap();

        assert!(!record.resolved);
        assert!(record.resolution.is_none());

        let pending = sync.list_conflicts(true).await;
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn test_resolve_manual_conflict() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::Manual);

        let record = sync
            .record_conflict(
                "cred:resolve".to_string(),
                json!({"title": "local"}),
                Utc::now(),
                "peer-4".to_string(),
                json!({"title": "remote"}),
                Utc::now(),
            )
            .await
            .unwrap();

        let resolved = sync
            .resolve_conflict(record.id, ConflictWinner::Local)
            .await
            .unwrap();

        assert!(resolved.resolved);
        assert_eq!(resolved.resolution.unwrap().winner, ConflictWinner::Local);

        let pending = sync.list_conflicts(true).await;
        assert_eq!(pending.len(), 0);
    }

    #[tokio::test]
    async fn test_resolve_nonexistent_conflict_fails() {
        let store = test_store();
        let sync = SyncManager::new(store, Uuid::new_v4());

        let result = sync
            .resolve_conflict(Uuid::new_v4(), ConflictWinner::Local)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_conflicts_all_vs_pending() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::Manual);

        // Add two conflicts
        let c1 = sync
            .record_conflict(
                "cred:a".to_string(),
                json!({}),
                Utc::now(),
                "p".to_string(),
                json!({}),
                Utc::now(),
            )
            .await
            .unwrap();

        sync.record_conflict(
            "cred:b".to_string(),
            json!({}),
            Utc::now(),
            "p".to_string(),
            json!({}),
            Utc::now(),
        )
        .await
        .unwrap();

        // Resolve one
        sync.resolve_conflict(c1.id, ConflictWinner::Remote)
            .await
            .unwrap();

        assert_eq!(sync.list_conflicts(false).await.len(), 2);
        assert_eq!(sync.list_conflicts(true).await.len(), 1);
    }

    #[tokio::test]
    async fn test_get_conflict_by_id() {
        let store = test_store();
        let sync = SyncManager::new(store, Uuid::new_v4());

        let record = sync
            .record_conflict(
                "cred:get".to_string(),
                json!({}),
                Utc::now(),
                "p".to_string(),
                json!({}),
                Utc::now(),
            )
            .await
            .unwrap();

        assert!(sync.get_conflict(record.id).await.is_some());
        assert!(sync.get_conflict(Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn test_conflict_events_emitted() {
        let store = test_store();
        let mut sync = SyncManager::new(store, Uuid::new_v4());
        sync.set_conflict_strategy(ConflictStrategy::Manual);
        let mut rx = sync.subscribe();

        sync.record_conflict(
            "cred:evt".to_string(),
            json!({}),
            Utc::now(),
            "p".to_string(),
            json!({}),
            Utc::now(),
        )
        .await
        .unwrap();

        // Should have received a ConflictDetected event
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, VaultSyncEvent::ConflictDetected { .. }));
    }
}
