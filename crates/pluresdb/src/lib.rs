pub use pluresdb_core::{NodeData, Record};
pub use pluresdb_storage::{MemoryStorage, SledStorage, StorageEngine, StorageError};
pub use pluresdb_sync::{GunRelayServer, SyncBroadcaster, SyncEvent};

use std::sync::Arc;

pub struct CrdtStore {
    persistence: Option<Arc<dyn StorageEngine>>,
    fallback: MemoryStorage,
}

impl Default for CrdtStore {
    fn default() -> Self {
        Self {
            persistence: None,
            fallback: MemoryStorage::default(),
        }
    }
}

impl CrdtStore {
    pub fn with_persistence(mut self, engine: Arc<dyn StorageEngine>) -> Self {
        self.persistence = Some(engine);
        self
    }

    fn engine(&self) -> &dyn StorageEngine {
        self.persistence
            .as_ref()
            .map(|e| e.as_ref())
            .unwrap_or(&self.fallback)
    }

    pub fn put(&self, key: impl Into<String>, _actor_id: &str, data: NodeData) {
        let key = key.into();
        let _ = self.engine().put(&key, &data);
    }

    pub fn get(&self, key: &str) -> Option<Record> {
        self.engine().get(key).ok().flatten()
    }

    pub fn list(&self) -> Vec<Record> {
        self.engine().list().unwrap_or_default()
    }

    pub fn delete(&self, key: &str) -> Result<(), String> {
        self.engine()
            .delete(key)
            .map_err(|e| e.to_string())
    }
}
