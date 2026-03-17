use pluresdb_core::{NodeData, Record};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Storage I/O error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Key not found: {0}")]
    NotFound(String),
}

pub trait StorageEngine: Send + Sync {
    fn put(&self, key: &str, data: &NodeData) -> Result<(), StorageError>;
    fn get(&self, key: &str) -> Result<Option<Record>, StorageError>;
    fn list(&self) -> Result<Vec<Record>, StorageError>;
    fn delete(&self, key: &str) -> Result<(), StorageError>;
}

// ── In-memory storage ────────────────────────────────────────────────────────

pub struct MemoryStorage {
    data: RwLock<HashMap<String, NodeData>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl StorageEngine for MemoryStorage {
    fn put(&self, key: &str, data: &NodeData) -> Result<(), StorageError> {
        self.data
            .write()
            .map_err(|e| StorageError::Io(e.to_string()))?
            .insert(key.to_string(), data.clone());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Record>, StorageError> {
        let guard = self
            .data
            .read()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(guard.get(key).map(|d| Record {
            id: key.to_string(),
            data: d.clone(),
        }))
    }

    fn list(&self) -> Result<Vec<Record>, StorageError> {
        let guard = self
            .data
            .read()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(guard
            .iter()
            .map(|(k, v)| Record {
                id: k.clone(),
                data: v.clone(),
            })
            .collect())
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.data
            .write()
            .map_err(|e| StorageError::Io(e.to_string()))?
            .remove(key);
        Ok(())
    }
}

// ── Sled-backed persistent storage ──────────────────────────────────────────

pub struct SledStorage {
    db: sled::Db,
}

impl SledStorage {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let db = sled::open(path).map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(Self { db })
    }
}

impl StorageEngine for SledStorage {
    fn put(&self, key: &str, data: &NodeData) -> Result<(), StorageError> {
        let bytes =
            serde_json::to_vec(data).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db
            .insert(key.as_bytes(), bytes)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Record>, StorageError> {
        match self
            .db
            .get(key.as_bytes())
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let data: NodeData = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(Record {
                    id: key.to_string(),
                    data,
                }))
            }
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<Record>, StorageError> {
        let mut records = Vec::new();
        for entry in self.db.iter() {
            let (key_bytes, val_bytes) =
                entry.map_err(|e| StorageError::Io(e.to_string()))?;
            let key = String::from_utf8_lossy(&key_bytes).to_string();
            let data: NodeData = serde_json::from_slice(&val_bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            records.push(Record { id: key, data });
        }
        Ok(records)
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.db
            .remove(key.as_bytes())
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }
}
