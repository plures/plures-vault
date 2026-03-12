-- SQLite Schema for Encrypted Credentials (vault-core / SQLx)
-- Migration 0001: Initial schema

-- vault_config: stores vault configuration and key derivation parameters.
-- Enforces single-row semantics via a constant primary key (id = 1).
CREATE TABLE IF NOT EXISTS vault_config (
    id INTEGER PRIMARY KEY CHECK (id = 1) DEFAULT 1,
    vault_id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    vault_name TEXT NOT NULL,
    salt TEXT NOT NULL,
    key_derivation_params TEXT NOT NULL, -- JSON: {"algorithm","m_cost","t_cost","p_cost"}
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (vault_id)
);

-- credentials: stores encrypted credential entries.
-- encrypted_password and encrypted_notes hold JSON-serialised EncryptedData payloads.
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL UNIQUE,
    username TEXT,
    encrypted_password TEXT NOT NULL,
    encrypted_notes TEXT,
    url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- credential_metadata: custom encrypted key/value fields attached to a credential.
CREATE TABLE IF NOT EXISTS credential_metadata (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    PRIMARY KEY (credential_id, key)
);

-- sync_metadata: tracks P2P sync state for each credential (future Hyperswarm use).
CREATE TABLE IF NOT EXISTS sync_metadata (
    credential_id TEXT NOT NULL PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
    last_sync TEXT NOT NULL,
    sync_hash TEXT NOT NULL
);
