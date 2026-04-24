# Plures Vault Roadmap

## Role in OASIS
Plures Vault is the security and credential layer for OASIS. It demonstrates zero‑knowledge, local‑first secret management and P2P sync, proving OASIS crypto patterns and privacy guarantees in a real product. It is also the reference MCP service for secure agent access to sensitive data.

## Current State
- Rust/Tauri CLI with graph‑native secret model
- Argon2 + AES‑256‑GCM encryption, zero‑knowledge design
- PluresDB CRDT replication for device‑to‑device sync (early)
- MCP server for agent access

## Near Term (v0.2–0.3)
- Harden vault init / recovery flows (seed backup, rotation, export)
- Complete P2P sync UX + conflict handling
- Expand MCP surface with least‑privilege scopes and audit logs
- Add deterministic test vectors + cryptographic validation suite

## Mid Term (v0.4–0.6)
- Browser extension + desktop pairing flow
- Device trust graph (approved devices, revocation, quarantine)
- Vault policies wired to praxis rules for OASIS privacy enforcement
- Encrypted sharing primitives (group secrets, time‑boxed grants)

## Long Term (v1.0+)
- ZK proof integration for OASIS commerce flows (prove access without revealing secrets)
- Enterprise integration hardened (Key Vault, SSO, policy gates)
- Multi‑tenant vaults for OASIS orgs and marketplaces
- Security certification / formal verification track
