# plures-vault Roadmap

## Role in Plures Ecosystem
plures-vault is the zero-trust secret manager for Plures, combining encrypted storage, graph-native relationships, P2P sync, and MCP tooling for AI agents. It anchors secure credential handling across the ecosystem.

## Current State
Core vault CLI, crypto, graph relationships, MCP server, and PluresDB-based sync are implemented. Browser extension and GUI work exist but are not fully productized. Enterprise features (Azure Key Vault sync, audit trails) are partially scoped.

## Milestones

### Near-term (Q2 2026)
- Stabilize browser extension and GUI MVP for daily use.
- Harden sync flows (conflict handling, device enrollment).
- Add audit log schema and export tooling.
- Improve onboarding (import/export, migration guides).
- Expand automated tests for crypto + graph integrity.

### Mid-term (Q3–Q4 2026)
- Implement secure sharing workflows (team vaults, permissions).
- Add policy controls (rotation reminders, password hygiene).
- Integrate Azure Key Vault bidirectional sync.
- Release MCP integration guides and agent examples.
- Support multiple vault partitions with licensing hooks.

### Long-term
- Full enterprise compliance suite (SOC2-ready audit reports).
- Cross-platform mobile clients with offline-first sync.
- Plures ecosystem single-sign-on and identity federation.
- Trusted hardware integration (TPM/SE) for key storage.
