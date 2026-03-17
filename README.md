# Plures Vault

**Zero-trust P2P password manager with graph-native secrets and AI-native MCP**

## Features

- 🔐 **Zero-knowledge encryption** — Master password never leaves your device
- 🚀 **No cloud dependencies** — P2P sync with your own devices only
- 🛡️ **Enterprise-grade crypto** — Argon2 + AES-256-GCM
- 📱 **Cross-platform** — Desktop (Rust/Tauri) + Browser extensions
- 🌐 **P2P sync** — PluresDB CRDT replication for device-to-device synchronization
- 💼 **Enterprise ready** — Azure Key Vault integration
- 🕸️ **Graph-native secrets** — Relationship-first secret management with groups, tags, and dependency tracking
- 🤖 **AI-native MCP** — Model Context Protocol server for AI agent integration

## Quick Start

```bash
# Initialize a new vault
cargo run -- init --name "My Secure Vault"

# Add a credential
cargo run -- add --title "GitHub" --username "myuser"

# Get a credential
cargo run -- get --title "GitHub"

# List all credentials
cargo run -- list
```

## Graph-Native Secret Management

Plures Vault introduces relationship-first secret management. Secrets aren't flat entries — they form a graph of relationships:

```bash
# Create organizational groups and tags
cargo run -- graph add-group --label "Work"
cargo run -- graph add-tag --label "critical"

# Link credentials to groups and tags
cargo run -- graph link-group --credential <CRED_UUID> --group <GROUP_UUID>
cargo run -- graph link-tag --credential <CRED_UUID> --tag <TAG_UUID>

# Add dependencies between credentials
cargo run -- graph add-dep --source <APP_UUID> --target <DB_UUID>

# Analyze rotation impact — what breaks if a secret changes?
cargo run -- graph impact --credential <DB_UUID>

# View the full secret graph
cargo run -- graph show
```

### Relationship Types

| Type | Description |
|------|-------------|
| `DependsOn` | Secret A depends on Secret B (e.g., app depends on DB credential) |
| `GroupMember` | Secret belongs to an organizational group |
| `TaggedWith` | Secret has a classification tag |
| `DerivedFrom` | Secret is derived from another (e.g., API key from master) |
| `SharedWith` | Secret is shared with an environment/service |
| `Supersedes` | Secret replaces an older version |
| `BundledWith` | Secrets are used together (e.g., username + password + 2FA) |

## AI-Native MCP Server

Plures Vault includes a [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server, allowing AI agents to interact with the vault programmatically:

```bash
# Start MCP server (reads JSON-RPC from stdin)
cargo run -- mcp-serve
```

### Available Tools

| Tool | Description |
|------|-------------|
| `vault_list_credentials` | List all credential titles |
| `vault_get_credential` | Get a specific credential by title |
| `vault_add_credential` | Add a new credential |
| `vault_delete_credential` | Delete a credential |
| `vault_search` | Search credentials by query |
| `vault_status` | Get vault status information |

### MCP Resources

| URI | Description |
|-----|-------------|
| `vault://credentials` | List of all credentials |
| `vault://status` | Current vault status |

## Architecture

```
Master Password (device-only)
    ↓ Argon2
Derived Master Key (memory-only)
    ↓ AES-256-GCM
PluresDB CRDT Store (encrypted at rest)
    ↓ Graph Layer (relationships, groups, tags)
    ↓ MCP Server (AI-native tool interface)
    ↓ P2P Sync (GUN protocol / relay)
Encrypted Sync to Your Devices
```

### Crate Architecture

| Crate | Description |
|-------|-------------|
| `vault-core` | Core vault operations backed by PluresDB |
| `vault-crypto` | AES-256-GCM encryption + Argon2 key derivation |
| `vault-graph` | Graph-native secret relationship management |
| `vault-mcp` | MCP (Model Context Protocol) server for AI integration |
| `vault-sync` | P2P sync via PluresDB CRDT replication |
| `vault-akv` | Azure Key Vault bidirectional sync |

## Development Status

- ✅ **Phase 1: Core Vault** — Production-ready CLI with PluresDB backend
- ✅ **Phase 2: Graph-Native Secrets** — Relationship-first secret management
- ✅ **Phase 3: AI-Native MCP** — Model Context Protocol server
- ✅ **Phase 4: P2P Sync** — PluresDB CRDT replication with GUN protocol
- 🔄 **Phase 5: GUI + Browser Extensions** — In development
- 🔄 **Phase 6: Enterprise Features** — Azure KV sync, multi-partition licensing

## Why Plures Vault?

**vs 1Password/Bitwarden:**
- No subscription fees for personal use
- No cloud servers to compromise
- Your data stays on your devices
- Graph-native secret relationships
- AI-native MCP integration

**vs local solutions:**
- Secure P2P sync across devices
- Professional encryption standards
- Enterprise integration available
- Relationship-aware secret management

## Business Model

- **Personal**: 1 sync partition free forever
- **Scale**: $10/month per additional sync partition (NOT per user!)

**Why this is better:**
- **Small teams**: Share 1 partition = $0/month (vs $10/user elsewhere)
- **Enterprise**: Pay per logical boundary, not headcount
- **Personal**: Add family partition for just $10/month total

## Security

- Master passwords are never stored or transmitted
- All data encrypted with AES-256-GCM before storage
- Argon2 key derivation with secure salting
- Memory safety with automatic secrets cleanup (zeroize)
- PluresDB CRDT store with conflict-free replication
- Open source for transparency

## Enterprise

- Azure Key Vault integration for centralized secret management
- Team credential sharing with granular permissions
- Comprehensive audit logging and compliance reporting
- SSO integration and enterprise policy enforcement

---

**Made by [Plures](https://plures.ai) — Building the future of privacy-first infrastructure**