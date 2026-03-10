# Plures Vault

**Zero-trust P2P password manager**

## Features

- 🔐 **Zero-knowledge encryption** - Master password never leaves your device
- 🚀 **No cloud dependencies** - P2P sync with your own devices only
- 🛡️ **Enterprise-grade crypto** - Argon2 + AES-256-GCM
- 📱 **Cross-platform** - Desktop (Rust/Tauri) + Browser extensions
- 🌐 **P2P sync** - Hyperswarm for device-to-device synchronization
- 💼 **Enterprise ready** - Azure Key Vault integration

## Quick Start

```bash
# Initialize a new vault
cargo run -- init --name "My Secure Vault"

# Add a credential
cargo run -- add --name "github" --username "myuser" 

# Get a credential
cargo run -- get --name "github"

# List all credentials
cargo run -- list
```

## Architecture

```
Master Password (device-only)
    ↓ Argon2
Derived Master Key (memory-only)
    ↓ AES-256-GCM
Encrypted SQLite Database
    ↓ Hyperswarm P2P (Phase 2)
Encrypted Sync to Your Devices
```

## Development Status

- ✅ **Phase 1: Core Vault** - Production ready CLI
- 🔄 **Phase 2: GUI + P2P Sync** - In development
- 🔄 **Phase 3: Browser Extensions** - Planned
- 🔄 **Phase 4: Enterprise Features** - Planned

## Why Plures Vault?

**vs 1Password/Bitwarden:**
- No subscription fees for personal use
- No cloud servers to compromise
- Your data stays on your devices

**vs local solutions:**
- Secure P2P sync across devices
- Professional encryption standards
- Enterprise integration available

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
- Memory safety with automatic secrets cleanup
- Open source for transparency

## Enterprise

- Azure Key Vault integration for centralized secret management
- Team credential sharing with granular permissions
- Comprehensive audit logging and compliance reporting
- SSO integration and enterprise policy enforcement

---

**Made by [Plures](https://plures.ai) - Building the future of privacy-first infrastructure**