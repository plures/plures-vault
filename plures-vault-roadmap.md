# Plures Vault: P2P Password Manager

**Vision**: Zero-trust password manager with P2P sync, no cloud dependencies

## Enterprise Integration Model

### Azure Key Vault Frontend Architecture
- **Plures Vault = UI/Frontend**, **Azure Key Vault = Backend Store**
- Each sync partition can pair with exactly 1 Azure Key Vault
- Bidirectional sync: Plures updates → Auto-sync to Key Vault (with error handling)
- Enterprise users see familiar Plures interface backed by compliant Key Vault storage

### Multi-Partition Management
- **Single license supports multiple partitions** (10s to 1000s possible)
- **Unified interface**: View/manage all partitions from one Plures instance
- **Partition examples:**
  - `work-partition` ↔ `company-keyvault-prod`
  - `dev-partition` ↔ `company-keyvault-dev`  
  - `personal-partition` ↔ Local P2P only (no Key Vault)

### Licensing & Partnership
- **Personal**: 1 partition free (local P2P only)
- **Key Vault integration**: Requires license (per partition or enterprise bundle)
- **Microsoft partnership**: Microsoft handles enterprise compliance/payment enforcement
- **Anti-abuse**: Enterprise detection via Key Vault usage patterns

## Architecture

```
Master Password (device-only)
    ↓ PBKDF2/Argon2
Derived Master Key (memory-only)
    ↓ AES-256
Encrypted PluresDB (at rest)
    ↓ Hyperswarm P2P
Encrypted Blobs Sync (zero-knowledge)
```

## Tech Stack

- **Backend**: PluresDB + Rust crypto + Hyperswarm
- **Frontend**: Svelte + Tauri + design-dojo components
- **Extension**: Chrome/Edge WebExtension (design-dojo styled)
- **Enterprise**: Azure Key Vault integration

## Development Phases

### Phase 1: Core Vault (2-3 weeks)
- [ ] PluresDB schema for encrypted credentials
- [x] **Master password derivation (Argon2)** - ✅ Implemented with secure salting
- [x] **AES-256 encryption/decryption layer** - ✅ AES-256-GCM with comprehensive tests
- [ ] Basic CRUD operations
- [x] **CLI interface scaffold** - ✅ Complete with all commands

### Phase 2: GUI + Sync (4-6 weeks)  
- [ ] Svelte-Tauri desktop app using design-dojo components
- [ ] Build required vault UI components in design-dojo first
- [ ] Hyperswarm P2P sync protocol
- [ ] Multi-device key derivation
- [ ] Conflict resolution for concurrent edits

### Phase 3: Browser Integration (6-8 weeks)
- [ ] Chrome/Edge extension
- [ ] Auto-fill and form detection
- [ ] Secure communication with desktop app
- [ ] Password generation + breach detection

### Phase 4: Enterprise (8-12 weeks)
- [ ] **Azure Key Vault bidirectional sync** (1 Key Vault per partition)
- [ ] **Multi-partition UI** (single interface for all topics)
- [ ] **Enterprise licensing system** (Key Vault integration requires license)
- [ ] **Auto-sync with error handling** (background Key Vault updates)
- [ ] **Microsoft partnership integration** (compliance/payment enforcement)
- [ ] **License abuse detection** (enterprise usage pattern monitoring)
- [ ] **Audit logging and compliance reporting**
- [ ] **Team permissions within Key Vault context**

## Business Model

- **Personal**: 1 sync partition free (unlimited passwords, unlimited devices)
- **Additional partitions**: $10/month per sync partition (personal or enterprise)
- **Enterprise scaling**: $10/month per sync container, NOT per user

**Partition examples:**
- **Enterprise**: One company partition ($10/month total) OR separate team partitions ($10 each)
- **Personal**: Free partition for personal passwords + $10/month for family partition
- **Prosumer**: Work partition + personal partition = $10/month total

**Revenue model**: $10/partition/month → Scales with actual usage, not headcount

## Competitive Advantages

1. **Zero cloud dependency** (vs 1Password, Bitwarden)
2. **True zero-knowledge** (master password never transmitted)
3. **P2P sync** (no third-party servers)
4. **Open source core** (transparency + community)
5. **Enterprise Azure integration** (Microsoft partnership value)

## Security Principles

- Master password never leaves device
- Only encrypted blobs sync between devices  
- Perfect forward secrecy for sync protocol
- Hardware security module support (future)
- Regular security audits and penetration testing

---

**Next**: Create GitHub repo and initial Rust project structure