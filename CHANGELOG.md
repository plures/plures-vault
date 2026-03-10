# Plures Vault - Security-First Password Manager

## Changelog

### v0.1.0 (2026-03-10)

**Initial Release - Production CLI**

- ✅ Zero-knowledge encryption with Argon2 + AES-256-GCM
- ✅ Complete CLI interface (init, unlock, add, get, list, update, delete, lock)
- ✅ SQLite backend with encrypted credential storage
- ✅ Session management and secure password verification
- ✅ Comprehensive error handling and user experience
- ✅ Memory safety with ZeroizeOnDrop for sensitive data
- ✅ Production-ready crypto layer with test coverage

**Security Features:**
- Master password never stored or transmitted
- All credentials encrypted before database storage
- Secure salt generation and password verification
- Memory cleanup of sensitive data
- Enterprise-grade cryptographic standards

**Coming Next (Phase 2):**
- GUI interface with design-dojo components
- P2P sync via Hyperswarm
- Multi-device key derivation
- Browser extension integration