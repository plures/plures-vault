# Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in Plures Vault, please report it responsibly:

**Contact:** security@plures.ai

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if you have one)

**Response time:** We aim to respond within 24 hours for critical vulnerabilities.

## Security Features

### Encryption
- **AES-256-GCM** for symmetric encryption
- **Argon2** for password derivation
- **Cryptographically secure random number generation**
- **Perfect forward secrecy** for P2P sync (Phase 2)

### Key Management
- Master passwords never stored or transmitted
- Keys derived fresh for each session
- Automatic memory cleanup of sensitive data
- Protection against timing attacks

### Database Security
- All credentials encrypted before storage
- Salt-based password verification
- No plaintext secrets in database
- Protection against database extraction attacks

### P2P Security (Phase 2)
- End-to-end encryption for sync
- Device authentication
- No central servers or third parties
- Hyperswarm DHT for peer discovery

## Security Audits

We welcome security audits and will coordinate responsible disclosure of any findings.

## Bug Bounty

Coming soon - we plan to offer rewards for security vulnerability reports once we reach Phase 2.

---

**Security is our top priority. Thank you for helping keep Plures Vault secure.**