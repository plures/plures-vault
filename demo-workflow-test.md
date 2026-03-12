# Plures Vault GUI Demo Workflow Test

## Test Environment
- **Platform:** Windows 11 via WSL interop
- **GUI Status:** Running (Tauri window active)
- **Backend:** vault-core + vault-crypto working
- **Frontend:** SvelteKit at localhost:5173

## Core Workflow Tests

### 1. Vault Creation
- [ ] Create new vault with name "Demo Vault"
- [ ] Set master password "TestPassword123!"
- [ ] Verify vault initialization success

### 2. Vault Operations
- [ ] Lock vault
- [ ] Unlock vault with correct password
- [ ] Verify invalid password rejection

### 3. Credential Management
- [ ] Add credential: GitHub account
  - Name: "GitHub Personal"
  - Username: "testuser"
  - Password: "gh_token_123"
  - URL: "https://github.com"
  - Notes: "Personal development account"
- [ ] View credential details
- [ ] Update credential password
- [ ] Delete credential

### 4. Security Features
- [ ] Auto-lock after timeout (if implemented)
- [ ] Password masking in UI
- [ ] Secure clipboard copy (if implemented)

### 5. Edge Cases
- [ ] Empty fields handling
- [ ] Special characters in passwords
- [ ] Long credential names/notes
- [ ] Invalid master password attempts

## Expected Results
All operations should complete successfully with proper error handling and user feedback.

## Microsoft Demo Preparation
This workflow will form the basis of the Microsoft partnership demo showcasing:
- Enterprise security (Argon2id + AES-256-GCM)
- Zero-trust architecture
- Cross-platform GUI (Tauri)
- Modern UX (SvelteKit)

## Automated Verification (2026-03-11)
- **GUI Process:** Active (`warm-kelp`)
- **Frontend:** Accessible (HTTP 200 at localhost:5173)
- **Backend CLI:** Compiled and responsive (`plures-vault.exe --help` passed)
- **Status:** Ready for manual UI walkthrough.
