## [0.2.0] — 2026-07-24

- Merge pull request #23 from plures/release-trigger-autobump (3a17e5d)
- Potential fix for pull request finding (6b766b8)
- ci(release): trigger release pipeline on merge to master (d6ed7e7)
- ci: migrate Tech Doc Writer to shared reusable (32b57cf)
- fix(ci): repair tech-doc-writer YAML indentation / remove empty workflow (e96473d)
- ci: add security-aware Dependabot auto-merge workflow (org backfill) (656df29)
- ci: change release trigger from push-to-main to tag-only (5327c3e)
- license: dual-license under BSL-1.1 OR MIT (e5d9ae8)
- refactor: replace inline lifecycle with reusable workflow call (3bcde3e)
- docs: refresh ROADMAP.md with OASIS strategic alignment (07a39e6)
- docs: update copilot-instructions with praxis, design-dojo, automation rules (bc1481c)
- feat(release): add target_version input for milestone-driven releases (c1ac8ea)
- feat(lifecycle): milestone-close triggers roadmap-aware release (679c817)
- feat(praxis): add contracts to all rules and constraints across modules (#18) (48cb266)
- feat(lifecycle v12): auto-release when milestone completes (a202018)
- feat(lifecycle v11): smart CI failure handling — infra vs code (f7f9148)
- fix(lifecycle): label-based retry counter + CI fix priority (cf52b31)
- ci: inline lifecycle workflow — fix schedule failures (5c86a0e)
- ci: centralize lifecycle — event-driven with schedule guard (267d853)
- fix(lifecycle): v9.2 — process all PRs per tick (return→continue), widen bot filter (79705ec)
- fix(lifecycle): change return→continue so all PRs process in one tick (2b1cbfb)
- fix(lifecycle): v9.1 — fix QA dispatch (client_payload as JSON object) (60acfa7)
- fix(lifecycle): rewrite v9 — apply suggestions, merge, no nudges (2b7f216)
- feat: adopt @plures/praxis for declarative logic management (#17) (91c0ddf)
- chore: license BSL 1.1 (commercial product) (6d1f846)
- chore: standardize copilot-pr-lifecycle.yml to canonical version (9fa5ce2)
- fix: add packages:write + id-token:write to release workflow (5c3f9c2)
- docs: add ROADMAP.md (6079590)
- Merge pull request #16 from plures/chore/org-standards (adba68a)
- Update .github/workflows/copilot-pr-lifecycle.yml (14c9392)
- Update .github/workflows/tech-doc-writer.yml (12814b3)
- Update .github/workflows/tech-doc-writer.yml (1c425bc)
- Update .github/workflows/tech-doc-writer.yml (27541d0)
- Update .github/workflows/copilot-pr-lifecycle.yml (9ef72cb)
- Update .github/workflows/copilot-pr-lifecycle.yml (70e5331)
- chore: add Reusable release pipeline (1c5b219)
- chore: add Auto-create doc issues on PR merge (476ad4a)
- chore: add Copilot PR auto-merge lifecycle (6aa0c3c)
- chore: add Copilot coding instructions (0af80a9)
- Merge pull request #14 from plures/copilot/strategic-complete-paradigm-proof (d4e4783)
- fix: use credential titles instead of UUIDs for graph node labels (5d937e4)
- feat: wire vault-graph and vault-mcp into CLI, update README with paradigm convergence docs (0241fb9)
- feat: add vault-mcp crate with MCP server for AI-native vault interactions (0ea871c)
- feat: add vault-graph crate for secret relationship management (e5ba5e2)
- Add PluresDB stub crates for in-repo compilation (f739e84)
- Initial plan (9a633ec)
- fix: update CLI sync commands for new vault-sync API (7f623a3)
- feat: add Windows Hello biometric unlock (1aa53fe)
- feat: add Chrome/Edge browser extension (Manifest V3) (dedd87b)
- feat: add Azure Key Vault sync + rewrite P2P sync on PluresDB CRDTs (4fef877)
- feat: replace SQLite/SQLx with PluresDB as sole storage backend (d3cf072)
- Merge pull request #5 from plures/copilot/implement-pluresdb-schema-encrypted-credentials (04a4875)
- fix: address PR review comments (schema constraints, error types, unwrap, migration transaction) (69f3922)
- Update crates/vault-core/migrations/0001_initial_schema.sql (94da662)
- feat: implement PluresDB schema for encrypted credentials (47c8472)
- chore: initial implementation plan (d7a92d7)
- Initial plan (c072e3d)
- feat(tray): implement system tray with lock, show/hide, autostart (a6054c0)
- fix(gui): correct password parameter type for add_credential API (2129ed8)
- fix(gui): add working icon files to resolve Windows build error (b0ceeb9)
- fix(gui): temporarily disable corrupted icons to fix Windows build (5c3451d)
- fix(gui): complete API migration, fix unlock method, password wrapping, and state management (e6cd730)
- fix(gui): refactor to create VaultManager per operation, fix API method names and mutex Send issues (90b37b5)
- fix(gui): add favicon.png and complete tauri v2 API fixes (2808ff9)
- fix(gui): update VaultManager initialization and fix mutex/Send issues (aa0a6e2)
- fix(gui): partial API fixes for tauri v2 - method names and parameters (1e5051f)
- fix(gui): add AppHandle parameter to all tauri commands for v2 compatibility (062f6b7)
- fix(gui): complete tauri v2 migration with proper api usage (e801ad0)
- fix(gui): revert to tauri v1 for compatibility (0a0b767)
- fix(gui): correct tauri v2 api usage and features (72f9095)
- fix(gui): add missing icons and complete tauri v2 migration (3bf0703)
- fix(gui): upgrade rust dependencies to tauri v2 and clean up lib (fa4bbb5)
- fix(gui): update tauri configuration for v2 schema (cc27bd8)
- fix(gui): update tauri api import to v2 core and disable SSR (c313106)
- feat: Phase 3 P2P sync implementation complete - TCP networking with peer discovery (370c27c)
- feat: Phase 2 GUI integration complete - Tauri + Svelte production ready (ecf04ec)
- feat: Phase 1 COMPLETE - Production crypto + CLI ready (c118687)
- feat: Phase 2 GUI foundation with Tauri + Svelte (cacae41)
- feat: Praxis integration architecture for auditability (211f99b)
- feat: Azure Key Vault frontend architecture (f987ad4)
- feat: Partition-based pricing model (a0a8b9a)
- feat: Production-ready Plures Vault v0.1.0 (6278451)

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