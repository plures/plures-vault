# 🔐 Plures Vault: Microsoft Partnership Demo Script

**Target Audience:** Microsoft Security & Identity Team  
**Goal:** Demonstrate enterprise-grade zero-trust architecture and cross-platform capability.  
**Duration:** 15 minutes

---

## 1. Introduction (2 mins)
* "Plures Vault is a zero-trust, commercial-grade password manager built in Rust."
* "Unlike consumer tools, it is designed for enterprise compliance from day one."
* **Key Differentiators:**
  * **Memory Safety:** 100% Rust implementation (no C/C++ memory bugs).
  * **Zero-Trust:** Master password never leaves the device; never stored on disk.
  * **Crypto-Agility:** Argon2id (hashing) + AES-256-GCM (encryption).
  * **Cross-Platform:** Single codebase for Windows (Tauri) and Linux.

---

## 2. Live Demo: The "Cold Start" (5 mins)
* **Action:** Launch `plures-vault-gui.exe` (fresh install).
* **Narrative:** "Watch how fast the cold start is—under 200ms. No Electron bloat."
* **Step 1: Vault Creation**
  * Click "New Vault".
  * Enter Name: `Enterprise Demo`.
  * Enter Master Password: `ComplexPassword123!`.
  * **Highlight:** "At this moment, Argon2id is deriving the key. The password itself is already zeroized from memory."
* **Step 2: Credential Storage**
  * Click "Add Credential".
  * **Input:**
    * Name: `Azure Admin Portal`
    * Username: `admin@contoso.com`
    * Password: `s3cr3t_cl0ud_k3y`
    * URL: `portal.azure.com`
  * Click "Save".
  * **Highlight:** "The data was just encrypted with AES-256-GCM before hitting the SQLite backend. The raw password existed in RAM for microseconds."

---

## 3. Technical Deep Dive (5 mins)
* **Action:** Open the "Developer Tools" or show the source code snippet.
* **Narrative:** "Let's look at the security architecture."
* **Point 1: Type-Safe Secrets**
  * Show `Secret<String>` usage in Rust.
  * Explain: "We use the `secrecy` crate. If a developer accidentally tries to print a log of the password, the compiler blocks it. It *cannot* be leaked by accident."
* **Point 2: The Tauri Bridge**
  * Explain: "The frontend is SvelteKit, but the logic is Rust. The frontend holds *no* crypto keys. It just asks the backend to 'decrypt this ID', and the backend returns the result. The key never touches the WebView."

---

## 4. Closing & Roadmap (3 mins)
* **Current Status:** Phase 1 Complete (Local Vault + GUI).
* **Phase 2 (In Progress):** P2P Sync (Hyperswarm) - No central cloud server to hack.
* **The Ask:** "We want to integrate with Windows Hello for authentication and explore bundling with Microsoft Enterprise tiers."

---

## 5. Q&A Prep
* **Q:** "How do you handle recovery?"
  * **A:** "We don't. That's a feature. No backdoor means no backdoor. We recommend key splitting (Phase 3)."
* **Q:** "Why Tauri instead of native WinUI 3?"
  * **A:** "Auditability. The UI is just HTML/JS, easy to audit. The crypto is pure Rust, easy to verify. WinUI 3 is great, but Tauri gives us Linux/macOS parity instantly."
