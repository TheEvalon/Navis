# Changelog

## v0.1.0 — initial release (foundational)

### Added
- Tauri 2 + React/TypeScript desktop app scaffold (Windows, macOS, Linux).
- Encrypted credential vault: master password → Argon2id → 256-bit DEK → AES-256-GCM per-secret with AAD bound to `vault_ref || kind`.
- Idle auto-lock (`AutoLocker`, default 15 min) with renderer heartbeat.
- OS keychain wrapper (`keyring`) for optional convenience-unlock.
- SQLite-backed registry: folders, connections, credential profiles.
- Effective credential resolution (connection → walk folder ancestry).
- Drag-and-drop connection tree (`react-arborist`) with search.
- JSON export / idempotent import of folder + connection + credential metadata.
- SSH engine (`russh`): password and key auth, PTY-backed shell, xterm.js terminal.
- SFTP engine (`russh-sftp`): list/canonicalize/mkdir/remove/rename + upload/download, file browser UI.
- SSH `known_hosts` TOFU store with strict mismatch failure.
- RDP options + cert-pin store (NLA-required by default; renderer-side editor).
- Vault gate UI: setup, unlock, lock-now, idle-lock indicator.
- Credentials panel and trust-store panel.
- Keyboard shortcut: `Ctrl/Cmd+Shift+L` locks the vault immediately.
- Documentation: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/THREATS.md`.
- CI matrix (Linux): rustfmt, clippy, cargo test, eslint, tsc, prettier, vite build.
- Release workflow with code-signing env hooks for Windows/macOS/Linux.
- 21 unit tests covering vault crypto, AAD binding, AEAD tamper detection, malformed-input safety, registry CRUD, policy inheritance, host-key TOFU, RDP cert pin store, SFTP path safety, export/import round-trip.

### Known limitations / follow-ups
- Full RDP connection / canvas rendering via `ironrdp` is not yet wired. The surface (options, cert pinning, IPC, UI) is in place; integrating the ironrdp client + framebuffer pipeline is its own substantial effort and lands in a dedicated PR.
- ssh-agent / Pageant authentication: surface stubbed (`SshAuth::Agent`); russh 0.46 has no turnkey agent helper, so the wiring is deferred.
- Vault rollback protection (T3 in `docs/THREATS.md`) — needs a monotonic counter in the OS keychain.
- Memory page locking (`mlock`) for DEK pages.
- Telnet, FTP, VNC, Serial, X11-forwarding UI, jump-host chains, port-forward GUI.
- Code-signing keys (Authenticode, Apple Developer ID, GPG for AppImage) need to be provisioned in repo secrets before the first signed release.
