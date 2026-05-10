# Changelog

## v0.1.1 — RDP launcher

### Added
- **RDP via the OS-native client** as the v0.1.x default. Connect on an RDP connection now decrypts the bound credential, prefills the system credential store, and spawns the platform's native RDP client:
  - Windows: `cmdkey /generic:TERMSRV/<host> /user:<user> /pass:<pwd>` then `mstsc /v:<host>:<port>`. The `cmdkey` entry is removed automatically ~20 s after launch.
  - Linux: `xfreerdp` (or `xfreerdp3`) with `/v`, `/u`, `/d`, `/size`, `/bpp`, `/cert:tofu`, `+clipboard`.
  - macOS: writes a transient `.rdp` file in `$TMPDIR` and `open`s it (Microsoft Remote Desktop). Username is prefilled; password prompt remains.
- `start_session` now returns a tagged `StartedSession`: `{ kind: "in_app", session_id }` for SSH/SFTP, `{ kind: "external", client, credentials_prefilled }` for RDP. The renderer shows "Launched in <client>" instead of treating RDP as an in-app session.
- Pull request feedback for `Connect` button: success info banner for external launches, error banner for failures.

### Security notes
- The Windows path passes the password to `cmdkey` via the command line, where it is briefly visible in process listings. The Linux path passes the password to `xfreerdp` via `/p:`, same caveat. The temporary `cmdkey` entry is deleted within 20 s. The embedded `ironrdp` client (deferred to v0.2) uses an in-memory credential path that avoids both.
- macOS does not prefill the password; users authenticate inside Microsoft Remote Desktop on first connect.

### Internal
- `protocols::rdp::launch_external` + `ExternalLaunch` / `ExternalLaunched` types form the new public surface.
- New build dep `which` (Linux-only target dep).

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
