# Navis

Cross-platform connection manager for SSH/SFTP/RDP, similar in spirit to MobaXterm. Windows-first, Mac/Linux to follow. Built with Tauri 2 (Rust backend) and React/TypeScript.

## Features

- Hierarchical folder tree of connections, with drag-and-drop reorganization.
- Reusable managed credentials, decoupled from connections (one credential, many connections).
- Encrypted credential vault (AES-256-GCM, Argon2id key derivation).
- TOFU host-key store for SSH and certificate pinning for RDP.
- SSH (interactive shell), SFTP (file transfer), RDP (remote desktop).
- Strict capability sandbox: the renderer cannot touch the filesystem or spawn processes; all sensitive operations go through typed Rust commands.

## Status

Phased delivery — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the project plan. Phase 1 (registry + tree UI) and Phase 2 (vault + credentials) are usable end-to-end. Phase 3+ (SSH/SFTP/RDP engines) ship the protocol code; SFTP and RDP UI are stubs in this revision and land in subsequent phases.

## Development

### Prerequisites

- Rust 1.85+ (stable)
- Node.js 20+
- Tauri 2 system dependencies for your platform — see <https://v2.tauri.app/start/prerequisites/>.

### Get started

```bash
npm install
npm run tauri dev
```

Useful commands:

```bash
npm run lint           # ESLint
npm run typecheck      # TypeScript
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src-tauri/Cargo.toml --all
```

## Security

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREATS.md](docs/THREATS.md). Highlights:

- Master password → Argon2id (64 MiB, t=3) → 256-bit DEK.
- Per-secret AES-256-GCM with random nonce and AAD bound to the secret kind.
- Host-key TOFU store, RDP cert pinning. NLA required by default.
- Tauri capability allowlist excludes filesystem and shell APIs.
- Code signing and signed auto-updates for releases (Phase 7).

## License

MIT OR Apache-2.0
