# AGENTS.md

Navis is a Tauri 2 desktop app (Rust backend + React/TypeScript frontend): a cross-platform SSH/SFTP/RDP connection manager.

## Prerequisites

- Rust 1.85+ (stable), with `rustfmt` and `clippy` for CI-equivalent checks
- Node.js 20+
- Tauri 2 system libraries for the host OS: <https://v2.tauri.app/start/prerequisites/>
- Linux CI packages (Ubuntu): `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libssl-dev`, `pkg-config`, `build-essential`, `libsoup-3.0-dev`, `libjavascriptcoregtk-4.1-dev`

## Setup

```bash
npm ci
```

## Commands

```bash
npm run lint
npm run typecheck
npm run format:check
npm run build
npm run tauri dev

cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --lib
```

## Layout

- `src/` — React/TypeScript renderer
- `src-tauri/` — Rust backend (vault, registry, SSH/SFTP/RDP)
- `.github/workflows/ci.yml` — lint/test on pull requests and `main`
- `.github/workflows/release.yml` — tagged `v*` (and `workflow_dispatch`) Tauri bundles

## Notes

- The renderer is capability-sandboxed: no filesystem or process spawn from the UI. Sensitive work goes through typed Tauri commands.
- Keep shared crates in `[dependencies]`. A `[target.'cfg(...)'.dependencies]` table owns every key that follows it until the next header — putting `russh` under a Linux-only target silently breaks Windows/macOS builds.
- Release builds Intel macOS with `--target x86_64-apple-darwin` on `macos-latest` (Apple Silicon). Do not add `macos-13`; those runners no longer pick up jobs.
