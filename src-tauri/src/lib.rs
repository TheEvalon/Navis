//! Navis — cross-platform connection manager.
//!
//! Module layout mirrors the architecture document:
//!
//! - `core::registry` — non-secret SQLite-backed metadata (folders, connections, credential refs).
//! - `core::vault`    — encrypted secret store (AES-256-GCM, Argon2id KDF).
//! - `core::keychain` — OS keychain wrapper for the master-key wrap.
//! - `core::policy`   — credential resolution + per-connection policy decisions.
//! - `protocols::{ssh, sftp, rdp}` — protocol engines.
//! - `ipc`            — Tauri command surface and event types.

pub mod core;
pub mod ipc;
pub mod protocols;

use std::sync::Arc;

use tauri::Manager;
use tracing::info;

use crate::core::{
    keychain::SystemKeychain, paths::AppPaths, registry::Registry, state::AppState, vault::Vault,
};

/// Entry point for the Tauri application.
pub fn run() {
    init_tracing();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let paths = AppPaths::for_app(app.handle())?;
            paths.ensure_dirs()?;

            let runtime = tauri::async_runtime::handle();
            let registry =
                runtime.block_on(async { Registry::open(&paths.database_path()).await })?;

            let vault = Vault::new(paths.vault_path());
            let keychain = SystemKeychain::new("com.navis.app", "default-vault");

            let state = AppState {
                registry: Arc::new(registry),
                vault: Arc::new(vault),
                keychain: Arc::new(keychain),
                paths: Arc::new(paths),
                sessions: Default::default(),
            };
            app.manage(state);
            info!("Navis backend initialized");
            Ok(())
        })
        .invoke_handler(ipc::handler())
        .run(tauri::generate_context!())
        .expect("error while running Navis application");
}

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,navis_lib=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .init();
}
