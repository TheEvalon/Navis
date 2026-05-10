//! Resolves filesystem paths for the user data directory, vault, and database.

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

use crate::core::errors::{AppError, AppResult};

/// Filesystem layout under `app_data_dir`:
///
/// ```text
/// <app_data_dir>/
///   navis.db          # SQLite metadata
///   vault.bin         # encrypted vault blob
///   keys/             # known_hosts, RDP cert pins
///     known_hosts
///     rdp_pins.json
///   logs/             # rotating logs
/// ```
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    pub fn for_app(app: &AppHandle) -> AppResult<Self> {
        let root = app
            .path()
            .app_data_dir()
            .map_err(|e| AppError::Internal(format!("resolve data dir: {e}")))?;
        Ok(Self { root })
    }

    pub fn from_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn ensure_dirs(&self) -> AppResult<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.keys_dir())?;
        std::fs::create_dir_all(self.logs_dir())?;
        Ok(())
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    pub fn database_path(&self) -> PathBuf {
        self.root.join("navis.db")
    }

    pub fn vault_path(&self) -> PathBuf {
        self.root.join("vault.bin")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.keys_dir().join("known_hosts")
    }

    pub fn rdp_pins_path(&self) -> PathBuf {
        self.keys_dir().join("rdp_pins.json")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
}
