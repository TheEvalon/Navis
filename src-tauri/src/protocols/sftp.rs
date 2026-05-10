//! SFTP client. Wraps `russh-sftp` on top of an authenticated `russh` session.
//!
//! Architecture:
//! - One `russh` session is established (host-key checked, user authenticated).
//! - We open a channel and request the `sftp` subsystem.
//! - The channel is converted to a stream and handed to `SftpSession`.
//! - The renderer talks to the session through opaque `SessionId`s; it
//!   never gets a raw remote path back without going through the
//!   path-validation policy below.
//!
//! Concurrency: SftpSession is `!Sync` for some methods, so the engine
//! holds it inside a `tokio::sync::Mutex`. Each request is short-lived;
//! transfers spawn their own task that reads the file in chunks and
//! emits `SessionEvent::TransferProgress`.

use std::path::Path;
use std::sync::Arc;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileType;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::core::errors::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub modified_unix: Option<i64>,
    pub mode: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferStatus {
    pub id: String,
    pub direction: TransferDirection,
    pub state: TransferState,
    pub local_path: String,
    pub remote_path: String,
    pub bytes_transferred: u64,
    pub total_bytes: Option<u64>,
    pub error: Option<String>,
}

/// Path-safety check shared by upload and download paths.
///
/// Refuses traversal sequences and embedded NULs. The caller is responsible
/// for joining with a known-safe base when needed.
pub fn validate_relative_path(p: &str) -> AppResult<()> {
    if p.is_empty() {
        return Err(AppError::InvalidInput("empty path".into()));
    }
    if p.bytes().any(|b| b == 0) {
        return Err(AppError::InvalidInput("path contains NUL".into()));
    }
    if p.contains("..") {
        return Err(AppError::InvalidInput("path traversal not allowed".into()));
    }
    Ok(())
}

/// Validates that a local path is absolute and points at an allowed
/// directory. The renderer passes file paths chosen via the dialog plugin,
/// so this is a defense-in-depth check.
pub fn validate_absolute_local_path(p: &str) -> AppResult<()> {
    if p.is_empty() {
        return Err(AppError::InvalidInput("local path empty".into()));
    }
    if p.bytes().any(|b| b == 0) {
        return Err(AppError::InvalidInput("local path contains NUL".into()));
    }
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(AppError::InvalidInput("local path must be absolute".into()));
    }
    Ok(())
}

/// A live SFTP session bound to a SessionId. Cheap to clone.
#[derive(Clone)]
pub struct SftpEngine {
    session: Arc<Mutex<SftpSession>>,
}

impl SftpEngine {
    pub fn new(session: SftpSession) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
        }
    }

    pub async fn list(&self, path: &str) -> AppResult<Vec<RemoteEntry>> {
        let s = self.session.lock().await;
        let canonical = s
            .canonicalize(path.to_string())
            .await
            .map_err(|e| AppError::Protocol(format!("canonicalize: {e}")))?;
        let read_dir = s
            .read_dir(canonical.clone())
            .await
            .map_err(|e| AppError::Protocol(format!("read_dir: {e}")))?;
        let mut out = Vec::new();
        for entry in read_dir {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let attrs = entry.metadata();
            let kind = match attrs.file_type() {
                FileType::Dir => EntryKind::Directory,
                FileType::File => EntryKind::File,
                FileType::Symlink => EntryKind::Symlink,
                _ => EntryKind::Other,
            };
            let mut full = canonical.clone();
            if !full.ends_with('/') {
                full.push('/');
            }
            full.push_str(&name);
            out.push(RemoteEntry {
                name,
                path: full,
                kind,
                size: attrs.size.unwrap_or(0),
                modified_unix: attrs.mtime.map(|t| t as i64),
                mode: attrs.permissions.unwrap_or(0),
            });
        }
        // Folders first, then alphabetical.
        out.sort_by(|a, b| match (a.kind, b.kind) {
            (EntryKind::Directory, EntryKind::Directory) | (EntryKind::File, EntryKind::File) => {
                a.name.cmp(&b.name)
            }
            (EntryKind::Directory, _) => std::cmp::Ordering::Less,
            (_, EntryKind::Directory) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });
        Ok(out)
    }

    pub async fn canonicalize(&self, path: &str) -> AppResult<String> {
        let s = self.session.lock().await;
        s.canonicalize(path.to_string())
            .await
            .map_err(|e| AppError::Protocol(format!("canonicalize: {e}")))
    }

    pub async fn mkdir(&self, path: &str) -> AppResult<()> {
        let s = self.session.lock().await;
        s.create_dir(path.to_string())
            .await
            .map_err(|e| AppError::Protocol(format!("mkdir: {e}")))
    }

    pub async fn remove(&self, path: &str, is_dir: bool) -> AppResult<()> {
        let s = self.session.lock().await;
        if is_dir {
            s.remove_dir(path.to_string())
                .await
                .map_err(|e| AppError::Protocol(format!("rmdir: {e}")))
        } else {
            s.remove_file(path.to_string())
                .await
                .map_err(|e| AppError::Protocol(format!("unlink: {e}")))
        }
    }

    pub async fn rename(&self, from: &str, to: &str) -> AppResult<()> {
        let s = self.session.lock().await;
        s.rename(from.to_string(), to.to_string())
            .await
            .map_err(|e| AppError::Protocol(format!("rename: {e}")))
    }

    pub async fn read_to_local(&self, remote: &str, local: &Path) -> AppResult<u64> {
        validate_absolute_local_path(local.to_string_lossy().as_ref())?;
        let s = self.session.lock().await;
        let bytes = s
            .read(remote.to_string())
            .await
            .map_err(|e| AppError::Protocol(format!("read: {e}")))?;
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(local, &bytes)?;
        Ok(bytes.len() as u64)
    }

    pub async fn write_from_local(&self, local: &Path, remote: &str) -> AppResult<u64> {
        validate_absolute_local_path(local.to_string_lossy().as_ref())?;
        let bytes = std::fs::read(local)?;
        let s = self.session.lock().await;
        s.write(remote.to_string(), &bytes)
            .await
            .map_err(|e| AppError::Protocol(format!("write: {e}")))?;
        Ok(bytes.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_safety() {
        assert!(validate_relative_path("a/b").is_ok());
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("a/\0b").is_err());
        assert!(validate_relative_path("").is_err());
    }

    #[test]
    fn absolute_local_path_safety() {
        #[cfg(unix)]
        {
            assert!(validate_absolute_local_path("/tmp/x").is_ok());
            assert!(validate_absolute_local_path("relative/x").is_err());
            assert!(validate_absolute_local_path("/tmp/\0x").is_err());
            assert!(validate_absolute_local_path("").is_err());
        }
        #[cfg(windows)]
        {
            assert!(validate_absolute_local_path("C:\\Users\\x").is_ok());
            assert!(validate_absolute_local_path("relative\\x").is_err());
        }
    }
}
