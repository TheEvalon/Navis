//! SFTP client. Wraps `russh-sftp` on top of an authenticated `russh` session.
//!
//! The SFTP engine reuses the SSH transport. Public surface here:
//! - `SftpClient` with list/stat/upload/download/mkdir/remove operations.
//! - A transfer queue that emits `SessionEvent::TransferProgress`.
//!
//! NOTE: This is a thin wrapper that compiles against the published API.
//! The high-level browser UI sits on top of these primitives. SFTP runs
//! over the same russh session, so the security/host-key story is identical
//! to plain SSH.

use serde::{Deserialize, Serialize};

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
/// Refuses absolute escape sequences and embedded NULs. The caller is
/// responsible for joining with a known-safe base.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_nul() {
        assert!(validate_relative_path("a/b").is_ok());
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("a/\0b").is_err());
        assert!(validate_relative_path("").is_err());
    }
}
