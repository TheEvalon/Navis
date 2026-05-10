//! Common session abstractions.
//!
//! A `SessionHandle` is a renderer-facing handle to a live SSH, SFTP, or RDP
//! session. The renderer never sees the underlying transport; it only talks
//! to commands keyed by `SessionId`.

use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::core::ids::{ConnectionId, SessionId};
use crate::core::registry::Protocol;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Ssh,
    Sftp,
    Rdp,
}

impl From<Protocol> for SessionKind {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Ssh => SessionKind::Ssh,
            Protocol::Sftp => SessionKind::Sftp,
            Protocol::Rdp => SessionKind::Rdp,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Connecting,
    Connected,
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub connection_id: ConnectionId,
    pub kind: SessionKind,
    pub state: SessionState,
}

/// Outbound payloads emitted to the renderer.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// Terminal output (SSH).
    Output {
        session_id: SessionId,
        data: Vec<u8>,
    },
    /// Connection state changed.
    State {
        session_id: SessionId,
        state: SessionState,
        message: Option<String>,
    },
    /// SFTP transfer progress update.
    TransferProgress {
        session_id: SessionId,
        transfer_id: String,
        bytes: u64,
        total: Option<u64>,
    },
}

/// Inbound commands from the renderer to a session (typed per protocol so
/// we don't need a giant tagged enum on the wire — the IPC layer dispatches
/// by command name).
pub enum SessionInput {
    Stdin(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

/// The handle stored in `AppState::sessions` for live sessions. Cloning is
/// cheap; everything sits behind `Arc`.
#[derive(Clone)]
pub struct SessionHandle {
    pub info: SessionInfo,
    pub input_tx: Option<mpsc::Sender<SessionInput>>,
    pub sftp: Option<crate::protocols::sftp::SftpEngine>,
    pub state: Arc<Mutex<SessionState>>,
}

impl SessionHandle {
    pub fn new_shell(info: SessionInfo, input_tx: mpsc::Sender<SessionInput>) -> Self {
        let initial = info.state;
        Self {
            info,
            input_tx: Some(input_tx),
            sftp: None,
            state: Arc::new(Mutex::new(initial)),
        }
    }

    pub fn new_sftp(info: SessionInfo, sftp: crate::protocols::sftp::SftpEngine) -> Self {
        let initial = info.state;
        Self {
            info,
            input_tx: None,
            sftp: Some(sftp),
            state: Arc::new(Mutex::new(initial)),
        }
    }

    pub fn current_state(&self) -> SessionState {
        *self.state.lock()
    }

    pub fn set_state(&self, new_state: SessionState) {
        *self.state.lock() = new_state;
    }
}
