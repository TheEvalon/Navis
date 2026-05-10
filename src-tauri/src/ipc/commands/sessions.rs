//! Session lifecycle commands. These take a `ConnectionId` and dispatch by
//! protocol; the renderer only ever sees a `SessionId`.

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::mpsc;

use crate::core::errors::{AppError, AppResult};
use crate::core::ids::{ConnectionId, SessionId};
use crate::core::policy;
use crate::core::registry::Protocol;
use crate::core::state::AppState;
use crate::protocols::session::{
    SessionEvent, SessionInfo, SessionInput, SessionKind, SessionState,
};

#[derive(Debug, Clone, Serialize)]
pub struct StartedSession {
    pub session_id: SessionId,
}

/// Starts an SSH/SFTP/RDP session for an existing connection.
///
/// The vault must be unlocked if the connection's effective credential is
/// stored in the vault; password-only inline secrets and `agent`-typed
/// credentials don't require unlock.
#[tauri::command]
pub async fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
    connection_id: ConnectionId,
) -> AppResult<StartedSession> {
    let conn = state.registry.get_connection(&connection_id).await?;
    let resolved = policy::resolve_credential(&state.registry, &connection_id).await?;
    let session_id = SessionId::new();

    let (event_tx, mut event_rx) = mpsc::channel::<SessionEvent>(64);
    let app_for_events = app.clone();
    tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            // The renderer subscribes via `listen('navis:session', ...)`.
            if let Err(e) = app_for_events.emit("navis:session", &ev) {
                tracing::error!("emit session event: {e}");
            }
        }
    });

    let handle = match conn.protocol {
        Protocol::Ssh => {
            let auth = build_ssh_auth(&state, resolved).await?;
            let known = std::sync::Arc::new(crate::protocols::hostkeys::SshKnownHosts::new(
                state.paths.known_hosts_path(),
            ));
            let opts: crate::protocols::ssh::SshOptions =
                serde_json::from_value(conn.options.clone()).unwrap_or_default();
            let params = crate::protocols::ssh::SshConnectParams {
                session_id,
                connection_id,
                host: conn.host.clone(),
                port: conn.port,
                user: conn
                    .username
                    .clone()
                    .ok_or_else(|| AppError::InvalidInput("connection has no username".into()))?,
                options: opts,
            };
            crate::protocols::ssh::connect(params, auth, known, event_tx.clone()).await?
        }
        Protocol::Sftp => {
            // SFTP shares the SSH stack but doesn't open a PTY. We register a
            // session shell first; the file-browser commands then operate on it.
            return Err(AppError::Protocol(
                "SFTP session bring-up is implemented in Phase 4".into(),
            ));
        }
        Protocol::Rdp => {
            // The full RDP renderer is wired up in Phase 5. We return a
            // structured error so the UI can show "coming soon" messaging
            // without crashing.
            return Err(AppError::Protocol(
                "RDP session bring-up is implemented in Phase 5".into(),
            ));
        }
    };

    let info = SessionInfo {
        id: session_id,
        connection_id,
        kind: SessionKind::from(conn.protocol.clone()),
        state: SessionState::Connected,
    };
    let _ = info; // for clarity
    state.sessions.write().insert(session_id, handle);
    Ok(StartedSession { session_id })
}

async fn build_ssh_auth(
    state: &AppState,
    cred: Option<crate::core::ids::CredentialId>,
) -> AppResult<crate::protocols::ssh::SshAuth> {
    let Some(cred_id) = cred else {
        return Err(AppError::InvalidInput(
            "no credential resolved for this connection".into(),
        ));
    };
    let profile = state.registry.get_credential(&cred_id).await?;
    match profile.kind {
        crate::core::vault::SecretKind::Password => {
            let bytes = state.vault.get(&profile.vault_ref)?;
            Ok(crate::protocols::ssh::SshAuth::Password(
                zeroize::Zeroizing::new(bytes.as_slice().to_vec()),
            ))
        }
        crate::core::vault::SecretKind::SshPrivateKey => {
            let pem = state.vault.get(&profile.vault_ref)?;
            Ok(crate::protocols::ssh::SshAuth::PrivateKey {
                pem: zeroize::Zeroizing::new(pem.as_slice().to_vec()),
                passphrase: None,
            })
        }
        other => Err(AppError::InvalidInput(format!(
            "credential kind {other:?} not usable for SSH"
        ))),
    }
}

#[tauri::command]
pub async fn send_input(
    state: State<'_, AppState>,
    session_id: SessionId,
    data: Vec<u8>,
) -> AppResult<()> {
    let tx = {
        let map = state.sessions.read();
        map.get(&session_id)
            .and_then(|h| h.input_tx.clone())
            .ok_or_else(|| AppError::NotFound(format!("session {session_id}")))?
    };
    tx.send(SessionInput::Stdin(data))
        .await
        .map_err(|e| AppError::Session(format!("send input: {e}")))
}

#[tauri::command]
pub async fn resize_session(
    state: State<'_, AppState>,
    session_id: SessionId,
    cols: u16,
    rows: u16,
) -> AppResult<()> {
    let tx = {
        let map = state.sessions.read();
        map.get(&session_id)
            .and_then(|h| h.input_tx.clone())
            .ok_or_else(|| AppError::NotFound(format!("session {session_id}")))?
    };
    tx.send(SessionInput::Resize { cols, rows })
        .await
        .map_err(|e| AppError::Session(format!("resize: {e}")))
}

#[tauri::command]
pub async fn close_session(state: State<'_, AppState>, session_id: SessionId) -> AppResult<()> {
    let tx = {
        let mut map = state.sessions.write();
        map.remove(&session_id)
            .and_then(|h| h.input_tx.clone())
            .ok_or_else(|| AppError::NotFound(format!("session {session_id}")))?
    };
    let _ = tx.send(SessionInput::Close).await;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionListItem {
    pub id: SessionId,
    pub connection_id: ConnectionId,
    pub kind: SessionKind,
    pub state: SessionState,
}

#[tauri::command]
pub fn list_sessions(state: State<'_, AppState>) -> Vec<SessionListItem> {
    state
        .sessions
        .read()
        .values()
        .map(|h| SessionListItem {
            id: h.info.id,
            connection_id: h.info.connection_id,
            kind: h.info.kind,
            state: h.current_state(),
        })
        .collect()
}
