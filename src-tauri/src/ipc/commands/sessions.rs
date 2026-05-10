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
use crate::protocols::rdp::ExternalLaunched;
use crate::protocols::session::{
    SessionEvent, SessionInfo, SessionInput, SessionKind, SessionState,
};

/// Result of `start_session`. SSH/SFTP go through the in-app path and
/// return a `SessionId` the renderer can attach to. RDP currently spawns
/// the OS-native client and returns its identity instead, so the renderer
/// shows "launched in <client>" rather than trying to render frames.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartedSession {
    InApp { session_id: SessionId },
    External(ExternalLaunched),
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
        Protocol::Ssh | Protocol::Sftp => {
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
            if matches!(conn.protocol, Protocol::Ssh) {
                crate::protocols::ssh::connect(params, auth, known, event_tx.clone()).await?
            } else {
                crate::protocols::ssh::connect_sftp(params, auth, known, event_tx.clone()).await?
            }
        }
        Protocol::Rdp => {
            let opts: crate::protocols::rdp::RdpOptions =
                serde_json::from_value(conn.options.clone()).unwrap_or_default();
            let user = conn
                .username
                .clone()
                .ok_or_else(|| AppError::InvalidInput("RDP connection has no username".into()))?;
            let password = build_rdp_password(&state, resolved).await?;
            let launched =
                crate::protocols::rdp::launch_external(crate::protocols::rdp::ExternalLaunch {
                    host: &conn.host,
                    port: conn.port,
                    user: &user,
                    domain: opts.domain.as_deref(),
                    password,
                    options: &opts,
                })?;
            return Ok(StartedSession::External(launched));
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
    Ok(StartedSession::InApp { session_id })
}

async fn build_rdp_password(
    state: &AppState,
    cred: Option<crate::core::ids::CredentialId>,
) -> AppResult<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let Some(cred_id) = cred else {
        // No credential bound; the external client will prompt.
        return Ok(None);
    };
    let profile = state.registry.get_credential(&cred_id).await?;
    match profile.kind {
        crate::core::vault::SecretKind::RdpPassword | crate::core::vault::SecretKind::Password => {
            let bytes = state.vault.get(&profile.vault_ref)?;
            Ok(Some(zeroize::Zeroizing::new(bytes.as_slice().to_vec())))
        }
        other => Err(AppError::InvalidInput(format!(
            "credential kind {other:?} not usable for RDP"
        ))),
    }
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
