//! SSH client engine on top of `russh`.
//!
//! Responsibilities:
//! - Resolve credentials via the policy module.
//! - Verify the server host key against `SshKnownHosts` (TOFU on unknown).
//! - Authenticate with password / private key / agent.
//! - Open a single PTY-backed channel and bridge stdin/stdout to the
//!   renderer via `mpsc` channels.
//!
//! The renderer never sees credentials. They are read from the vault, kept
//! in `Zeroizing` buffers, and dropped as soon as authentication succeeds.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex as PlMutex;
use russh::client::{self, Handle, Handler};
use russh::keys::key::PublicKey;
use russh::keys::PublicKeyBase64;
use russh::{ChannelMsg, Disconnect};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::core::errors::{AppError, AppResult};
use crate::core::ids::{ConnectionId, SessionId};
use crate::core::vault::SecretKind;
use crate::protocols::hostkeys::{SshKnownHosts, TrustOutcome};
use crate::protocols::session::{
    SessionEvent, SessionHandle, SessionInfo, SessionInput, SessionKind, SessionState,
};

/// SSH-specific options stored in `Connection.options`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SshOptions {
    /// Override TERM (default `xterm-256color`).
    #[serde(default)]
    pub term: Option<String>,
    /// Initial PTY size.
    #[serde(default)]
    pub cols: Option<u16>,
    #[serde(default)]
    pub rows: Option<u16>,
}

/// What the renderer must provide for a TOFU acceptance flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    Accept,
    Reject,
}

/// Authentication input (decrypted by the caller from the vault).
pub enum SshAuth {
    Password(Zeroizing<Vec<u8>>),
    PrivateKey {
        pem: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    },
    /// Use the running ssh-agent (via `SSH_AUTH_SOCK` / Pageant pipe).
    Agent,
}

#[derive(Debug, Clone)]
pub struct SshConnectParams {
    pub session_id: SessionId,
    pub connection_id: ConnectionId,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub options: SshOptions,
}

/// Pair of `(algorithm, key_blob)` captured during the host-key check.
type SeenHostKey = (String, Vec<u8>);

/// Result of a host key check from the handler back to the connect flow.
#[derive(Clone, Default)]
struct HostKeyChannel {
    seen: Arc<PlMutex<Option<SeenHostKey>>>,
}

struct ClientHandler {
    host: String,
    port: u16,
    known: Arc<SshKnownHosts>,
    seen: HostKeyChannel,
}

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let algo = server_public_key.name().to_string();
        let key_blob = server_public_key.public_key_bytes();
        let outcome = self
            .known
            .check(&self.host, self.port, &algo, &key_blob)
            .map_err(|e| russh::Error::IO(std::io::Error::other(e.to_string())))?;
        // Stash for the connect flow to consult on TOFU/mismatch.
        *self.seen.seen.lock() = Some((algo.clone(), key_blob.clone()));
        match outcome {
            TrustOutcome::Trusted => Ok(true),
            TrustOutcome::Unknown => {
                // Connect flow will surface a UI prompt and call accept().
                // Here we reject by default; the caller retries after accept.
                warn!("unknown host key for {}:{}", self.host, self.port);
                Ok(false)
            }
            TrustOutcome::Mismatch => {
                error!("host key MISMATCH for {}:{}", self.host, self.port);
                Ok(false)
            }
        }
    }
}

/// Establishes an SSH session, opens an interactive PTY shell, and starts
/// the bidirectional bridge. Returns a `SessionHandle` ready to be inserted
/// into `AppState::sessions`. Outbound terminal data is delivered as
/// `SessionEvent::Output` on `event_tx`.
pub async fn connect(
    params: SshConnectParams,
    auth: SshAuth,
    known_hosts: Arc<SshKnownHosts>,
    event_tx: mpsc::Sender<SessionEvent>,
) -> AppResult<SessionHandle> {
    let info = SessionInfo {
        id: params.session_id,
        connection_id: params.connection_id,
        kind: SessionKind::Ssh,
        state: SessionState::Connecting,
    };
    let _ = event_tx
        .send(SessionEvent::State {
            session_id: info.id,
            state: SessionState::Connecting,
            message: None,
        })
        .await;

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    });

    let seen = HostKeyChannel::default();
    let handler = ClientHandler {
        host: params.host.clone(),
        port: params.port,
        known: known_hosts.clone(),
        seen: seen.clone(),
    };

    let addr = (params.host.as_str(), params.port);
    let mut session = client::connect(config.clone(), addr, handler)
        .await
        .map_err(|e| AppError::Protocol(format!("ssh connect: {e}")))?;

    authenticate(&mut session, &params.user, auth).await?;
    info!("ssh authenticated as {}", params.user);

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| AppError::Protocol(format!("open session: {e}")))?;

    let term = params
        .options
        .term
        .clone()
        .unwrap_or_else(|| "xterm-256color".into());
    let cols = params.options.cols.unwrap_or(120) as u32;
    let rows = params.options.rows.unwrap_or(30) as u32;
    channel
        .request_pty(false, &term, cols, rows, 0, 0, &[])
        .await
        .map_err(|e| AppError::Protocol(format!("request pty: {e}")))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| AppError::Protocol(format!("request shell: {e}")))?;

    let (input_tx, mut input_rx) = mpsc::channel::<SessionInput>(64);
    let handle = SessionHandle::new(
        SessionInfo {
            state: SessionState::Connected,
            ..info
        },
        Some(input_tx),
    );
    let _ = event_tx
        .send(SessionEvent::State {
            session_id: info.id,
            state: SessionState::Connected,
            message: None,
        })
        .await;

    let session_id = info.id;
    let state_for_task = handle.state.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(msg) = channel.wait() => {
                    match msg {
                        ChannelMsg::Data { data } => {
                            let _ = event_tx.send(SessionEvent::Output {
                                session_id,
                                data: data.to_vec(),
                            }).await;
                        }
                        ChannelMsg::ExtendedData { data, ext: _ } => {
                            let _ = event_tx.send(SessionEvent::Output {
                                session_id,
                                data: data.to_vec(),
                            }).await;
                        }
                        ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. } => {
                            *state_for_task.lock() = SessionState::Disconnected;
                            let _ = event_tx.send(SessionEvent::State {
                                session_id,
                                state: SessionState::Disconnected,
                                message: None,
                            }).await;
                            break;
                        }
                        other => debug!("ssh channel msg: {:?}", other),
                    }
                }
                Some(cmd) = input_rx.recv() => {
                    match cmd {
                        SessionInput::Stdin(bytes) => {
                            if let Err(e) = channel.data(bytes.as_slice()).await {
                                error!("ssh write: {e}");
                            }
                        }
                        SessionInput::Resize { cols, rows } => {
                            if let Err(e) = channel
                                .window_change(cols as u32, rows as u32, 0, 0)
                                .await
                            {
                                error!("ssh resize: {e}");
                            }
                        }
                        SessionInput::Close => {
                            let _ = channel.eof().await;
                            let _ = session
                                .disconnect(Disconnect::ByApplication, "", "en")
                                .await;
                            break;
                        }
                    }
                }
                else => break,
            }
        }
    });

    let _ = seen; // keep alive via clone above
    Ok(handle)
}

async fn authenticate(
    session: &mut Handle<ClientHandler>,
    user: &str,
    auth: SshAuth,
) -> AppResult<()> {
    let ok = match auth {
        SshAuth::Password(pw) => {
            let s = std::str::from_utf8(pw.as_slice())
                .map_err(|_| AppError::InvalidInput("password is not valid UTF-8".into()))?;
            session
                .authenticate_password(user, s)
                .await
                .map_err(|e| AppError::Protocol(format!("ssh auth password: {e}")))?
        }
        SshAuth::PrivateKey { pem, passphrase } => {
            let pp = passphrase
                .as_ref()
                .map(|p| std::str::from_utf8(p.as_slice()).unwrap_or(""));
            let key = russh::keys::decode_secret_key(
                std::str::from_utf8(pem.as_slice())
                    .map_err(|_| AppError::InvalidInput("private key not utf-8".into()))?,
                pp,
            )
            .map_err(|e| AppError::Protocol(format!("decode key: {e}")))?;
            session
                .authenticate_publickey(user, Arc::new(key))
                .await
                .map_err(|e| AppError::Protocol(format!("ssh auth pubkey: {e}")))?
        }
        SshAuth::Agent => {
            // ssh-agent integration requires routing the agent socket
            // through russh's signing API (no direct `authenticate_agent`
            // helper in russh 0.46). The hook lives here so the IPC layer
            // can offer the option; the wiring lands in Phase 3.5.
            let _ = (session, user);
            return Err(AppError::Protocol(
                "ssh-agent auth wiring is deferred to a follow-up; use password or key for now"
                    .into(),
            ));
        }
    };
    if !ok {
        return Err(AppError::Protocol("ssh authentication failed".into()));
    }
    Ok(())
}

/// Pick the right `SecretKind` for the auth mode, used by callers when
/// retrieving the secret from the vault.
pub fn secret_kind_for(auth_kind: &str) -> SecretKind {
    match auth_kind {
        "ssh_key" | "ssh_private_key" => SecretKind::SshPrivateKey,
        "ssh_key_passphrase" => SecretKind::SshKeyPassphrase,
        _ => SecretKind::Password,
    }
}
