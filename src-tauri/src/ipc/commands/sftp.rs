//! SFTP file-browser and transfer commands.
//!
//! Every command takes a `SessionId` referring to a session previously
//! created via `start_session` against an SFTP-protocol connection.
//! The renderer chooses local paths through the dialog plugin; we
//! still defense-in-depth-validate them.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;

use crate::core::errors::{AppError, AppResult};
use crate::core::ids::SessionId;
use crate::core::state::AppState;
use crate::protocols::sftp::{validate_relative_path, RemoteEntry, SftpEngine};

fn sftp_for(state: &AppState, session_id: &SessionId) -> AppResult<SftpEngine> {
    state
        .sessions
        .read()
        .get(session_id)
        .and_then(|h| h.sftp.clone())
        .ok_or_else(|| AppError::NotFound(format!("sftp session {session_id}")))
}

#[tauri::command]
pub async fn sftp_list(
    state: State<'_, AppState>,
    session_id: SessionId,
    path: String,
) -> AppResult<Vec<RemoteEntry>> {
    let engine = sftp_for(&state, &session_id)?;
    engine.list(&path).await
}

#[tauri::command]
pub async fn sftp_canonicalize(
    state: State<'_, AppState>,
    session_id: SessionId,
    path: String,
) -> AppResult<String> {
    let engine = sftp_for(&state, &session_id)?;
    engine.canonicalize(&path).await
}

#[tauri::command]
pub async fn sftp_mkdir(
    state: State<'_, AppState>,
    session_id: SessionId,
    path: String,
) -> AppResult<()> {
    let engine = sftp_for(&state, &session_id)?;
    engine.mkdir(&path).await
}

#[tauri::command]
pub async fn sftp_remove(
    state: State<'_, AppState>,
    session_id: SessionId,
    path: String,
    is_dir: bool,
) -> AppResult<()> {
    let engine = sftp_for(&state, &session_id)?;
    engine.remove(&path, is_dir).await
}

#[tauri::command]
pub async fn sftp_rename(
    state: State<'_, AppState>,
    session_id: SessionId,
    from: String,
    to: String,
) -> AppResult<()> {
    let engine = sftp_for(&state, &session_id)?;
    engine.rename(&from, &to).await
}

#[derive(Debug, Serialize)]
pub struct TransferResult {
    pub bytes: u64,
}

#[tauri::command]
pub async fn sftp_download(
    state: State<'_, AppState>,
    session_id: SessionId,
    remote_path: String,
    local_path: String,
) -> AppResult<TransferResult> {
    let engine = sftp_for(&state, &session_id)?;
    let bytes = engine
        .read_to_local(&remote_path, &PathBuf::from(local_path))
        .await?;
    Ok(TransferResult { bytes })
}

#[tauri::command]
pub async fn sftp_upload(
    state: State<'_, AppState>,
    session_id: SessionId,
    local_path: String,
    remote_path: String,
) -> AppResult<TransferResult> {
    let engine = sftp_for(&state, &session_id)?;
    let bytes = engine
        .write_from_local(&PathBuf::from(local_path), &remote_path)
        .await?;
    Ok(TransferResult { bytes })
}

/// Sanity check exposed to the UI.
#[tauri::command]
pub fn sftp_validate_relative_path(path: String) -> AppResult<()> {
    validate_relative_path(&path)
}
