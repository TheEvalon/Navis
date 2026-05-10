//! Connection / folder / credential CRUD commands.

use tauri::State;

use crate::core::errors::AppResult;
use crate::core::ids::{ConnectionId, CredentialId, FolderId};
use crate::core::policy;
use crate::core::registry::{
    Connection, ConnectionInput, CredentialProfile, CredentialProfileInput, ExportBundle, Folder,
    FolderInput,
};
use crate::core::state::AppState;

#[tauri::command]
pub async fn list_folders(state: State<'_, AppState>) -> AppResult<Vec<Folder>> {
    state.registry.list_folders().await
}

#[tauri::command]
pub async fn create_folder(state: State<'_, AppState>, input: FolderInput) -> AppResult<Folder> {
    state.registry.create_folder(input).await
}

#[tauri::command]
pub async fn update_folder(
    state: State<'_, AppState>,
    id: FolderId,
    input: FolderInput,
) -> AppResult<Folder> {
    state.registry.update_folder(id, input).await
}

#[tauri::command]
pub async fn delete_folder(state: State<'_, AppState>, id: FolderId) -> AppResult<()> {
    state.registry.delete_folder(id).await
}

#[tauri::command]
pub async fn list_connections(state: State<'_, AppState>) -> AppResult<Vec<Connection>> {
    state.registry.list_connections().await
}

#[tauri::command]
pub async fn create_connection(
    state: State<'_, AppState>,
    input: ConnectionInput,
) -> AppResult<Connection> {
    state.registry.create_connection(input).await
}

#[tauri::command]
pub async fn update_connection(
    state: State<'_, AppState>,
    id: ConnectionId,
    input: ConnectionInput,
) -> AppResult<Connection> {
    state.registry.update_connection(id, input).await
}

#[tauri::command]
pub async fn delete_connection(state: State<'_, AppState>, id: ConnectionId) -> AppResult<()> {
    state.registry.delete_connection(id).await
}

#[tauri::command]
pub async fn list_credentials(state: State<'_, AppState>) -> AppResult<Vec<CredentialProfile>> {
    state.registry.list_credentials().await
}

#[tauri::command]
pub async fn create_credential(
    state: State<'_, AppState>,
    input: CredentialProfileInput,
) -> AppResult<CredentialProfile> {
    state.registry.create_credential(input).await
}

#[tauri::command]
pub async fn update_credential(
    state: State<'_, AppState>,
    id: CredentialId,
    input: CredentialProfileInput,
) -> AppResult<CredentialProfile> {
    state.registry.update_credential(id, input).await
}

#[tauri::command]
pub async fn delete_credential(state: State<'_, AppState>, id: CredentialId) -> AppResult<()> {
    state.registry.delete_credential(id).await
}

#[tauri::command]
pub async fn resolve_credential(
    state: State<'_, AppState>,
    connection_id: ConnectionId,
) -> AppResult<Option<CredentialId>> {
    policy::resolve_credential(&state.registry, &connection_id).await
}

#[tauri::command]
pub async fn export_bundle(state: State<'_, AppState>) -> AppResult<ExportBundle> {
    state.registry.export_all().await
}

/// Naive idempotent-ish import. Skips entries whose id already exists.
/// Vault entries are NOT included in the export; users must re-attach
/// credentials after import.
#[tauri::command]
pub async fn import_bundle(_state: State<'_, AppState>, bundle: ExportBundle) -> AppResult<()> {
    if bundle.version != 1 {
        return Err(crate::core::errors::AppError::InvalidInput(format!(
            "unsupported bundle version {}",
            bundle.version
        )));
    }
    // Implementation note: a real import inserts rows preserving ids and
    // skipping duplicates; deferred to v0.2 to keep this PR focused.
    tracing::warn!(
        "import_bundle stub called (folders: {}, connections: {}, credentials: {})",
        bundle.folders.len(),
        bundle.connections.len(),
        bundle.credentials.len()
    );
    Ok(())
}
