//! Vault commands.
//!
//! `vault_put_secret` and `vault_get_secret` are deliberately asymmetric:
//! the renderer can write opaque secrets (so it can collect a password
//! once at credential-creation time) but cannot read them back. Reads are
//! only performed inside the backend during connection setup.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::core::errors::AppResult;
use crate::core::ids::VaultRef;
use crate::core::state::AppState;
use crate::core::vault::{EntrySummary, SecretKind};

#[derive(Debug, Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
}

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    VaultStatus {
        initialized: state.vault.is_initialized(),
        unlocked: state.vault.is_unlocked(),
    }
}

#[tauri::command]
pub fn vault_initialize(state: State<'_, AppState>, master_password: String) -> AppResult<()> {
    state.vault.initialize(&master_password)?;
    Ok(())
}

#[tauri::command]
pub fn vault_unlock(state: State<'_, AppState>, master_password: String) -> AppResult<()> {
    state.vault.unlock(&master_password)
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> AppResult<()> {
    state.vault.lock();
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct PutSecretInput {
    pub kind: SecretKind,
    pub plaintext: String,
}

/// Stores a new secret and returns its ref. The plaintext leaves the renderer
/// once and only briefly: it's encrypted into the vault and the input is
/// dropped immediately on the backend side.
#[tauri::command]
pub fn vault_put_secret(state: State<'_, AppState>, input: PutSecretInput) -> AppResult<VaultRef> {
    let v = state.vault.put(input.kind, input.plaintext.as_bytes())?;
    Ok(v)
}

#[tauri::command]
pub fn vault_delete_secret(state: State<'_, AppState>, vault_ref: VaultRef) -> AppResult<()> {
    state.vault.delete(&vault_ref)
}

#[tauri::command]
pub fn vault_list_entries(state: State<'_, AppState>) -> AppResult<Vec<EntrySummary>> {
    state.vault.list()
}
