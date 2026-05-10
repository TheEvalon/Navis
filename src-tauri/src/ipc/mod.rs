//! Tauri IPC surface.
//!
//! All renderer-callable operations are typed Rust functions registered
//! with `tauri::generate_handler!`. Every command takes `tauri::State<AppState>`
//! and returns `AppResult<T>`. There is no `tauri-plugin-sql`, no `fs`, no
//! `shell.open` — the renderer cannot touch the filesystem or spawn
//! processes directly. Secrets never leave the backend in plaintext form;
//! the renderer only ever sees opaque `VaultRef` ids.

pub mod commands;

/// Returns the invoke handler that wires every command. We pin this to
/// `tauri::Wry` (the desktop runtime) because `generate_handler!` resolves
/// `AppHandle` to the default runtime — making the function generic would
/// cause the macro to expand against a runtime mismatch.
pub fn handler() -> Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync> {
    Box::new(tauri::generate_handler![
        commands::registry::list_folders,
        commands::registry::create_folder,
        commands::registry::update_folder,
        commands::registry::delete_folder,
        commands::registry::list_connections,
        commands::registry::create_connection,
        commands::registry::update_connection,
        commands::registry::delete_connection,
        commands::registry::list_credentials,
        commands::registry::create_credential,
        commands::registry::update_credential,
        commands::registry::delete_credential,
        commands::registry::resolve_credential,
        commands::registry::export_bundle,
        commands::registry::import_bundle,
        commands::vault::vault_status,
        commands::vault::vault_initialize,
        commands::vault::vault_unlock,
        commands::vault::vault_lock,
        commands::vault::vault_put_secret,
        commands::vault::vault_delete_secret,
        commands::vault::vault_list_entries,
        commands::vault::autolock_touch,
        commands::vault::autolock_get,
        commands::vault::autolock_set,
        commands::sessions::start_session,
        commands::sessions::send_input,
        commands::sessions::resize_session,
        commands::sessions::close_session,
        commands::sessions::list_sessions,
        commands::hostkeys::ssh_known_hosts,
        commands::hostkeys::ssh_trust_host,
        commands::hostkeys::ssh_forget_host,
        commands::hostkeys::rdp_pinned_hosts,
        commands::hostkeys::rdp_pin_host,
        commands::hostkeys::rdp_forget_host,
        commands::sftp::sftp_list,
        commands::sftp::sftp_canonicalize,
        commands::sftp::sftp_mkdir,
        commands::sftp::sftp_remove,
        commands::sftp::sftp_rename,
        commands::sftp::sftp_download,
        commands::sftp::sftp_upload,
        commands::sftp::sftp_validate_relative_path,
    ])
}
