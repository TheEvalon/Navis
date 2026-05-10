//! Trust-store management commands.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::core::errors::AppResult;
use crate::core::state::AppState;
use crate::protocols::hostkeys::{KnownSshHost, RdpPinStore, SshKnownHosts};

#[tauri::command]
pub fn ssh_known_hosts(state: State<'_, AppState>) -> AppResult<Vec<KnownSshHost>> {
    let store = SshKnownHosts::new(state.paths.known_hosts_path());
    store.list()
}

#[derive(Debug, Deserialize)]
pub struct SshTrustInput {
    pub host: String,
    pub port: u16,
    pub algo: String,
    pub key_b64: String,
}

#[tauri::command]
pub fn ssh_trust_host(state: State<'_, AppState>, input: SshTrustInput) -> AppResult<()> {
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD
        .decode(input.key_b64.as_bytes())
        .map_err(|e| crate::core::errors::AppError::InvalidInput(format!("base64: {e}")))?;
    let store = SshKnownHosts::new(state.paths.known_hosts_path());
    store.trust_on_first_use(&input.host, input.port, &input.algo, &key)
}

#[derive(Debug, Deserialize)]
pub struct SshForgetInput {
    pub host: String,
    pub port: u16,
}

#[tauri::command]
pub fn ssh_forget_host(state: State<'_, AppState>, input: SshForgetInput) -> AppResult<()> {
    let store = SshKnownHosts::new(state.paths.known_hosts_path());
    store.forget(&input.host, input.port)
}

#[derive(Debug, Serialize)]
pub struct RdpPin {
    pub host: String,
    pub port: u16,
    pub thumbprint_sha256: String,
}

#[tauri::command]
pub fn rdp_pinned_hosts(state: State<'_, AppState>) -> AppResult<Vec<RdpPin>> {
    let pins = RdpPinStore::load(&state.paths.rdp_pins_path())?;
    // We expose the internal map in a richer wire format.
    Ok(serde_json::to_value(&pins)?
        .get("pins")
        .and_then(|v| v.as_object())
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| {
                    let (host, port) = k.rsplit_once(':')?;
                    let port: u16 = port.parse().ok()?;
                    Some(RdpPin {
                        host: host.to_string(),
                        port,
                        thumbprint_sha256: v.as_str().unwrap_or_default().to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

#[derive(Debug, Deserialize)]
pub struct RdpPinInput {
    pub host: String,
    pub port: u16,
    /// DER-encoded server certificate.
    pub cert_der_b64: String,
}

#[tauri::command]
pub fn rdp_pin_host(state: State<'_, AppState>, input: RdpPinInput) -> AppResult<()> {
    use base64::Engine as _;
    let cert = base64::engine::general_purpose::STANDARD
        .decode(input.cert_der_b64.as_bytes())
        .map_err(|e| crate::core::errors::AppError::InvalidInput(format!("base64: {e}")))?;
    let path = state.paths.rdp_pins_path();
    let mut store = RdpPinStore::load(&path)?;
    store.pin(&input.host, input.port, &cert);
    store.save(&path)
}

#[derive(Debug, Deserialize)]
pub struct RdpForgetInput {
    pub host: String,
    pub port: u16,
}

#[tauri::command]
pub fn rdp_forget_host(state: State<'_, AppState>, input: RdpForgetInput) -> AppResult<()> {
    let path = state.paths.rdp_pins_path();
    let mut store = RdpPinStore::load(&path)?;
    store.forget(&input.host, input.port);
    store.save(&path)
}
