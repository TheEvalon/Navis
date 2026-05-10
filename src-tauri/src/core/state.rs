//! Shared Tauri-managed state.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::core::autolock::AutoLocker;
use crate::core::ids::SessionId;
use crate::core::keychain::SystemKeychain;
use crate::core::paths::AppPaths;
use crate::core::registry::Registry;
use crate::core::vault::Vault;
use crate::protocols::session::SessionHandle;

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub vault: Arc<Vault>,
    pub keychain: Arc<SystemKeychain>,
    pub paths: Arc<AppPaths>,
    pub autolock: AutoLocker,
    pub sessions: Arc<RwLock<HashMap<SessionId, SessionHandle>>>,
}
