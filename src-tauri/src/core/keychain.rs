//! Thin wrapper over the `keyring` crate. We don't store user secrets here —
//! only an optional wrapping key for the vault DEK so users in
//! "convenience" unlock mode don't have to type a master password every launch.

use keyring::Entry;
use zeroize::Zeroizing;

use crate::core::errors::{AppError, AppResult};

pub struct SystemKeychain {
    service: String,
    user: String,
}

impl SystemKeychain {
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }

    fn entry(&self) -> AppResult<Entry> {
        Entry::new(&self.service, &self.user).map_err(AppError::from)
    }

    /// Stores a 32-byte wrapping key.
    pub fn set_wrap_key(&self, key: &[u8; 32]) -> AppResult<()> {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
        self.entry()?.set_password(&encoded)?;
        Ok(())
    }

    /// Retrieves the 32-byte wrapping key, if any.
    pub fn get_wrap_key(&self) -> AppResult<Option<Zeroizing<[u8; 32]>>> {
        match self.entry()?.get_password() {
            Ok(encoded) => {
                use base64::Engine as _;
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|e| AppError::Keychain(format!("decode: {e}")))?;
                if raw.len() != 32 {
                    return Err(AppError::Keychain("wrap key wrong length".into()));
                }
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&raw);
                Ok(Some(Zeroizing::new(buf)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn clear_wrap_key(&self) -> AppResult<()> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
