//! Top-level error type for the backend. Implements `serde::Serialize` so it
//! can flow back to the renderer over Tauri IPC as a tagged variant.

use serde::{Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("vault is locked")]
    VaultLocked,

    #[error("vault is already initialized")]
    VaultAlreadyInitialized,

    #[error("incorrect master password")]
    BadMasterPassword,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl AppError {
    /// Stable kind string used by the renderer to switch on.
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::NotFound(_) => "NotFound",
            AppError::InvalidInput(_) => "InvalidInput",
            AppError::VaultLocked => "VaultLocked",
            AppError::VaultAlreadyInitialized => "VaultAlreadyInitialized",
            AppError::BadMasterPassword => "BadMasterPassword",
            AppError::Crypto(_) => "Crypto",
            AppError::Io(_) => "Io",
            AppError::Storage(_) => "Storage",
            AppError::Keychain(_) => "Keychain",
            AppError::Session(_) => "Session",
            AppError::Protocol(_) => "Protocol",
            AppError::Internal(_) => "Internal",
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        AppError::Storage(value.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for AppError {
    fn from(value: sqlx::migrate::MigrateError) -> Self {
        AppError::Storage(format!("migration: {value}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::InvalidInput(format!("json: {value}"))
    }
}

impl From<keyring::Error> for AppError {
    fn from(value: keyring::Error) -> Self {
        AppError::Keychain(value.to_string())
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("kind", self.kind())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

pub type AppResult<T> = Result<T, AppError>;
