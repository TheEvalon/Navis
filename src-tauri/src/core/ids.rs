//! Strongly typed wrappers around UUIDs. Keeps connection ids from being
//! confused with folder ids or credential ids in function signatures.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_newtype {
    ($name:ident, $tag:literal) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub const TAG: &'static str = $tag;
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

id_newtype!(FolderId, "folder");
id_newtype!(ConnectionId, "connection");
id_newtype!(CredentialId, "credential");
id_newtype!(VaultRef, "vault");
id_newtype!(SessionId, "session");

/// Convenience: render the storage form of a UUID id.
pub fn to_db_string<I: fmt::Display>(id: &I) -> String {
    id.to_string()
}
