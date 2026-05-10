//! Effective credential resolution.
//!
//! For a given connection, walk up the folder chain to find the first
//! `default_credential_id`. The connection's own `credential_id` always wins.

use crate::core::errors::{AppError, AppResult};
use crate::core::ids::{ConnectionId, CredentialId};
use crate::core::registry::Registry;

pub async fn resolve_credential(
    registry: &Registry,
    connection_id: &ConnectionId,
) -> AppResult<Option<CredentialId>> {
    let conn = registry.get_connection(connection_id).await?;
    if let Some(c) = conn.credential_id {
        return Ok(Some(c));
    }
    let mut cursor = conn.folder_id;
    let mut visited = std::collections::HashSet::new();
    while let Some(fid) = cursor {
        if !visited.insert(fid) {
            return Err(AppError::Storage(format!("folder cycle detected at {fid}")));
        }
        let folder = registry.get_folder(&fid).await?;
        if let Some(c) = folder.default_credential_id {
            return Ok(Some(c));
        }
        cursor = folder.parent_id;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::{
        ConnectionInput, CredentialProfileInput, FolderInput, Protocol, Registry,
    };
    use crate::core::vault::SecretKind;

    #[tokio::test]
    async fn inherits_from_parent_folder() {
        let r = Registry::open_memory().await.unwrap();
        let cred = r
            .create_credential(CredentialProfileInput {
                name: "shared".into(),
                kind: SecretKind::Password,
                username: Some("ops".into()),
                vault_ref: crate::core::ids::VaultRef::new(),
            })
            .await
            .unwrap();
        let parent = r
            .create_folder(FolderInput {
                parent_id: None,
                name: "prod".into(),
                default_credential_id: Some(cred.id),
                sort_order: None,
            })
            .await
            .unwrap();
        let child = r
            .create_folder(FolderInput {
                parent_id: Some(parent.id),
                name: "web".into(),
                default_credential_id: None,
                sort_order: None,
            })
            .await
            .unwrap();
        let conn = r
            .create_connection(ConnectionInput {
                folder_id: Some(child.id),
                name: "host".into(),
                protocol: Protocol::Ssh,
                host: "h".into(),
                port: None,
                username: None,
                credential_id: None,
                options: None,
            })
            .await
            .unwrap();
        let resolved = resolve_credential(&r, &conn.id).await.unwrap();
        assert_eq!(resolved, Some(cred.id));
    }

    #[tokio::test]
    async fn connection_override_wins() {
        let r = Registry::open_memory().await.unwrap();
        let parent_cred = r
            .create_credential(CredentialProfileInput {
                name: "parent".into(),
                kind: SecretKind::Password,
                username: None,
                vault_ref: crate::core::ids::VaultRef::new(),
            })
            .await
            .unwrap();
        let conn_cred = r
            .create_credential(CredentialProfileInput {
                name: "conn".into(),
                kind: SecretKind::Password,
                username: None,
                vault_ref: crate::core::ids::VaultRef::new(),
            })
            .await
            .unwrap();
        let folder = r
            .create_folder(FolderInput {
                parent_id: None,
                name: "f".into(),
                default_credential_id: Some(parent_cred.id),
                sort_order: None,
            })
            .await
            .unwrap();
        let conn = r
            .create_connection(ConnectionInput {
                folder_id: Some(folder.id),
                name: "c".into(),
                protocol: Protocol::Ssh,
                host: "h".into(),
                port: None,
                username: None,
                credential_id: Some(conn_cred.id),
                options: None,
            })
            .await
            .unwrap();
        let resolved = resolve_credential(&r, &conn.id).await.unwrap();
        assert_eq!(resolved, Some(conn_cred.id));
    }

    #[tokio::test]
    async fn no_credential_returns_none() {
        let r = Registry::open_memory().await.unwrap();
        let folder = r
            .create_folder(FolderInput {
                parent_id: None,
                name: "f".into(),
                default_credential_id: None,
                sort_order: None,
            })
            .await
            .unwrap();
        let conn = r
            .create_connection(ConnectionInput {
                folder_id: Some(folder.id),
                name: "c".into(),
                protocol: Protocol::Ssh,
                host: "h".into(),
                port: None,
                username: None,
                credential_id: None,
                options: None,
            })
            .await
            .unwrap();
        assert_eq!(resolve_credential(&r, &conn.id).await.unwrap(), None);
    }
}
