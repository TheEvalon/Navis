//! SQLite-backed metadata store for folders, connections, and credential profiles.
//!
//! No secret material lives here — credential profiles only store a `vault_ref`
//! pointing into the encrypted vault.

use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::core::errors::{AppError, AppResult};
use crate::core::ids::{ConnectionId, CredentialId, FolderId, VaultRef};
use crate::core::vault::SecretKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Ssh,
    Sftp,
    Rdp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Sftp => "sftp",
            Protocol::Rdp => "rdp",
        }
    }

    pub fn parse(s: &str) -> AppResult<Self> {
        match s {
            "ssh" => Ok(Protocol::Ssh),
            "sftp" => Ok(Protocol::Sftp),
            "rdp" => Ok(Protocol::Rdp),
            other => Err(AppError::InvalidInput(format!("unknown protocol: {other}"))),
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Ssh | Protocol::Sftp => 22,
            Protocol::Rdp => 3389,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Folder {
    pub id: FolderId,
    pub parent_id: Option<FolderId>,
    pub name: String,
    pub default_credential_id: Option<CredentialId>,
    pub sort_order: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: ConnectionId,
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub credential_id: Option<CredentialId>,
    pub options: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfile {
    pub id: CredentialId,
    pub name: String,
    pub kind: SecretKind,
    pub username: Option<String>,
    pub vault_ref: VaultRef,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Inputs for creating/updating folders and connections. Separated from the
/// stored types so the renderer doesn't have to invent timestamps or ids.
#[derive(Debug, Clone, Deserialize)]
pub struct FolderInput {
    pub parent_id: Option<FolderId>,
    pub name: String,
    pub default_credential_id: Option<CredentialId>,
    #[serde(default)]
    pub sort_order: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionInput {
    pub folder_id: Option<FolderId>,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub credential_id: Option<CredentialId>,
    #[serde(default)]
    pub options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialProfileInput {
    pub name: String,
    pub kind: SecretKind,
    pub username: Option<String>,
    pub vault_ref: VaultRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    pub version: u32,
    pub folders: Vec<Folder>,
    pub connections: Vec<Connection>,
    pub credentials: Vec<CredentialProfile>,
}

pub struct Registry {
    pool: SqlitePool,
}

impl Registry {
    pub async fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|e| AppError::Storage(format!("dsn: {e}")))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        let registry = Self { pool };
        registry.migrate().await?;
        Ok(registry)
    }

    /// Open an in-memory registry. Tests only.
    #[cfg(test)]
    pub async fn open_memory() -> AppResult<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        let registry = Self { pool };
        registry.migrate().await?;
        Ok(registry)
    }

    async fn migrate(&self) -> AppResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY NOT NULL,
                parent_id TEXT NULL REFERENCES folders(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                default_credential_id TEXT NULL REFERENCES credential_profiles(id) ON DELETE SET NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credential_profiles (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                username TEXT NULL,
                vault_ref TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY NOT NULL,
                folder_id TEXT NULL REFERENCES folders(id) ON DELETE SET NULL,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NULL,
                credential_id TEXT NULL REFERENCES credential_profiles(id) ON DELETE SET NULL,
                options_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_connections_folder ON connections(folder_id);")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ---- folders ----

    pub async fn list_folders(&self) -> AppResult<Vec<Folder>> {
        let rows = sqlx::query("SELECT * FROM folders ORDER BY sort_order, name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(folder_from_row).collect()
    }

    pub async fn create_folder(&self, input: FolderInput) -> AppResult<Folder> {
        validate_name(&input.name)?;
        if let Some(parent) = input.parent_id {
            self.require_folder_exists(&parent).await?;
        }
        if let Some(cid) = input.default_credential_id {
            self.require_credential_exists(&cid).await?;
        }
        let id = FolderId::new();
        let now = Utc::now();
        let sort = input.sort_order.unwrap_or(0);
        sqlx::query(
            r#"INSERT INTO folders
                (id, parent_id, name, default_credential_id, sort_order, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        )
        .bind(id.to_string())
        .bind(input.parent_id.map(|p| p.to_string()))
        .bind(&input.name)
        .bind(input.default_credential_id.map(|c| c.to_string()))
        .bind(sort)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(Folder {
            id,
            parent_id: input.parent_id,
            name: input.name,
            default_credential_id: input.default_credential_id,
            sort_order: sort,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn update_folder(&self, id: FolderId, input: FolderInput) -> AppResult<Folder> {
        validate_name(&input.name)?;
        if let Some(parent) = input.parent_id {
            if parent == id {
                return Err(AppError::InvalidInput(
                    "folder cannot be its own parent".into(),
                ));
            }
            self.require_folder_exists(&parent).await?;
        }
        if let Some(cid) = input.default_credential_id {
            self.require_credential_exists(&cid).await?;
        }
        let now = Utc::now();
        let sort = input.sort_order.unwrap_or(0);
        let updated = sqlx::query(
            r#"UPDATE folders
                  SET parent_id = ?2,
                      name = ?3,
                      default_credential_id = ?4,
                      sort_order = ?5,
                      updated_at = ?6
                WHERE id = ?1"#,
        )
        .bind(id.to_string())
        .bind(input.parent_id.map(|p| p.to_string()))
        .bind(&input.name)
        .bind(input.default_credential_id.map(|c| c.to_string()))
        .bind(sort)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("folder {id}")));
        }
        self.get_folder(&id).await
    }

    pub async fn delete_folder(&self, id: FolderId) -> AppResult<()> {
        // ON DELETE CASCADE handles child folders; connections in the folder
        // get folder_id set to NULL via FK. That's intentional: deleting a
        // folder shouldn't silently delete connections.
        let res = sqlx::query("DELETE FROM folders WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("folder {id}")));
        }
        Ok(())
    }

    pub async fn get_folder(&self, id: &FolderId) -> AppResult<Folder> {
        let row = sqlx::query("SELECT * FROM folders WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("folder {id}")))?;
        folder_from_row(&row)
    }

    async fn require_folder_exists(&self, id: &FolderId) -> AppResult<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM folders WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("folder {id}")))?;
        Ok(())
    }

    // ---- connections ----

    pub async fn list_connections(&self) -> AppResult<Vec<Connection>> {
        let rows = sqlx::query("SELECT * FROM connections ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(connection_from_row).collect()
    }

    pub async fn create_connection(&self, input: ConnectionInput) -> AppResult<Connection> {
        validate_name(&input.name)?;
        validate_host(&input.host)?;
        if let Some(folder) = input.folder_id {
            self.require_folder_exists(&folder).await?;
        }
        if let Some(cid) = input.credential_id {
            self.require_credential_exists(&cid).await?;
        }
        let id = ConnectionId::new();
        let now = Utc::now();
        let port = input.port.unwrap_or_else(|| input.protocol.default_port());
        let options = input.options.unwrap_or(serde_json::json!({}));
        sqlx::query(
            r#"INSERT INTO connections
                (id, folder_id, name, protocol, host, port, username, credential_id, options_json, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
        )
        .bind(id.to_string())
        .bind(input.folder_id.map(|f| f.to_string()))
        .bind(&input.name)
        .bind(input.protocol.as_str())
        .bind(&input.host)
        .bind(port as i64)
        .bind(&input.username)
        .bind(input.credential_id.map(|c| c.to_string()))
        .bind(serde_json::to_string(&options)?)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(Connection {
            id,
            folder_id: input.folder_id,
            name: input.name,
            protocol: input.protocol,
            host: input.host,
            port,
            username: input.username,
            credential_id: input.credential_id,
            options,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn update_connection(
        &self,
        id: ConnectionId,
        input: ConnectionInput,
    ) -> AppResult<Connection> {
        validate_name(&input.name)?;
        validate_host(&input.host)?;
        if let Some(folder) = input.folder_id {
            self.require_folder_exists(&folder).await?;
        }
        if let Some(cid) = input.credential_id {
            self.require_credential_exists(&cid).await?;
        }
        let now = Utc::now();
        let port = input.port.unwrap_or_else(|| input.protocol.default_port());
        let options = input.options.unwrap_or(serde_json::json!({}));
        let res = sqlx::query(
            r#"UPDATE connections
                  SET folder_id = ?2,
                      name = ?3,
                      protocol = ?4,
                      host = ?5,
                      port = ?6,
                      username = ?7,
                      credential_id = ?8,
                      options_json = ?9,
                      updated_at = ?10
                WHERE id = ?1"#,
        )
        .bind(id.to_string())
        .bind(input.folder_id.map(|f| f.to_string()))
        .bind(&input.name)
        .bind(input.protocol.as_str())
        .bind(&input.host)
        .bind(port as i64)
        .bind(&input.username)
        .bind(input.credential_id.map(|c| c.to_string()))
        .bind(serde_json::to_string(&options)?)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("connection {id}")));
        }
        self.get_connection(&id).await
    }

    pub async fn delete_connection(&self, id: ConnectionId) -> AppResult<()> {
        let res = sqlx::query("DELETE FROM connections WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("connection {id}")));
        }
        Ok(())
    }

    pub async fn get_connection(&self, id: &ConnectionId) -> AppResult<Connection> {
        let row = sqlx::query("SELECT * FROM connections WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("connection {id}")))?;
        connection_from_row(&row)
    }

    // ---- credentials ----

    pub async fn list_credentials(&self) -> AppResult<Vec<CredentialProfile>> {
        let rows = sqlx::query("SELECT * FROM credential_profiles ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(credential_from_row).collect()
    }

    pub async fn create_credential(
        &self,
        input: CredentialProfileInput,
    ) -> AppResult<CredentialProfile> {
        validate_name(&input.name)?;
        let id = CredentialId::new();
        let now = Utc::now();
        let kind = serde_json::to_string(&input.kind)?
            .trim_matches('"')
            .to_string();
        sqlx::query(
            r#"INSERT INTO credential_profiles
                (id, name, kind, username, vault_ref, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        )
        .bind(id.to_string())
        .bind(&input.name)
        .bind(&kind)
        .bind(&input.username)
        .bind(input.vault_ref.to_string())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(CredentialProfile {
            id,
            name: input.name,
            kind: input.kind,
            username: input.username,
            vault_ref: input.vault_ref,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn update_credential(
        &self,
        id: CredentialId,
        input: CredentialProfileInput,
    ) -> AppResult<CredentialProfile> {
        validate_name(&input.name)?;
        let now = Utc::now();
        let kind = serde_json::to_string(&input.kind)?
            .trim_matches('"')
            .to_string();
        let res = sqlx::query(
            r#"UPDATE credential_profiles
                  SET name = ?2,
                      kind = ?3,
                      username = ?4,
                      vault_ref = ?5,
                      updated_at = ?6
                WHERE id = ?1"#,
        )
        .bind(id.to_string())
        .bind(&input.name)
        .bind(&kind)
        .bind(&input.username)
        .bind(input.vault_ref.to_string())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("credential {id}")));
        }
        self.get_credential(&id).await
    }

    pub async fn delete_credential(&self, id: CredentialId) -> AppResult<()> {
        let res = sqlx::query("DELETE FROM credential_profiles WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("credential {id}")));
        }
        Ok(())
    }

    pub async fn get_credential(&self, id: &CredentialId) -> AppResult<CredentialProfile> {
        let row = sqlx::query("SELECT * FROM credential_profiles WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("credential {id}")))?;
        credential_from_row(&row)
    }

    async fn require_credential_exists(&self, id: &CredentialId) -> AppResult<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM credential_profiles WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("credential {id}")))?;
        Ok(())
    }

    // ---- export / import ----

    pub async fn export_all(&self) -> AppResult<ExportBundle> {
        let folders = self.list_folders().await?;
        let connections = self.list_connections().await?;
        let credentials = self.list_credentials().await?;
        Ok(ExportBundle {
            version: 1,
            folders,
            connections,
            credentials,
        })
    }

    /// Imports a bundle, skipping any rows whose ids already exist locally.
    /// Returns counts so the UI can show "added X folders, Y connections,
    /// Z credentials". Vault entries are NOT included in exports — credential
    /// vault_refs from another machine won't resolve, and that's by design.
    pub async fn import_bundle(&self, bundle: ExportBundle) -> AppResult<ImportSummary> {
        if bundle.version != 1 {
            return Err(AppError::InvalidInput(format!(
                "unsupported bundle version {}",
                bundle.version
            )));
        }
        let mut summary = ImportSummary::default();
        for f in &bundle.folders {
            let exists = self.get_folder(&f.id).await.ok();
            if exists.is_some() {
                continue;
            }
            sqlx::query(
                r#"INSERT INTO folders
                    (id, parent_id, name, default_credential_id, sort_order, created_at, updated_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            )
            .bind(f.id.to_string())
            .bind(f.parent_id.map(|p| p.to_string()))
            .bind(&f.name)
            .bind(f.default_credential_id.map(|c| c.to_string()))
            .bind(f.sort_order)
            .bind(f.created_at.to_rfc3339())
            .bind(f.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
            summary.folders_added += 1;
        }
        for cred in &bundle.credentials {
            let exists = self.get_credential(&cred.id).await.ok();
            if exists.is_some() {
                continue;
            }
            let kind = serde_json::to_string(&cred.kind)?
                .trim_matches('"')
                .to_string();
            sqlx::query(
                r#"INSERT INTO credential_profiles
                    (id, name, kind, username, vault_ref, created_at, updated_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            )
            .bind(cred.id.to_string())
            .bind(&cred.name)
            .bind(&kind)
            .bind(&cred.username)
            .bind(cred.vault_ref.to_string())
            .bind(cred.created_at.to_rfc3339())
            .bind(cred.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
            summary.credentials_added += 1;
        }
        for conn in &bundle.connections {
            let exists = self.get_connection(&conn.id).await.ok();
            if exists.is_some() {
                continue;
            }
            sqlx::query(
                r#"INSERT INTO connections
                    (id, folder_id, name, protocol, host, port, username, credential_id, options_json, created_at, updated_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            )
            .bind(conn.id.to_string())
            .bind(conn.folder_id.map(|f| f.to_string()))
            .bind(&conn.name)
            .bind(conn.protocol.as_str())
            .bind(&conn.host)
            .bind(conn.port as i64)
            .bind(&conn.username)
            .bind(conn.credential_id.map(|c| c.to_string()))
            .bind(serde_json::to_string(&conn.options)?)
            .bind(conn.created_at.to_rfc3339())
            .bind(conn.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
            summary.connections_added += 1;
        }
        Ok(summary)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportSummary {
    pub folders_added: usize,
    pub connections_added: usize,
    pub credentials_added: usize,
}

fn validate_name(name: &str) -> AppResult<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidInput("name cannot be empty".into()));
    }
    if trimmed.len() > 256 {
        return Err(AppError::InvalidInput("name too long".into()));
    }
    Ok(())
}

fn validate_host(host: &str) -> AppResult<()> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidInput("host cannot be empty".into()));
    }
    if trimmed.len() > 256 {
        return Err(AppError::InvalidInput("host too long".into()));
    }
    if trimmed
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'\t')
    {
        return Err(AppError::InvalidInput(
            "host contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn parse_uuid(s: &str) -> AppResult<Uuid> {
    Uuid::parse_str(s).map_err(|e| AppError::Storage(format!("bad uuid {s}: {e}")))
}

fn parse_dt(s: &str) -> AppResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| AppError::Storage(format!("bad timestamp {s}: {e}")))
}

fn folder_from_row(row: &sqlx::sqlite::SqliteRow) -> AppResult<Folder> {
    let id: String = row.try_get("id")?;
    let parent: Option<String> = row.try_get("parent_id")?;
    let dcid: Option<String> = row.try_get("default_credential_id")?;
    let created: String = row.try_get("created_at")?;
    let updated: String = row.try_get("updated_at")?;
    Ok(Folder {
        id: FolderId::from_uuid(parse_uuid(&id)?),
        parent_id: parent
            .map(|p| parse_uuid(&p).map(FolderId::from_uuid))
            .transpose()?,
        name: row.try_get("name")?,
        default_credential_id: dcid
            .map(|c| parse_uuid(&c).map(CredentialId::from_uuid))
            .transpose()?,
        sort_order: row.try_get("sort_order")?,
        created_at: parse_dt(&created)?,
        updated_at: parse_dt(&updated)?,
    })
}

fn connection_from_row(row: &sqlx::sqlite::SqliteRow) -> AppResult<Connection> {
    let id: String = row.try_get("id")?;
    let folder: Option<String> = row.try_get("folder_id")?;
    let cred: Option<String> = row.try_get("credential_id")?;
    let proto: String = row.try_get("protocol")?;
    let port: i64 = row.try_get("port")?;
    let opts_json: String = row.try_get("options_json")?;
    let created: String = row.try_get("created_at")?;
    let updated: String = row.try_get("updated_at")?;
    Ok(Connection {
        id: ConnectionId::from_uuid(parse_uuid(&id)?),
        folder_id: folder
            .map(|f| parse_uuid(&f).map(FolderId::from_uuid))
            .transpose()?,
        name: row.try_get("name")?,
        protocol: Protocol::parse(&proto)?,
        host: row.try_get("host")?,
        port: port.clamp(0, u16::MAX as i64) as u16,
        username: row.try_get("username")?,
        credential_id: cred
            .map(|c| parse_uuid(&c).map(CredentialId::from_uuid))
            .transpose()?,
        options: serde_json::from_str(&opts_json).unwrap_or(serde_json::json!({})),
        created_at: parse_dt(&created)?,
        updated_at: parse_dt(&updated)?,
    })
}

fn credential_from_row(row: &sqlx::sqlite::SqliteRow) -> AppResult<CredentialProfile> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let vref: String = row.try_get("vault_ref")?;
    let created: String = row.try_get("created_at")?;
    let updated: String = row.try_get("updated_at")?;
    let kind_enum: SecretKind = serde_json::from_str(&format!("\"{kind}\""))
        .map_err(|e| AppError::Storage(format!("bad credential kind {kind}: {e}")))?;
    Ok(CredentialProfile {
        id: CredentialId::from_uuid(parse_uuid(&id)?),
        name: row.try_get("name")?,
        kind: kind_enum,
        username: row.try_get("username")?,
        vault_ref: VaultRef::from_uuid(parse_uuid(&vref)?),
        created_at: parse_dt(&created)?,
        updated_at: parse_dt(&updated)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn folder_and_connection_crud_roundtrip() {
        let r = Registry::open_memory().await.unwrap();
        let f = r
            .create_folder(FolderInput {
                parent_id: None,
                name: "Production".into(),
                default_credential_id: None,
                sort_order: None,
            })
            .await
            .unwrap();
        assert_eq!(f.name, "Production");

        let c = r
            .create_connection(ConnectionInput {
                folder_id: Some(f.id),
                name: "web-1".into(),
                protocol: Protocol::Ssh,
                host: "10.0.0.1".into(),
                port: None,
                username: Some("ops".into()),
                credential_id: None,
                options: None,
            })
            .await
            .unwrap();
        assert_eq!(c.port, 22);
        assert_eq!(c.protocol, Protocol::Ssh);

        // Update
        let c2 = r
            .update_connection(
                c.id,
                ConnectionInput {
                    folder_id: Some(f.id),
                    name: "web-1".into(),
                    protocol: Protocol::Rdp,
                    host: "10.0.0.1".into(),
                    port: None,
                    username: Some("ops".into()),
                    credential_id: None,
                    options: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(c2.protocol, Protocol::Rdp);
        assert_eq!(c2.port, 3389);

        // Delete
        r.delete_connection(c.id).await.unwrap();
        assert!(matches!(
            r.get_connection(&c.id).await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_input() {
        let r = Registry::open_memory().await.unwrap();
        assert!(matches!(
            r.create_folder(FolderInput {
                parent_id: None,
                name: "   ".into(),
                default_credential_id: None,
                sort_order: None,
            })
            .await,
            Err(AppError::InvalidInput(_))
        ));
        assert!(matches!(
            r.create_connection(ConnectionInput {
                folder_id: None,
                name: "n".into(),
                protocol: Protocol::Ssh,
                host: "bad host".into(),
                port: None,
                username: None,
                credential_id: None,
                options: None,
            })
            .await,
            Err(AppError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn export_import_roundtrip() {
        let src = Registry::open_memory().await.unwrap();
        let f = src
            .create_folder(FolderInput {
                parent_id: None,
                name: "Prod".into(),
                default_credential_id: None,
                sort_order: None,
            })
            .await
            .unwrap();
        let cred = src
            .create_credential(CredentialProfileInput {
                name: "shared".into(),
                kind: SecretKind::Password,
                username: Some("ops".into()),
                vault_ref: VaultRef::new(),
            })
            .await
            .unwrap();
        let conn = src
            .create_connection(ConnectionInput {
                folder_id: Some(f.id),
                name: "host".into(),
                protocol: Protocol::Ssh,
                host: "h".into(),
                port: None,
                username: Some("ops".into()),
                credential_id: Some(cred.id),
                options: None,
            })
            .await
            .unwrap();

        let bundle = src.export_all().await.unwrap();
        let dst = Registry::open_memory().await.unwrap();
        let summary = dst.import_bundle(bundle.clone()).await.unwrap();
        assert_eq!(summary.folders_added, 1);
        assert_eq!(summary.connections_added, 1);
        assert_eq!(summary.credentials_added, 1);

        // Idempotent: re-import skips everything.
        let again = dst.import_bundle(bundle).await.unwrap();
        assert_eq!(again.folders_added, 0);
        assert_eq!(again.connections_added, 0);
        assert_eq!(again.credentials_added, 0);

        // Verify shape preserved.
        let folders = dst.list_folders().await.unwrap();
        let connections = dst.list_connections().await.unwrap();
        let credentials = dst.list_credentials().await.unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(connections.len(), 1);
        assert_eq!(credentials.len(), 1);
        assert_eq!(connections[0].id, conn.id);
        assert_eq!(connections[0].folder_id, Some(f.id));
        assert_eq!(connections[0].credential_id, Some(cred.id));
    }

    #[tokio::test]
    async fn import_rejects_bad_version() {
        let r = Registry::open_memory().await.unwrap();
        let bundle = ExportBundle {
            version: 999,
            folders: vec![],
            connections: vec![],
            credentials: vec![],
        };
        assert!(matches!(
            r.import_bundle(bundle).await,
            Err(AppError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn folder_self_parent_rejected() {
        let r = Registry::open_memory().await.unwrap();
        let f = r
            .create_folder(FolderInput {
                parent_id: None,
                name: "x".into(),
                default_credential_id: None,
                sort_order: None,
            })
            .await
            .unwrap();
        assert!(matches!(
            r.update_folder(
                f.id,
                FolderInput {
                    parent_id: Some(f.id),
                    name: "x".into(),
                    default_credential_id: None,
                    sort_order: None,
                },
            )
            .await,
            Err(AppError::InvalidInput(_))
        ));
    }
}
