//! Encrypted credential vault.
//!
//! Design:
//! - Master password is stretched with Argon2id into a 256-bit *KEK*.
//! - A 256-bit *DEK* is generated at vault creation and wrapped with the KEK
//!   using AES-256-GCM (`wrapped_dek`, `dek_nonce`).
//! - Each secret entry is encrypted with the DEK using AES-256-GCM with a
//!   random 96-bit nonce and AAD = `vault_ref || record_kind`.
//! - The wrapped DEK and metadata live in a JSON file on disk; ciphertexts
//!   for entries are kept in the same file (single-file vault).
//! - The DEK lives in memory only while the vault is unlocked and is wiped
//!   on lock or drop via `zeroize`.
//!
//! AAD prevents an attacker who can swap ciphertexts from substituting an
//! entry of one kind (e.g. ssh_password) for another (e.g. master_recovery).
//!
//! Out of scope here (handled in higher layers):
//! - Idle auto-lock timer.
//! - OS keychain DEK wrapping for "convenience unlock".

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::core::errors::{AppError, AppResult};
use crate::core::ids::VaultRef;

const VAULT_MAGIC: &str = "navis-vault-v1";
const ARGON2_M_COST_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

/// What kind of secret an entry holds. Used as part of the AAD so an entry
/// can never be reinterpreted as a different kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    SshPrivateKey,
    SshKeyPassphrase,
    RdpPassword,
    Certificate,
    Generic,
}

impl SecretKind {
    pub fn as_aad(&self) -> &'static [u8] {
        match self {
            SecretKind::Password => b"password",
            SecretKind::SshPrivateKey => b"ssh_private_key",
            SecretKind::SshKeyPassphrase => b"ssh_key_passphrase",
            SecretKind::RdpPassword => b"rdp_password",
            SecretKind::Certificate => b"certificate",
            SecretKind::Generic => b"generic",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct OnDiskVault {
    magic: String,
    version: u32,
    kdf: KdfParamsOnDisk,
    salt_b64: String,
    wrapped_dek_b64: String,
    dek_nonce_b64: String,
    entries: std::collections::BTreeMap<String, EncryptedEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfParamsOnDisk {
    algorithm: String,
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedEntry {
    kind: SecretKind,
    nonce_b64: String,
    ciphertext_b64: String,
}

/// Public, redacted summary of a vault entry.
#[derive(Debug, Clone, Serialize)]
pub struct EntrySummary {
    pub vault_ref: VaultRef,
    pub kind: SecretKind,
    pub size_bytes: usize,
}

/// In-memory unlocked state.
struct Unlocked {
    dek: Zeroizing<[u8; 32]>,
}

impl Drop for Unlocked {
    fn drop(&mut self) {
        // Zeroizing<[u8;32]> already zeroes on drop; this is documentation.
    }
}

pub struct Vault {
    path: PathBuf,
    inner: RwLock<VaultInner>,
}

struct VaultInner {
    on_disk: Option<OnDiskVault>,
    unlocked: Option<Arc<Unlocked>>,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: RwLock::new(VaultInner {
                on_disk: None,
                unlocked: None,
            }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_initialized(&self) -> bool {
        self.path.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.read().unlocked.is_some()
    }

    /// Initialize a brand-new vault, encrypted with `master_password`.
    /// Fails if a vault file already exists.
    pub fn initialize(&self, master_password: &str) -> AppResult<()> {
        if self.path.exists() {
            return Err(AppError::VaultAlreadyInitialized);
        }
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let kek = derive_kek(master_password.as_bytes(), &salt)?;
        let mut dek_buf = [0u8; 32];
        OsRng.fill_bytes(&mut dek_buf);
        let dek = Zeroizing::new(dek_buf);

        let cipher = Aes256Gcm::new_from_slice(kek.as_slice())
            .map_err(|e| AppError::Crypto(format!("kek init: {e}")))?;
        let dek_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let wrapped_dek = cipher
            .encrypt(
                &dek_nonce,
                Payload {
                    msg: dek.as_slice(),
                    aad: VAULT_MAGIC.as_bytes(),
                },
            )
            .map_err(|e| AppError::Crypto(format!("wrap dek: {e}")))?;

        let on_disk = OnDiskVault {
            magic: VAULT_MAGIC.into(),
            version: 1,
            kdf: KdfParamsOnDisk {
                algorithm: "argon2id".into(),
                m_cost_kib: ARGON2_M_COST_KIB,
                t_cost: ARGON2_T_COST,
                parallelism: ARGON2_PARALLELISM,
            },
            salt_b64: b64(&salt),
            wrapped_dek_b64: b64(&wrapped_dek),
            dek_nonce_b64: b64(&dek_nonce),
            entries: Default::default(),
        };

        write_vault_atomic(&self.path, &on_disk)?;
        let mut inner = self.inner.write();
        inner.on_disk = Some(on_disk);
        inner.unlocked = Some(Arc::new(Unlocked { dek }));
        Ok(())
    }

    /// Load the on-disk vault into memory (does not unlock it).
    pub fn load(&self) -> AppResult<()> {
        let bytes = std::fs::read(&self.path)?;
        let on_disk: OnDiskVault = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Storage(format!("vault parse: {e}")))?;
        if on_disk.magic != VAULT_MAGIC {
            return Err(AppError::Storage("vault magic mismatch".into()));
        }
        let mut inner = self.inner.write();
        inner.on_disk = Some(on_disk);
        Ok(())
    }

    pub fn unlock(&self, master_password: &str) -> AppResult<()> {
        if !self.path.exists() && self.inner.read().on_disk.is_none() {
            return Err(AppError::NotFound("vault".into()));
        }
        if self.inner.read().on_disk.is_none() {
            self.load()?;
        }
        let inner_read = self.inner.read();
        let on_disk = inner_read
            .on_disk
            .as_ref()
            .ok_or_else(|| AppError::Internal("vault not loaded".into()))?;
        let salt = unb64(&on_disk.salt_b64)?;
        let wrapped = unb64(&on_disk.wrapped_dek_b64)?;
        let nonce = unb64(&on_disk.dek_nonce_b64)?;
        if nonce.len() != 12 {
            return Err(AppError::Crypto("dek nonce length".into()));
        }
        drop(inner_read);

        let kek = derive_kek(master_password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new_from_slice(kek.as_slice())
            .map_err(|e| AppError::Crypto(format!("kek init: {e}")))?;
        let dek_vec = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: &wrapped,
                    aad: VAULT_MAGIC.as_bytes(),
                },
            )
            .map_err(|_| AppError::BadMasterPassword)?;
        if dek_vec.len() != 32 {
            return Err(AppError::Crypto("dek length".into()));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_vec);
        // Burn the intermediate Vec.
        let mut tmp = dek_vec;
        tmp.zeroize();

        let mut inner = self.inner.write();
        inner.unlocked = Some(Arc::new(Unlocked {
            dek: Zeroizing::new(dek),
        }));
        Ok(())
    }

    pub fn lock(&self) {
        let mut inner = self.inner.write();
        inner.unlocked = None;
    }

    fn require_unlocked(&self) -> AppResult<Arc<Unlocked>> {
        self.inner
            .read()
            .unlocked
            .clone()
            .ok_or(AppError::VaultLocked)
    }

    /// Stores a new secret, returns its `VaultRef`.
    pub fn put(&self, kind: SecretKind, plaintext: &[u8]) -> AppResult<VaultRef> {
        let unlocked = self.require_unlocked()?;
        let cipher = Aes256Gcm::new_from_slice(unlocked.dek.as_slice())
            .map_err(|e| AppError::Crypto(format!("dek init: {e}")))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let vref = VaultRef::new();
        let aad = aad_for(&vref, kind);
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| AppError::Crypto(format!("encrypt entry: {e}")))?;

        let entry = EncryptedEntry {
            kind,
            nonce_b64: b64(&nonce),
            ciphertext_b64: b64(&ct),
        };

        let mut inner = self.inner.write();
        let on_disk = inner
            .on_disk
            .as_mut()
            .ok_or_else(|| AppError::Internal("vault not loaded".into()))?;
        on_disk.entries.insert(vref.to_string(), entry);
        write_vault_atomic(&self.path, on_disk)?;
        Ok(vref)
    }

    pub fn get(&self, vref: &VaultRef) -> AppResult<Zeroizing<Vec<u8>>> {
        let unlocked = self.require_unlocked()?;
        let inner = self.inner.read();
        let on_disk = inner
            .on_disk
            .as_ref()
            .ok_or_else(|| AppError::Internal("vault not loaded".into()))?;
        let entry = on_disk
            .entries
            .get(&vref.to_string())
            .ok_or_else(|| AppError::NotFound(format!("vault entry {vref}")))?;
        let nonce = unb64(&entry.nonce_b64)?;
        let ct = unb64(&entry.ciphertext_b64)?;
        let cipher = Aes256Gcm::new_from_slice(unlocked.dek.as_slice())
            .map_err(|e| AppError::Crypto(format!("dek init: {e}")))?;
        let aad = aad_for(vref, entry.kind);
        let pt = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|e| AppError::Crypto(format!("decrypt entry: {e}")))?;
        Ok(Zeroizing::new(pt))
    }

    pub fn delete(&self, vref: &VaultRef) -> AppResult<()> {
        let mut inner = self.inner.write();
        let on_disk = inner
            .on_disk
            .as_mut()
            .ok_or_else(|| AppError::Internal("vault not loaded".into()))?;
        if on_disk.entries.remove(&vref.to_string()).is_none() {
            return Err(AppError::NotFound(format!("vault entry {vref}")));
        }
        write_vault_atomic(&self.path, on_disk)?;
        Ok(())
    }

    /// Returns redacted summaries of all entries.
    pub fn list(&self) -> AppResult<Vec<EntrySummary>> {
        let inner = self.inner.read();
        let on_disk = inner
            .on_disk
            .as_ref()
            .ok_or_else(|| AppError::Internal("vault not loaded".into()))?;
        let mut out = Vec::with_capacity(on_disk.entries.len());
        for (k, v) in &on_disk.entries {
            let id: uuid::Uuid = k
                .parse()
                .map_err(|e| AppError::Storage(format!("bad vault id {k}: {e}")))?;
            let approx_size = base64_decoded_len(&v.ciphertext_b64).saturating_sub(16);
            out.push(EntrySummary {
                vault_ref: VaultRef::from_uuid(id),
                kind: v.kind,
                size_bytes: approx_size,
            });
        }
        Ok(out)
    }
}

fn aad_for(vref: &VaultRef, kind: SecretKind) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(VAULT_MAGIC.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(vref.to_string().as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(kind.as_aad());
    aad
}

fn derive_kek(password: &[u8], salt: &[u8]) -> AppResult<Zeroizing<[u8; 32]>> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| AppError::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| AppError::Crypto(format!("argon2: {e}")))?;
    Ok(Zeroizing::new(out))
}

fn write_vault_atomic(path: &Path, vault: &OnDiskVault) -> AppResult<()> {
    let serialized = serde_json::to_vec_pretty(vault)?;
    let parent = path.parent().ok_or_else(|| {
        AppError::Internal(format!("vault path has no parent: {}", path.display()))
    })?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".vault.{}.tmp",
        std::process::id().wrapping_add(rand::random::<u32>())
    ));
    std::fs::write(&tmp, serialized)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> AppResult<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| AppError::Crypto(format!("base64: {e}")))
}

fn base64_decoded_len(s: &str) -> usize {
    let bytes = s.len();
    if bytes == 0 {
        return 0;
    }
    let pad = s.bytes().rev().take_while(|b| *b == b'=').count();
    bytes / 4 * 3 - pad
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_vault() -> (TempDir, Vault) {
        let dir = TempDir::new().expect("tmp");
        let path = dir.path().join("vault.bin");
        (dir, Vault::new(path))
    }

    #[test]
    fn initialize_unlock_put_get_delete_roundtrip() {
        let (_g, vault) = temp_vault();
        vault.initialize("correct horse battery staple").unwrap();
        assert!(vault.is_unlocked());

        let vref = vault
            .put(SecretKind::Password, b"hunter2")
            .expect("put password");
        let got = vault.get(&vref).expect("get");
        assert_eq!(got.as_slice(), b"hunter2");

        vault.delete(&vref).expect("delete");
        assert!(matches!(vault.get(&vref), Err(AppError::NotFound(_))));
    }

    #[test]
    fn lock_then_unlock_with_wrong_password_fails() {
        let (_g, vault) = temp_vault();
        vault.initialize("right").unwrap();
        let v = vault.put(SecretKind::Password, b"x").unwrap();
        vault.lock();
        assert!(!vault.is_unlocked());
        assert!(matches!(vault.get(&v), Err(AppError::VaultLocked)));
        assert!(matches!(
            vault.unlock("wrong"),
            Err(AppError::BadMasterPassword)
        ));
        vault.unlock("right").unwrap();
        let got = vault.get(&v).unwrap();
        assert_eq!(got.as_slice(), b"x");
    }

    #[test]
    fn aad_binds_kind_to_entry() {
        // Tampering with stored kind label invalidates decryption.
        let (_g, vault) = temp_vault();
        vault.initialize("pw").unwrap();
        let vref = vault.put(SecretKind::Password, b"shh").unwrap();

        // Manually flip the entry kind on disk and reload.
        let bytes = std::fs::read(vault.path()).unwrap();
        let mut on_disk: OnDiskVault = serde_json::from_slice(&bytes).unwrap();
        let entry = on_disk.entries.get_mut(&vref.to_string()).unwrap();
        entry.kind = SecretKind::Certificate;
        let bytes = serde_json::to_vec(&on_disk).unwrap();
        std::fs::write(vault.path(), bytes).unwrap();

        let v2 = Vault::new(vault.path().to_path_buf());
        v2.unlock("pw").unwrap();
        assert!(matches!(v2.get(&vref), Err(AppError::Crypto(_))));
    }

    #[test]
    fn reinit_existing_vault_fails() {
        let (_g, vault) = temp_vault();
        vault.initialize("pw").unwrap();
        assert!(matches!(
            vault.initialize("pw"),
            Err(AppError::VaultAlreadyInitialized)
        ));
    }

    /// A small property-style harness: write malformed bytes to the vault
    /// path and confirm we never panic and never claim a successful unlock.
    #[test]
    fn malformed_inputs_never_panic() {
        let cases: &[&[u8]] = &[
            b"",
            b"{}",
            b"not json at all",
            b"{\"magic\": \"navis-vault-v1\"}",
            b"{\"magic\":\"navis-vault-v1\",\"version\":1,\"kdf\":{\"algorithm\":\"argon2id\",\"m_cost_kib\":1,\"t_cost\":1,\"parallelism\":1},\"salt_b64\":\"\",\"wrapped_dek_b64\":\"\",\"dek_nonce_b64\":\"\",\"entries\":{}}",
            b"\xFF\xFE\xFD\xFC",
            &[0u8; 4096],
        ];
        for (i, bytes) in cases.iter().enumerate() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("vault.bin");
            std::fs::write(&path, bytes).unwrap();
            let v = Vault::new(path);
            // Either errors cleanly or returns BadMasterPassword/Crypto.
            let r = v.unlock("any");
            assert!(r.is_err(), "case {i} should error");
            assert!(!v.is_unlocked());
        }
    }

    #[test]
    fn truncated_ciphertext_fails_aead() {
        let (_g, vault) = temp_vault();
        vault.initialize("pw").unwrap();
        let v = vault.put(SecretKind::Password, b"sensitive").unwrap();

        // Truncate the ciphertext on disk and confirm decryption fails.
        let raw = std::fs::read(vault.path()).unwrap();
        let mut on_disk: OnDiskVault = serde_json::from_slice(&raw).unwrap();
        let entry = on_disk.entries.get_mut(&v.to_string()).unwrap();
        let mut bytes = unb64(&entry.ciphertext_b64).unwrap();
        bytes.pop();
        entry.ciphertext_b64 = b64(&bytes);
        std::fs::write(vault.path(), serde_json::to_vec(&on_disk).unwrap()).unwrap();

        let v2 = Vault::new(vault.path().to_path_buf());
        v2.unlock("pw").unwrap();
        assert!(matches!(v2.get(&v), Err(AppError::Crypto(_))));
    }
}
