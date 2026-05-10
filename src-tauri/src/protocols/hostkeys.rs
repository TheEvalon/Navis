//! Pluggable host-key/cert trust store (TOFU).
//!
//! - SSH: file in `known_hosts`-style format, one record per host:port.
//! - RDP: JSON file mapping `host:port` to a SHA-256 cert thumbprint.
//!
//! Behavior:
//! - Unknown host: caller decides (UI prompt) and on confirmation calls
//!   [`SshKnownHosts::trust_on_first_use`] / [`RdpPinStore::pin`].
//! - Mismatch: hard failure unless the caller explicitly forces an update.
//!
//! On Windows, MobaXterm and PuTTY both maintain their own host-key stores;
//! we keep ours separate so unrelated changes elsewhere don't widen our
//! trust set.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::errors::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustOutcome {
    Trusted,
    Unknown,
    Mismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownSshHost {
    pub host: String,
    pub port: u16,
    /// Algorithm (e.g. `ssh-ed25519`).
    pub algo: String,
    /// Base64-encoded public key blob.
    pub key_b64: String,
}

pub struct SshKnownHosts {
    path: PathBuf,
}

impl SshKnownHosts {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn check(&self, host: &str, port: u16, algo: &str, key: &[u8]) -> AppResult<TrustOutcome> {
        let entries = self.read_all()?;
        let key_b64 = b64(key);
        let mut found_host = false;
        for e in &entries {
            if e.host == host && e.port == port {
                found_host = true;
                if e.algo == algo && e.key_b64 == key_b64 {
                    return Ok(TrustOutcome::Trusted);
                }
            }
        }
        Ok(if found_host {
            TrustOutcome::Mismatch
        } else {
            TrustOutcome::Unknown
        })
    }

    pub fn trust_on_first_use(
        &self,
        host: &str,
        port: u16,
        algo: &str,
        key: &[u8],
    ) -> AppResult<()> {
        let mut entries = self.read_all()?;
        let key_b64 = b64(key);
        if entries
            .iter()
            .any(|e| e.host == host && e.port == port && e.algo == algo)
        {
            return Err(AppError::InvalidInput(
                "host already has a key recorded; use update".into(),
            ));
        }
        entries.push(KnownSshHost {
            host: host.into(),
            port,
            algo: algo.into(),
            key_b64,
        });
        self.write_all(&entries)
    }

    pub fn list(&self) -> AppResult<Vec<KnownSshHost>> {
        self.read_all()
    }

    pub fn forget(&self, host: &str, port: u16) -> AppResult<()> {
        let mut entries = self.read_all()?;
        entries.retain(|e| !(e.host == host && e.port == port));
        self.write_all(&entries)
    }

    fn read_all(&self) -> AppResult<Vec<KnownSshHost>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&self.path)?;
        let mut out = Vec::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, ' ');
            let host_port = parts
                .next()
                .ok_or_else(|| AppError::Storage(format!("known_hosts:{}: empty", lineno + 1)))?;
            let algo = parts
                .next()
                .ok_or_else(|| AppError::Storage(format!("known_hosts:{}: no algo", lineno + 1)))?;
            let key_b64 = parts
                .next()
                .ok_or_else(|| AppError::Storage(format!("known_hosts:{}: no key", lineno + 1)))?;
            let (host, port) = parse_host_port(host_port)?;
            out.push(KnownSshHost {
                host,
                port,
                algo: algo.into(),
                key_b64: key_b64.into(),
            });
        }
        Ok(out)
    }

    fn write_all(&self, entries: &[KnownSshHost]) -> AppResult<()> {
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut text = String::new();
        text.push_str("# Navis known_hosts (one entry per host:port)\n");
        for e in entries {
            text.push_str(&format!("{}:{} {} {}\n", e.host, e.port, e.algo, e.key_b64));
        }
        write_atomic(&self.path, text.as_bytes())
    }
}

fn parse_host_port(s: &str) -> AppResult<(String, u16)> {
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| AppError::Storage(format!("bad host:port {s}")))?;
    let port: u16 = port_str
        .parse()
        .map_err(|e| AppError::Storage(format!("bad port {port_str}: {e}")))?;
    Ok((host.to_string(), port))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RdpPinStore {
    pins: BTreeMap<String, String>, // "host:port" -> sha256_hex
}

impl RdpPinStore {
    pub fn load(path: &Path) -> AppResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes).unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> AppResult<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        write_atomic(path, &bytes)
    }

    pub fn check(&self, host: &str, port: u16, cert_der: &[u8]) -> TrustOutcome {
        let key = format!("{host}:{port}");
        let thumb = sha256_hex(cert_der);
        match self.pins.get(&key) {
            Some(existing) if existing == &thumb => TrustOutcome::Trusted,
            Some(_) => TrustOutcome::Mismatch,
            None => TrustOutcome::Unknown,
        }
    }

    pub fn pin(&mut self, host: &str, port: u16, cert_der: &[u8]) {
        self.pins
            .insert(format!("{host}:{port}"), sha256_hex(cert_der));
    }

    pub fn forget(&mut self, host: &str, port: u16) {
        self.pins.remove(&format!("{host}:{port}"));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Internal(format!("path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        rand::random::<u32>()
    ));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn ssh_tofu_then_match_then_mismatch() {
        let g = TempDir::new().unwrap();
        let kh = SshKnownHosts::new(g.path().join("known_hosts"));
        let host = "h.example";
        let key = b"\x01\x02\x03";
        let key2 = b"\x99\x98";
        assert_eq!(
            kh.check(host, 22, "ssh-ed25519", key).unwrap(),
            TrustOutcome::Unknown
        );
        kh.trust_on_first_use(host, 22, "ssh-ed25519", key).unwrap();
        assert_eq!(
            kh.check(host, 22, "ssh-ed25519", key).unwrap(),
            TrustOutcome::Trusted
        );
        assert_eq!(
            kh.check(host, 22, "ssh-ed25519", key2).unwrap(),
            TrustOutcome::Mismatch
        );
    }

    #[test]
    fn ssh_known_hosts_parser_rejects_garbage() {
        let g = TempDir::new().unwrap();
        let kh_path = g.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            b"# comment\n\nincomplete-line\nhost-without-port ssh-rsa key=\nbad:port_str algo k\n",
        )
        .unwrap();
        let kh = SshKnownHosts::new(kh_path);
        assert!(kh.list().is_err());
    }

    #[test]
    fn rdp_pin_store_handles_corrupt_file() {
        let g = TempDir::new().unwrap();
        let p = g.path().join("rdp_pins.json");
        std::fs::write(&p, b"this is not json").unwrap();
        // load() falls back to empty; we explicitly accept this rather than
        // surfacing an error, so legitimate users aren't locked out by a
        // corrupted store.
        let store = RdpPinStore::load(&p).unwrap();
        assert_eq!(store.pins.len(), 0);
    }

    #[test]
    fn rdp_pin_then_check() {
        let g = TempDir::new().unwrap();
        let p = g.path().join("rdp_pins.json");
        let mut store = RdpPinStore::load(&p).unwrap();
        let cert = b"cert-bytes";
        assert_eq!(store.check("h", 3389, cert), TrustOutcome::Unknown);
        store.pin("h", 3389, cert);
        store.save(&p).unwrap();

        let store2 = RdpPinStore::load(&p).unwrap();
        assert_eq!(store2.check("h", 3389, cert), TrustOutcome::Trusted);
        assert_eq!(
            store2.check("h", 3389, b"different"),
            TrustOutcome::Mismatch
        );
    }
}
