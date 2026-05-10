//! RDP engine.
//!
//! Architecture:
//! - The protocol/decoding layer is implemented with `ironrdp` (added behind
//!   a feature so the crate tree compiles without it during early phases).
//! - Frames are pushed to the renderer as raw RGBA tiles via Tauri events.
//! - Cert thumbprints are pinned via [`crate::protocols::hostkeys::RdpPinStore`].
//! - NLA (Network Level Authentication) is required by default; downgrades
//!   are refused unless the connection options explicitly opt in.
//!
//! This module currently exposes the public types and trust-policy logic
//! that the IPC layer relies on. The full ironrdp wiring is a Phase 5
//! deliverable; the surface below makes that integration drop-in.

use serde::{Deserialize, Serialize};

use crate::core::errors::{AppError, AppResult};
use crate::protocols::hostkeys::{RdpPinStore, TrustOutcome};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RdpOptions {
    /// Resolution width in pixels.
    #[serde(default = "default_width")]
    pub width: u32,
    /// Resolution height in pixels.
    #[serde(default = "default_height")]
    pub height: u32,
    /// Color depth (16/24/32).
    #[serde(default = "default_depth")]
    pub color_depth: u32,
    /// Require NLA. Defaults to true; cannot be disabled without an explicit
    /// override in the connection options.
    #[serde(default = "default_true")]
    pub require_nla: bool,
    /// Forward clipboard.
    #[serde(default = "default_true")]
    pub clipboard: bool,
    /// Domain (optional).
    #[serde(default)]
    pub domain: Option<String>,
}

fn default_width() -> u32 {
    1280
}
fn default_height() -> u32 {
    800
}
fn default_depth() -> u32 {
    24
}
fn default_true() -> bool {
    true
}

impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            width: default_width(),
            height: default_height(),
            color_depth: default_depth(),
            require_nla: true,
            clipboard: true,
            domain: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RdpFrame {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Pixel format (always `rgba8`).
    pub format: &'static str,
    /// Raw RGBA bytes, length = width * height * 4.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Decision returned by the trust check.
pub enum CertCheck {
    Trusted,
    NeedsConfirmation,
    Mismatch,
}

pub fn check_certificate(pins: &RdpPinStore, host: &str, port: u16, cert_der: &[u8]) -> CertCheck {
    match pins.check(host, port, cert_der) {
        TrustOutcome::Trusted => CertCheck::Trusted,
        TrustOutcome::Unknown => CertCheck::NeedsConfirmation,
        TrustOutcome::Mismatch => CertCheck::Mismatch,
    }
}

/// Validates the renderer-supplied options before we start a session.
pub fn validate_options(opts: &RdpOptions) -> AppResult<()> {
    if !(640..=7680).contains(&opts.width) || !(480..=4320).contains(&opts.height) {
        return Err(AppError::InvalidInput("rdp resolution out of range".into()));
    }
    if !matches!(opts.color_depth, 16 | 24 | 32) {
        return Err(AppError::InvalidInput(
            "rdp color depth must be 16/24/32".into(),
        ));
    }
    if !opts.require_nla {
        // Reject silently-disabled NLA. The UI must pass a confirmed override.
        return Err(AppError::InvalidInput(
            "NLA must remain enabled (security policy)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_bad_options() {
        let opts = RdpOptions {
            width: 100,
            ..Default::default()
        };
        assert!(validate_options(&opts).is_err());

        let opts = RdpOptions {
            color_depth: 8,
            ..Default::default()
        };
        assert!(validate_options(&opts).is_err());

        let opts = RdpOptions {
            require_nla: false,
            ..Default::default()
        };
        assert!(validate_options(&opts).is_err());

        let ok = RdpOptions::default();
        assert!(validate_options(&ok).is_ok());
    }
}
