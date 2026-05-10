//! RDP engine.
//!
//! Two delivery paths share this module:
//!
//! 1. **External-client launcher (current default).** Spawns the platform's
//!    native RDP client (`mstsc.exe` on Windows, `xfreerdp` on Linux,
//!    `open` on macOS) with the connection details prefilled and the
//!    decrypted password handed to the OS credential store for the host
//!    so the client doesn't prompt. The session opens in its own window
//!    rather than embedded in Navis. Used by `start_session` for
//!    `Protocol::Rdp` until the embedded client lands.
//! 2. **Embedded `ironrdp` client (planned).** Frames pushed to a renderer
//!    canvas as raw RGBA, clipboard sync via the cliprdr channel, NLA on
//!    by default, cert thumbprints pinned via
//!    [`crate::protocols::hostkeys::RdpPinStore`]. The
//!    [`RdpFrame`]/`RdpOptions` types and validation logic below are the
//!    drop-in surface for that integration.
//!
//! NLA is required by default; downgrades are refused unless the
//! connection options explicitly opt in via the validated options.

use std::process::Command;

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use tracing::{info, warn};
use zeroize::Zeroizing;

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

/// Inputs to the external-client launcher.
pub struct ExternalLaunch<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub domain: Option<&'a str>,
    /// Decrypted password. Held in a `Zeroizing` buffer; we hand it to the
    /// OS credential store and then drop our copy.
    pub password: Option<Zeroizing<Vec<u8>>>,
    pub options: &'a RdpOptions,
}

/// What the launcher returns to the UI so it can show "launched in the
/// system RDP client" messaging instead of treating it as a connected
/// in-app session.
#[derive(Debug, Clone, Serialize)]
pub struct ExternalLaunched {
    /// Human-readable label for the renderer.
    pub client: String,
    /// Whether credentials were prefilled. If `false` the user will see a
    /// password prompt in the external client.
    pub credentials_prefilled: bool,
}

/// Spawn the platform's native RDP client. The session opens in its own
/// window; Navis does not own the lifecycle once the spawn returns. The
/// password (if provided) is wiped from our process before this function
/// returns.
#[allow(clippy::needless_return)] // explicit `return` reads more clearly across `cfg` arms
pub fn launch_external(launch: ExternalLaunch<'_>) -> AppResult<ExternalLaunched> {
    validate_options(launch.options)?;
    let qualified_user = match launch.domain.filter(|d| !d.is_empty()) {
        Some(domain) => format!("{}\\{}", domain, launch.user),
        None => launch.user.to_string(),
    };

    let password_slice: Option<&[u8]> = launch.password.as_ref().map(|p| p.as_slice());

    #[cfg(target_os = "windows")]
    {
        let target = format!("{}:{}", launch.host, launch.port);
        return launch_mstsc(&target, &qualified_user, launch.host, password_slice);
    }

    #[cfg(target_os = "linux")]
    {
        return launch_xfreerdp(
            launch.host,
            launch.port,
            &qualified_user,
            launch.domain,
            password_slice,
            launch.options,
        );
    }

    #[cfg(target_os = "macos")]
    {
        let _ = qualified_user;
        return launch_macos(
            launch.host,
            launch.port,
            launch.user,
            launch.domain,
            password_slice,
        );
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (qualified_user, password_slice);
        Err(AppError::Protocol(
            "no external RDP client launcher is wired up for this platform".into(),
        ))
    }
}

#[cfg(target_os = "windows")]
fn launch_mstsc(
    target: &str,
    user: &str,
    host: &str,
    password: Option<&[u8]>,
) -> AppResult<ExternalLaunched> {
    // mstsc reads credentials from Windows Credential Manager keyed by
    // `TERMSRV/<host>`. Pre-seed the entry with cmdkey, then schedule a
    // best-effort delete after a short delay so the password isn't
    // persisted long-term. `cmdkey` reads `/pass:` from the command line,
    // which is the documented path and is what other connection managers
    // (Royal TS, mRemoteNG) use.
    let mut prefilled = false;
    if let Some(pw) = password {
        let pw_str = std::str::from_utf8(pw).map_err(|_| {
            AppError::InvalidInput("rdp password must be valid UTF-8 for cmdkey".into())
        })?;
        let status = Command::new("cmdkey")
            .arg(format!("/generic:TERMSRV/{}", host))
            .arg(format!("/user:{}", user))
            .arg(format!("/pass:{}", pw_str))
            .status();
        match status {
            Ok(s) if s.success() => {
                prefilled = true;
                info!("cmdkey seeded TERMSRV/{} for mstsc", host);
            }
            Ok(s) => warn!("cmdkey exited with status {s}; mstsc will prompt"),
            Err(e) => warn!("cmdkey not found ({e}); mstsc will prompt"),
        }
    }

    let host_owned = host.to_string();
    Command::new("mstsc")
        .arg("/v")
        .arg(target)
        .spawn()
        .map_err(|e| AppError::Protocol(format!("spawn mstsc: {e}")))?;

    if prefilled {
        // Best-effort: remove the credential entry shortly after launch so
        // the password isn't left in Credential Manager. mstsc has already
        // read it by then.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(20));
            let _ = Command::new("cmdkey")
                .arg(format!("/delete:TERMSRV/{}", host_owned))
                .status();
        });
    }

    Ok(ExternalLaunched {
        client: "mstsc.exe".into(),
        credentials_prefilled: prefilled,
    })
}

#[cfg(target_os = "linux")]
fn launch_xfreerdp(
    host: &str,
    port: u16,
    user: &str,
    domain: Option<&str>,
    password: Option<&[u8]>,
    options: &RdpOptions,
) -> AppResult<ExternalLaunched> {
    // xfreerdp accepts /v, /u, /d, /p; /size and /cert are best-effort.
    // Password leaks into the process argv; for v0.1.x we accept this and
    // document it. The embedded ironrdp client doesn't have this issue.
    let exe = ["xfreerdp3", "xfreerdp"]
        .iter()
        .find(|name| ::which::which(name).is_ok())
        .copied()
        .ok_or_else(|| {
            AppError::Protocol(
                "xfreerdp not found on PATH (install freerdp2-x11 / freerdp3-x11)".into(),
            )
        })?;

    let mut cmd = Command::new(exe);
    cmd.arg(format!("/v:{}:{}", host, port));
    cmd.arg(format!("/u:{}", user));
    if let Some(d) = domain.filter(|d| !d.is_empty()) {
        cmd.arg(format!("/d:{}", d));
    }
    cmd.arg(format!("/size:{}x{}", options.width, options.height));
    cmd.arg(format!("/bpp:{}", options.color_depth));
    cmd.arg("/cert:tofu");
    if options.clipboard {
        cmd.arg("+clipboard");
    }

    let mut prefilled = false;
    if let Some(pw) = password {
        let pw_str = std::str::from_utf8(pw)
            .map_err(|_| AppError::InvalidInput("rdp password must be valid UTF-8".into()))?;
        cmd.arg(format!("/p:{}", pw_str));
        prefilled = true;
    }

    cmd.spawn()
        .map_err(|e| AppError::Protocol(format!("spawn xfreerdp: {e}")))?;
    Ok(ExternalLaunched {
        client: exe.to_string(),
        credentials_prefilled: prefilled,
    })
}

#[cfg(target_os = "macos")]
fn launch_macos(
    host: &str,
    port: u16,
    user: &str,
    domain: Option<&str>,
    password: Option<&[u8]>,
) -> AppResult<ExternalLaunched> {
    // macOS doesn't have a CLI counterpart to mstsc and Microsoft Remote
    // Desktop's URL scheme is private. We write a transient .rdp file in
    // the user's temp dir and `open` it; the user authenticates in the
    // Microsoft Remote Desktop UI on first connect. Password prefill is
    // not supported via the .rdp file format reliably, so we skip it.
    let _ = password;

    let domain_part = domain.filter(|d| !d.is_empty()).unwrap_or("");
    let full_username = if domain_part.is_empty() {
        user.to_string()
    } else {
        format!("{}\\{}", domain_part, user)
    };

    let rdp_body = format!(
        "full address:s:{host}:{port}\nusername:s:{full_username}\n\
         prompt for credentials:i:1\nauthentication level:i:2\n",
    );
    let mut path = std::env::temp_dir();
    path.push(format!(
        "navis-{}-{}.rdp",
        host.replace([':', '/'], "_"),
        std::process::id()
    ));
    std::fs::write(&path, rdp_body)?;

    Command::new("open")
        .arg(&path)
        .spawn()
        .map_err(|e| AppError::Protocol(format!("spawn open: {e}")))?;
    Ok(ExternalLaunched {
        client: "Microsoft Remote Desktop".into(),
        credentials_prefilled: false,
    })
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
