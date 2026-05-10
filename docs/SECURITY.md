# Navis security guide

Navis stores sensitive material — connection metadata, credentials, host keys — and it speaks remote-administration protocols. The backend is built so that a compromise of the renderer alone is contained, and so that an attacker with read-only access to disk cannot derive credentials.

## Trust boundaries

| Boundary | Privileges |
| --- | --- |
| Renderer (webview) | Restricted CSP. No `fs`/`shell` capabilities. Talks only to typed IPC commands. Receives opaque ids; never receives plaintext secrets. |
| Backend (Rust) | Full local FS for `app_data_dir`, OS keychain access, network access for SSH/RDP. |
| OS keychain | Optional convenience storage for the DEK wrap key. |

## Cryptography

| Where | Primitive | Parameters |
| --- | --- | --- |
| Master password → KEK | Argon2id | m=64 MiB, t=3, p=1, 32-byte output |
| KEK wraps DEK | AES-256-GCM | random 96-bit nonce, AAD = vault magic |
| DEK encrypts each entry | AES-256-GCM | random 96-bit nonce, AAD = magic ‖ vault_ref ‖ kind |
| Host-key store | text record | algorithm + base64 key blob |
| RDP cert pinning | SHA-256 thumbprint | hex-encoded |

The DEK lives only in memory while the vault is unlocked. It is held in a `Zeroizing<[u8; 32]>` and dropped on `vault_lock`, on app exit, and on idle auto-lock.

The AAD on entries binds `vault_ref` and `kind` to the ciphertext, so an attacker who can swap entries on disk cannot reinterpret a stored RDP password as, say, a recovery code.

## Authentication options

| Method | Notes |
| --- | --- |
| SSH password | Stored as `SecretKind::Password`. Sent only to the negotiated SSH transport. |
| SSH private key | Stored as `SecretKind::SshPrivateKey` (PEM bytes). Decoded with optional passphrase at session start. |
| ssh-agent / Pageant | API surface present (`SshAuth::Agent`); wiring lands in a follow-up. |
| RDP password / NLA | Stored as `SecretKind::RdpPassword`. NLA enforced by default. |
| Certificate | `SecretKind::Certificate`. Reserved for OpenSSH user certs and RDP smart cards. |

## Host trust

- **SSH:** trust-on-first-use with explicit user confirmation. Mismatches abort the connection and require a manual `ssh_forget_host` before retrying.
- **RDP:** SHA-256 thumbprint pin per `host:port`. Mismatch aborts; we never silently accept renewed certificates.

## IPC hardening

- The Tauri capability allowlist explicitly excludes `core:fs:*`, `core:shell:*`, `core:http:*`, and the asset protocol scope is empty.
- All command parameters are deserialized into typed Rust structs, then validated. Names, hosts, paths, ports, and resolutions are checked before they reach storage or the network.
- Errors are returned as `{ kind, message }`. We avoid leaking stack traces or path details to the renderer.

## Logging

- `tracing` with an env-filterable level. Default `info,navis_lib=debug`.
- Credentials are never logged. The vault and keychain modules use `Zeroizing` buffers and never `Debug`-print secret material.
- Connection logs include host, port, protocol, user, and outcome. They do not include passwords or key material.

## Update channel

- Tauri's signed updater is wired up in Phase 7. The public key is pinned at build time in the Tauri config; release artifacts are signed with the matching private key kept offline.
- Windows: Authenticode-signed `.msi` / `.exe`. macOS: notarized `.dmg` (Phase 7). Linux: signed `AppImage` and `.deb` (Phase 7).

## What we explicitly do **not** do

- We do not store master passwords.
- We do not transmit telemetry. There are no analytics endpoints in the build.
- We do not auto-trust SSH host-key changes or RDP certificate changes — ever.
- We do not enable the `asset:` protocol.

## Reporting issues

Open a private security report via your usual channel. Until then, please do not file public issues for vulnerabilities.
