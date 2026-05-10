# Navis threat model

This document lists the assets we protect, the adversaries we consider, what is in and out of scope for v1, and how each threat is addressed.

## Assets

| Asset | Description |
| --- | --- |
| Master password | Never persisted; controls access to the vault. |
| Vault DEK | 256-bit symmetric key, in memory while unlocked. |
| Stored credentials | Passwords, SSH keys, RDP passwords, certificates. |
| Connection metadata | Hostnames, ports, usernames, options. |
| Host trust store | SSH known_hosts and RDP cert pins. |
| User session bytes | Plaintext SSH terminal output, file transfers, RDP frames. |

## Adversaries

| Adversary | Capabilities |
| --- | --- |
| Casual disk reader | Reads files in `app_data_dir`, e.g. via stolen disk image. |
| Same-host malware (user-level) | Reads/writes files Navis can read; can inject into our process if no integrity protection. |
| Network MITM | Sees and tampers with traffic between Navis and remote servers. |
| Compromised remote host | Replays old keys or presents a fresh-but-rogue key/cert. |
| Renderer XSS via malicious data | Hostile data flows in via imported bundles or remote responses. |

## Threats and mitigations

| # | Threat | Mitigation |
| --- | --- | --- |
| T1 | Disk thief reads `vault.bin` | All entries are AES-256-GCM-encrypted; the DEK is wrapped with an Argon2id-stretched master password. |
| T2 | Attacker swaps two ciphertexts inside `vault.bin` | AAD binds each entry to its `vault_ref` and `kind`; reinterpretation fails AEAD verification. |
| T3 | Attacker substitutes the entire `vault.bin` with an old copy | Not mitigated in v1 (rollback). Documented as future work; mitigated partially by the user's master password being different per vault. |
| T4 | Reading or modifying `navis.db` | Metadata only; contains no secret material. Imports must pass schema validation. |
| T5 | Reading the OS keychain entry | Holds at most a randomly generated wrap key. Without the keychain entry, the master password is still required. |
| T6 | Tampering with `known_hosts` | A real attacker who can write our files could impersonate a server. The trust store is only meaningful on a trusted endpoint; we treat tampering as out of scope. |
| T7 | Network MITM during SSH | russh enforces transport integrity and authenticity. Host-key TOFU prevents silent first-time MITM only if the user is careful at first contact. |
| T8 | Network MITM during RDP | NLA required by default; cert thumbprint pin per host:port. |
| T9 | Compromised remote rotates SSH host key | Mismatch aborts the connection; user must explicitly `forget` and re-trust. |
| T10 | Renderer compromise via supplied data | Strict CSP, no `fs`/`shell` capabilities, all writes go through validated typed commands, no plaintext secrets ever sent to renderer. |
| T11 | Memory disclosure (cold boot, swap, core dump) | Secrets held in `Zeroizing` buffers and zeroed on lock or drop. We do not currently mlock pages. |
| T12 | Update-channel poisoning | Updates are downloaded only from the configured updater endpoint and verified with a public key pinned at build time. |
| T13 | Supply-chain attack on dependencies | Pinned versions in `Cargo.toml` / `package.json`. CI runs `cargo audit` and `npm audit` (Phase 8). |
| T14 | Plaintext password disclosure in logs | Logging policy: no secret material is ever included; `Zeroize` types do not implement `Debug`/`Display` of secret bytes. |
| T15 | UI-driven secret exposure | The `vault_get_secret` command is intentionally not exposed to the renderer. Only the connect path reads from the vault, and only inside the backend. |

## Out of scope for v1

- Hardened against root-level malware on the same machine.
- Side-channel resistant cryptography (timing, cache).
- Endpoint integrity attestation.
- Defending against a malicious build of Navis itself (use signed releases).

## Future hardening

- Memory locking (`mlock`) for DEK pages.
- Optional FIDO2/PKCS#11-protected vault unlock.
- Per-connection 2FA / OTP plumbing.
- Vault rollback protection via a monotonic counter persisted in the OS keychain.
