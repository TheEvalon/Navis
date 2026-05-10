# Navis architecture

This document describes how Navis is organized end-to-end. It is the source of truth for module boundaries; if behavior changes, update the relevant section here.

## Process model

Navis runs as a single Tauri 2 desktop application:

- **Main process (Rust):** owns the database, vault, keychain, and protocol engines. Exposes a typed IPC surface.
- **Renderer (Chromium webview):** React + TypeScript UI. Cannot read or write the filesystem directly. Cannot spawn processes. Talks to the main process exclusively through `tauri::generate_handler!` commands.

```text
+----------------------+        IPC (typed, capability-scoped)        +-------------------------+
| React UI             | <-------------------------------------------> | Rust backend            |
|                      |                                               |                         |
| - Tree / editor      |          tauri::invoke / tauri::emit          | core::registry  (SQLite)|
| - Vault gate         |                                               | core::vault     (AES)   |
| - Credentials panel  |                                               | core::keychain          |
| - Trust store panel  |                                               | core::policy            |
| - Terminal (xterm.js)|                                               | protocols::ssh / sftp / rdp |
+----------------------+                                               +-------------------------+
                                                                                  |
                                                                                  v
                                                                         +-------------------+
                                                                         | OS keychain       |
                                                                         | filesystem (data) |
                                                                         | network (SSH/RDP) |
                                                                         +-------------------+
```

## Filesystem layout

```text
<app_data_dir>/
  navis.db          # SQLite metadata (folders, connections, credential refs)
  vault.bin         # encrypted vault (AES-256-GCM blobs, Argon2id-wrapped DEK)
  keys/
    known_hosts     # SSH TOFU
    rdp_pins.json   # RDP cert pins
  logs/
```

The renderer never sees absolute paths to these files; the backend resolves them via `core::paths::AppPaths`.

## Module map

```text
src-tauri/src/
├── lib.rs               # tauri::Builder wiring
├── main.rs              # binary entrypoint
├── core/
│   ├── errors.rs        # AppError tagged into IPC
│   ├── ids.rs           # FolderId / ConnectionId / ... (UUID newtypes)
│   ├── keychain.rs      # OS keychain wrapper (DEK convenience-wrap)
│   ├── paths.rs         # filesystem layout
│   ├── policy.rs        # effective credential resolution
│   ├── registry.rs      # SQLite-backed CRUD
│   ├── state.rs         # AppState managed by Tauri
│   └── vault.rs         # AES-256-GCM secret store
├── protocols/
│   ├── hostkeys.rs      # SshKnownHosts + RdpPinStore
│   ├── ssh.rs           # russh-based SSH client
│   ├── sftp.rs          # SFTP types + path validation
│   ├── rdp.rs           # RDP options + cert policy
│   └── session.rs       # SessionHandle / SessionEvent / SessionInput
└── ipc/
    ├── mod.rs           # generate_handler! wiring
    └── commands/
        ├── registry.rs
        ├── vault.rs
        ├── sessions.rs
        └── hostkeys.rs

src/                     # React frontend
├── App.tsx              # entrypoint
├── layout/Shell.tsx     # header + sidebar + main
├── store/app.ts         # zustand app store
├── ipc/{client.ts, types.ts}
└── features/
    ├── tree/            # connection tree (react-arborist)
    ├── connections/     # form editor
    ├── credentials/     # vault-aware credential UI
    ├── vault/           # unlock / setup gate
    ├── trust/           # known_hosts + RDP pins UI
    └── sessions/        # tabs + xterm-backed terminal
```

## Data model

```text
Folder
  id           : UUID
  parent_id    : Option<FolderId>
  name         : String
  default_credential_id : Option<CredentialId>
  sort_order   : i64

Connection
  id           : UUID
  folder_id    : Option<FolderId>
  name         : String
  protocol     : ssh | sftp | rdp
  host, port, username
  credential_id: Option<CredentialId>
  options      : JSON

CredentialProfile
  id           : UUID
  name         : String
  kind         : password | ssh_private_key | rdp_password | certificate | ...
  username     : Option<String>
  vault_ref    : VaultRef          # opaque pointer into vault.bin

VaultEntry (on disk only)
  vault_ref    : UUID
  kind         : SecretKind
  nonce        : 12 bytes
  ciphertext   : AES-256-GCM(plaintext, AAD = magic || vault_ref || kind)
```

### Effective credential resolution

```text
resolve_credential(connection):
    if connection.credential_id is set      -> use it
    else walk up folder ancestry:
        first folder.default_credential_id  -> use it
    else return None (UI will prompt before connect)
```

Cycle detection guards against malformed parent_id chains.

## Protocol engines

### SSH

`protocols::ssh::connect` opens a `russh::client` session, verifies the host key against `SshKnownHosts`, authenticates with the resolved credential, opens a PTY-backed channel, and bridges stdin/stdout to the renderer through an `mpsc<SessionEvent>` channel that becomes a Tauri event stream (`navis:session`).

- Host-key flow: a strict TOFU policy. Unknown hosts cause the connection to fail; the UI then offers "Trust this host" which calls `ssh_trust_host`. A subsequent connect succeeds. Mismatches fail loudly.
- Credentials: only ever read inside the backend; the renderer hands over `vault_ref` via `start_session`.

### SFTP

Reuses the SSH transport. Phase 4 wires `russh-sftp` to a transfer queue. The current code defines wire types and the `validate_relative_path` policy used by the file-browser commands.

### RDP

Backed by `ironrdp`. The current code defines the public surface (`RdpOptions`, frame format, certificate pinning) so the IPC layer is stable. Phase 5 wires the actual `ironrdp` client and renders frames into a `<canvas>` in the renderer. NLA is required by default; downgrades require an explicit option that the UI gates behind a confirmation.

## IPC surface

All commands live in `src-tauri/src/ipc/commands/`. They:

1. Take only typed `Deserialize` payloads or `tauri::State<AppState>` / `tauri::AppHandle`.
2. Return `AppResult<T>` where `AppError` is serialized as `{ kind, message }` so the renderer can switch on `kind`.
3. Never return decrypted secret material.

## Future extension points (out of scope for v1)

- Telnet, FTP, VNC, Serial, Mosh — slot under `protocols::*`.
- X11 forwarding, port-forward GUI, jump-host chains — extend SSH options + UI.
- Team sync / cloud vault — the vault encrypts with a DEK that can be re-wrapped against a team key.
- PKCS#11 / FIDO2 hardware keys — extend `SshAuth`.
- ssh-agent / Pageant — already stubbed in `SshAuth::Agent`.
