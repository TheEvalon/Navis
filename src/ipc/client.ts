import { invoke as rawInvoke } from "@tauri-apps/api/core";
import type {
  Connection,
  ConnectionInput,
  CredentialId,
  CredentialProfile,
  CredentialProfileInput,
  ExportBundle,
  Folder,
  FolderInput,
  ConnectionId,
  KnownSshHost,
  PutSecretInput,
  RdpPin,
  SecretKind,
  SessionListItem,
  StartedSession,
  VaultEntrySummary,
  VaultStatus,
  VaultRef,
} from "./types";

export class IpcError extends Error {
  kind: string;
  constructor(kind: string, message: string) {
    super(message);
    this.kind = kind;
    this.name = "IpcError";
  }
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return (await rawInvoke<T>(cmd, args)) as T;
  } catch (err) {
    if (err && typeof err === "object" && "kind" in err && "message" in err) {
      const e = err as { kind: string; message: string };
      throw new IpcError(e.kind, e.message);
    }
    throw new IpcError("Unknown", String(err));
  }
}

export const api = {
  // ---- Folders / connections / credentials
  listFolders: () => invoke<Folder[]>("list_folders"),
  createFolder: (input: FolderInput) => invoke<Folder>("create_folder", { input }),
  updateFolder: (id: string, input: FolderInput) => invoke<Folder>("update_folder", { id, input }),
  deleteFolder: (id: string) => invoke<void>("delete_folder", { id }),

  listConnections: () => invoke<Connection[]>("list_connections"),
  createConnection: (input: ConnectionInput) => invoke<Connection>("create_connection", { input }),
  updateConnection: (id: ConnectionId, input: ConnectionInput) =>
    invoke<Connection>("update_connection", { id, input }),
  deleteConnection: (id: ConnectionId) => invoke<void>("delete_connection", { id }),

  listCredentials: () => invoke<CredentialProfile[]>("list_credentials"),
  createCredential: (input: CredentialProfileInput) =>
    invoke<CredentialProfile>("create_credential", { input }),
  updateCredential: (id: CredentialId, input: CredentialProfileInput) =>
    invoke<CredentialProfile>("update_credential", { id, input }),
  deleteCredential: (id: CredentialId) => invoke<void>("delete_credential", { id }),

  resolveCredential: (connectionId: ConnectionId) =>
    invoke<CredentialId | null>("resolve_credential", { connectionId }),

  exportBundle: () => invoke<ExportBundle>("export_bundle"),
  importBundle: (bundle: ExportBundle) => invoke<void>("import_bundle", { bundle }),

  // ---- Vault
  vaultStatus: () => invoke<VaultStatus>("vault_status"),
  vaultInitialize: (masterPassword: string) => invoke<void>("vault_initialize", { masterPassword }),
  vaultUnlock: (masterPassword: string) => invoke<void>("vault_unlock", { masterPassword }),
  vaultLock: () => invoke<void>("vault_lock"),
  vaultPutSecret: (input: PutSecretInput) => invoke<VaultRef>("vault_put_secret", { input }),
  vaultDeleteSecret: (vaultRef: VaultRef) => invoke<void>("vault_delete_secret", { vaultRef }),
  vaultListEntries: () => invoke<VaultEntrySummary[]>("vault_list_entries"),

  // ---- Sessions
  startSession: (connectionId: ConnectionId) =>
    invoke<StartedSession>("start_session", { connectionId }),
  sendInput: (sessionId: string, data: number[]) => invoke<void>("send_input", { sessionId, data }),
  resizeSession: (sessionId: string, cols: number, rows: number) =>
    invoke<void>("resize_session", { sessionId, cols, rows }),
  closeSession: (sessionId: string) => invoke<void>("close_session", { sessionId }),
  listSessions: () => invoke<SessionListItem[]>("list_sessions"),

  // ---- Trust stores
  sshKnownHosts: () => invoke<KnownSshHost[]>("ssh_known_hosts"),
  sshTrustHost: (input: { host: string; port: number; algo: string; keyB64: string }) =>
    invoke<void>("ssh_trust_host", {
      input: { host: input.host, port: input.port, algo: input.algo, key_b64: input.keyB64 },
    }),
  sshForgetHost: (host: string, port: number) =>
    invoke<void>("ssh_forget_host", { input: { host, port } }),

  rdpPinnedHosts: () => invoke<RdpPin[]>("rdp_pinned_hosts"),
  rdpPinHost: (input: { host: string; port: number; certDerB64: string }) =>
    invoke<void>("rdp_pin_host", {
      input: { host: input.host, port: input.port, cert_der_b64: input.certDerB64 },
    }),
  rdpForgetHost: (host: string, port: number) =>
    invoke<void>("rdp_forget_host", { input: { host, port } }),
};

export type { SecretKind };
