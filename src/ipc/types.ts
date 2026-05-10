export type FolderId = string;
export type ConnectionId = string;
export type CredentialId = string;
export type VaultRef = string;
export type SessionId = string;

export type Protocol = "ssh" | "sftp" | "rdp";

export type SecretKind =
  | "password"
  | "ssh_private_key"
  | "ssh_key_passphrase"
  | "rdp_password"
  | "certificate"
  | "generic";

export interface Folder {
  id: FolderId;
  parent_id: FolderId | null;
  name: string;
  default_credential_id: CredentialId | null;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface FolderInput {
  parent_id: FolderId | null;
  name: string;
  default_credential_id: CredentialId | null;
  sort_order?: number | null;
}

export interface Connection {
  id: ConnectionId;
  folder_id: FolderId | null;
  name: string;
  protocol: Protocol;
  host: string;
  port: number;
  username: string | null;
  credential_id: CredentialId | null;
  options: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ConnectionInput {
  folder_id: FolderId | null;
  name: string;
  protocol: Protocol;
  host: string;
  port?: number | null;
  username?: string | null;
  credential_id?: CredentialId | null;
  options?: Record<string, unknown> | null;
}

export interface CredentialProfile {
  id: CredentialId;
  name: string;
  kind: SecretKind;
  username: string | null;
  vault_ref: VaultRef;
  created_at: string;
  updated_at: string;
}

export interface CredentialProfileInput {
  name: string;
  kind: SecretKind;
  username?: string | null;
  vault_ref: VaultRef;
}

export interface ExportBundle {
  version: number;
  folders: Folder[];
  connections: Connection[];
  credentials: CredentialProfile[];
}

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
}

export interface PutSecretInput {
  kind: SecretKind;
  plaintext: string;
}

export interface VaultEntrySummary {
  vault_ref: VaultRef;
  kind: SecretKind;
  size_bytes: number;
}

export interface KnownSshHost {
  host: string;
  port: number;
  algo: string;
  key_b64: string;
}

export interface RdpPin {
  host: string;
  port: number;
  thumbprint_sha256: string;
}

export type SessionState = "connecting" | "connected" | "disconnected" | "failed";

export interface SessionListItem {
  id: SessionId;
  connection_id: ConnectionId;
  kind: "ssh" | "sftp" | "rdp";
  state: SessionState;
}

export type StartedSession =
  | { kind: "in_app"; session_id: SessionId }
  | { kind: "external"; client: string; credentials_prefilled: boolean };

export type SessionEvent =
  | { type: "output"; session_id: SessionId; data: number[] }
  | { type: "state"; session_id: SessionId; state: SessionState; message: string | null }
  | {
      type: "transfer_progress";
      session_id: SessionId;
      transfer_id: string;
      bytes: number;
      total: number | null;
    };
