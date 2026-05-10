import { useEffect, useMemo, useState } from "react";
import { useAppStore } from "../../store/app";
import { api, IpcError } from "../../ipc/client";
import type { Connection, ConnectionInput, CredentialId, Folder, Protocol } from "../../ipc/types";
import "./editor.css";

interface FormState {
  folder_id: string | null;
  name: string;
  protocol: Protocol;
  host: string;
  port: string;
  username: string;
  credential_id: string | null;
  options_json: string;
}

function defaultPort(p: Protocol): number {
  return p === "rdp" ? 3389 : 22;
}

export function ConnectionEditor() {
  const selected = useAppStore((s) => s.selected);
  const folders = useAppStore((s) => s.folders);
  const connections = useAppStore((s) => s.connections);
  const credentials = useAppStore((s) => s.credentials);
  const refresh = useAppStore((s) => s.refresh);
  const vault = useAppStore((s) => s.vault);

  const target: Connection | Folder | null = useMemo(() => {
    if (!selected) return null;
    if (selected.kind === "folder") return folders.find((f) => f.id === selected.id) ?? null;
    return connections.find((c) => c.id === selected.id) ?? null;
  }, [selected, folders, connections]);

  if (!target) {
    return (
      <div className="empty-state">
        <p>Select a connection or folder, or create a new one.</p>
      </div>
    );
  }

  if (selected?.kind === "folder") {
    return <FolderEditor folder={target as Folder} onChange={refresh} />;
  }

  return (
    <ConnectionForm
      key={target.id}
      connection={target as Connection}
      folders={folders}
      credentials={credentials}
      vaultUnlocked={vault.unlocked}
      onChange={refresh}
    />
  );
}

function FolderEditor({ folder, onChange }: { folder: Folder; onChange: () => Promise<void> }) {
  const credentials = useAppStore((s) => s.credentials);
  const [name, setName] = useState(folder.name);
  const [defaultCred, setDefaultCred] = useState<string | null>(folder.default_credential_id);
  useEffect(() => {
    setName(folder.name);
    setDefaultCred(folder.default_credential_id);
  }, [folder.id, folder.name, folder.default_credential_id]);
  return (
    <form
      className="editor"
      onSubmit={async (e) => {
        e.preventDefault();
        await api.updateFolder(folder.id, {
          parent_id: folder.parent_id,
          name,
          default_credential_id: defaultCred as CredentialId | null,
          sort_order: folder.sort_order,
        });
        await onChange();
      }}
    >
      <h2>Folder</h2>
      <div className="field">
        <label>Name</label>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="field">
        <label>Default credential (inherited by connections without their own)</label>
        <select value={defaultCred ?? ""} onChange={(e) => setDefaultCred(e.target.value || null)}>
          <option value="">— none —</option>
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} ({c.kind})
            </option>
          ))}
        </select>
      </div>
      <div className="row">
        <button type="submit" className="primary">
          Save folder
        </button>
        <button
          type="button"
          className="danger"
          onClick={async () => {
            if (!window.confirm(`Delete folder "${folder.name}"?`)) return;
            await api.deleteFolder(folder.id);
            await onChange();
          }}
        >
          Delete folder
        </button>
      </div>
    </form>
  );
}

function ConnectionForm({
  connection,
  folders,
  credentials,
  vaultUnlocked,
  onChange,
}: {
  connection: Connection;
  folders: Folder[];
  credentials: import("../../ipc/types").CredentialProfile[];
  vaultUnlocked: boolean;
  onChange: () => Promise<void>;
}) {
  const [form, setForm] = useState<FormState>({
    folder_id: connection.folder_id,
    name: connection.name,
    protocol: connection.protocol,
    host: connection.host,
    port: String(connection.port),
    username: connection.username ?? "",
    credential_id: connection.credential_id,
    options_json: JSON.stringify(connection.options ?? {}, null, 2),
  });

  useEffect(() => {
    setForm({
      folder_id: connection.folder_id,
      name: connection.name,
      protocol: connection.protocol,
      host: connection.host,
      port: String(connection.port),
      username: connection.username ?? "",
      credential_id: connection.credential_id,
      options_json: JSON.stringify(connection.options ?? {}, null, 2),
    });
    // We deliberately resync the form only when switching connections
    // (by id). Other field changes coming back from the backend after a
    // save would otherwise wipe in-progress edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connection.id]);

  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  return (
    <form
      className="editor"
      onSubmit={async (e) => {
        e.preventDefault();
        setError(null);
        setInfo(null);
        let optsObj: Record<string, unknown> | null = null;
        if (form.options_json.trim().length) {
          try {
            optsObj = JSON.parse(form.options_json) as Record<string, unknown>;
          } catch (err) {
            setError(`options must be valid JSON: ${(err as Error).message}`);
            return;
          }
        }
        const port = parseInt(form.port, 10);
        const input: ConnectionInput = {
          folder_id: form.folder_id,
          name: form.name,
          protocol: form.protocol,
          host: form.host,
          port: Number.isFinite(port) ? port : defaultPort(form.protocol),
          username: form.username || null,
          credential_id: form.credential_id,
          options: optsObj,
        };
        try {
          await api.updateConnection(connection.id, input);
          await onChange();
        } catch (err) {
          setError((err as IpcError).message ?? String(err));
        }
      }}
    >
      <h2>Connection</h2>
      {error ? <div className="banner error">{error}</div> : null}
      {info ? <div className="banner">{info}</div> : null}
      <div className="field">
        <label>Name</label>
        <input
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
        />
      </div>
      <div className="field">
        <label>Folder</label>
        <select
          value={form.folder_id ?? ""}
          onChange={(e) => setForm((f) => ({ ...f, folder_id: e.target.value || null }))}
        >
          <option value="">— root —</option>
          {folders.map((f) => (
            <option key={f.id} value={f.id}>
              {f.name}
            </option>
          ))}
        </select>
      </div>
      <div className="row">
        <div className="field" style={{ flex: 1 }}>
          <label>Protocol</label>
          <select
            value={form.protocol}
            onChange={(e) => {
              const protocol = e.target.value as Protocol;
              setForm((f) => ({
                ...f,
                protocol,
                port: String(defaultPort(protocol)),
              }));
            }}
          >
            <option value="ssh">SSH</option>
            <option value="sftp">SFTP</option>
            <option value="rdp">RDP</option>
          </select>
        </div>
        <div className="field" style={{ width: 100 }}>
          <label>Port</label>
          <input
            value={form.port}
            onChange={(e) => setForm((f) => ({ ...f, port: e.target.value }))}
          />
        </div>
      </div>
      <div className="field">
        <label>Host</label>
        <input
          value={form.host}
          onChange={(e) => setForm((f) => ({ ...f, host: e.target.value }))}
        />
      </div>
      <div className="field">
        <label>Username</label>
        <input
          value={form.username}
          onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
          placeholder="(blank = use credential's username)"
        />
      </div>
      <div className="field">
        <label>Credential</label>
        <select
          value={form.credential_id ?? ""}
          onChange={(e) => setForm((f) => ({ ...f, credential_id: e.target.value || null }))}
          disabled={!vaultUnlocked && credentials.length === 0}
        >
          <option value="">— inherit from folder —</option>
          {credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} ({c.kind})
            </option>
          ))}
        </select>
        {!vaultUnlocked ? (
          <div className="muted">Unlock the vault to attach a saved credential.</div>
        ) : null}
      </div>
      <div className="field">
        <label>Options (JSON)</label>
        <textarea
          rows={4}
          value={form.options_json}
          onChange={(e) => setForm((f) => ({ ...f, options_json: e.target.value }))}
        />
      </div>
      <div className="row">
        <button type="submit" className="primary">
          Save
        </button>
        <button
          type="button"
          onClick={async () => {
            setError(null);
            setInfo(null);
            try {
              const result = await api.startSession(connection.id);
              if (result.kind === "external") {
                const detail = result.credentials_prefilled
                  ? " with credentials prefilled"
                  : " (you'll be prompted for credentials)";
                setInfo(`Launched in ${result.client}${detail}.`);
              }
            } catch (err) {
              const msg = (err as IpcError).message ?? String(err);
              setError(msg);
            }
          }}
        >
          Connect
        </button>
        <span style={{ flex: 1 }} />
        <button
          type="button"
          className="danger"
          onClick={async () => {
            if (!window.confirm(`Delete connection "${connection.name}"?`)) return;
            await api.deleteConnection(connection.id);
            await onChange();
          }}
        >
          Delete
        </button>
      </div>
    </form>
  );
}
