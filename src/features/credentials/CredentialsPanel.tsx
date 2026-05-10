import { useState } from "react";
import { useAppStore } from "../../store/app";
import { api, IpcError } from "../../ipc/client";
import type { SecretKind } from "../../ipc/types";
import "./credentials.css";

const KINDS: { value: SecretKind; label: string }[] = [
  { value: "password", label: "Password (SSH/SFTP)" },
  { value: "ssh_private_key", label: "SSH private key" },
  { value: "rdp_password", label: "RDP password" },
  { value: "certificate", label: "Certificate" },
  { value: "generic", label: "Generic secret" },
];

export function CredentialsPanel() {
  const credentials = useAppStore((s) => s.credentials);
  const vault = useAppStore((s) => s.vault);
  const refresh = useAppStore((s) => s.refresh);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [kind, setKind] = useState<SecretKind>("password");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!vault.unlocked) {
    return (
      <div className="empty-state">
        <p>Unlock the vault to manage credentials.</p>
      </div>
    );
  }

  return (
    <div className="cred-panel">
      <div className="toolbar">
        <button
          className="primary"
          onClick={() => {
            setName("");
            setUsername("");
            setKind("password");
            setSecret("");
            setError(null);
            setOpen(true);
          }}
        >
          + New credential
        </button>
      </div>
      {credentials.length === 0 ? (
        <div className="empty-state">
          <p>No credentials yet. Create one and reuse it across many connections.</p>
        </div>
      ) : (
        <ul className="cred-list">
          {credentials.map((c) => (
            <li key={c.id} className="cred-row">
              <div>
                <div className="cred-name">{c.name}</div>
                <div className="muted">
                  {c.kind} · {c.username || "no username"}
                </div>
              </div>
              <button
                className="danger"
                title="Delete credential and remove its secret from the vault"
                onClick={async () => {
                  if (!window.confirm(`Delete credential "${c.name}"?`)) return;
                  try {
                    await api.deleteCredential(c.id);
                    await api.vaultDeleteSecret(c.vault_ref).catch(() => undefined);
                    await refresh();
                  } catch (err) {
                    setError((err as IpcError).message ?? String(err));
                  }
                }}
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
      {open ? (
        <div className="modal-backdrop" onClick={() => setOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>New credential</h3>
            {error ? <div className="banner error">{error}</div> : null}
            <div className="field">
              <label>Name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            </div>
            <div className="row">
              <div className="field" style={{ flex: 1 }}>
                <label>Kind</label>
                <select value={kind} onChange={(e) => setKind(e.target.value as SecretKind)}>
                  {KINDS.map((k) => (
                    <option key={k.value} value={k.value}>
                      {k.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field" style={{ flex: 1 }}>
                <label>Username (optional)</label>
                <input value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
            </div>
            <div className="field">
              <label>{kind === "ssh_private_key" ? "Private key (PEM)" : "Secret"}</label>
              {kind === "ssh_private_key" ? (
                <textarea rows={6} value={secret} onChange={(e) => setSecret(e.target.value)} />
              ) : (
                <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} />
              )}
            </div>
            <p className="muted">
              The secret is encrypted with the vault DEK and never written in plaintext.
            </p>
            <div className="row">
              <button onClick={() => setOpen(false)}>Cancel</button>
              <span style={{ flex: 1 }} />
              <button
                className="primary"
                disabled={busy || !name.trim() || !secret}
                onClick={async () => {
                  setBusy(true);
                  setError(null);
                  try {
                    const vref = await api.vaultPutSecret({ kind, plaintext: secret });
                    await api.createCredential({
                      name,
                      kind,
                      username: username || null,
                      vault_ref: vref,
                    });
                    setOpen(false);
                    await refresh();
                  } catch (err) {
                    setError((err as IpcError).message ?? String(err));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Save credential
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
