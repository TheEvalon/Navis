import { useState } from "react";
import { useAppStore } from "../../store/app";
import { api, IpcError } from "../../ipc/client";
import "./vault.css";

export function VaultGate() {
  const vault = useAppStore((s) => s.vault);
  const refreshVault = useAppStore((s) => s.refreshVault);
  const refresh = useAppStore((s) => s.refresh);
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  return (
    <div className="vault-gate">
      <span className={`vault-pill ${vault.unlocked ? "unlocked" : "locked"}`}>
        {!vault.initialized
          ? "Vault: not set up"
          : vault.unlocked
            ? "Vault: unlocked"
            : "Vault: locked"}
      </span>
      {!vault.unlocked ? (
        <button
          onClick={() => {
            setError(null);
            setPw("");
            setPw2("");
            setOpen(true);
          }}
        >
          {vault.initialized ? "Unlock" : "Set up vault"}
        </button>
      ) : (
        <button
          onClick={async () => {
            await api.vaultLock();
            await refresh();
          }}
        >
          Lock
        </button>
      )}
      {open ? (
        <div className="modal-backdrop" onClick={() => setOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{vault.initialized ? "Unlock vault" : "Set up vault"}</h3>
            <p className="muted">
              {vault.initialized
                ? "Enter your master password. The vault stays unlocked until you lock it or restart Navis."
                : "Choose a strong master password. It encrypts every credential at rest. We cannot recover it."}
            </p>
            {error ? <div className="banner error">{error}</div> : null}
            <div className="field">
              <label>Master password</label>
              <input type="password" value={pw} autoFocus onChange={(e) => setPw(e.target.value)} />
            </div>
            {!vault.initialized ? (
              <div className="field">
                <label>Confirm master password</label>
                <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
              </div>
            ) : null}
            <div className="row">
              <button onClick={() => setOpen(false)}>Cancel</button>
              <span style={{ flex: 1 }} />
              <button
                className="primary"
                disabled={busy || pw.length < 8 || (!vault.initialized && pw !== pw2)}
                onClick={async () => {
                  setBusy(true);
                  setError(null);
                  try {
                    if (vault.initialized) {
                      await api.vaultUnlock(pw);
                    } else {
                      await api.vaultInitialize(pw);
                    }
                    await refreshVault();
                    setOpen(false);
                  } catch (err) {
                    setError((err as IpcError).message ?? String(err));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {vault.initialized ? "Unlock" : "Create vault"}
              </button>
            </div>
            {!vault.initialized ? (
              <p className="muted">
                Tip: pick at least 12 characters; longer is better. The vault uses Argon2id (64 MiB)
                and AES-256-GCM.
              </p>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
