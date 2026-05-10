import { useEffect, useState } from "react";
import { api } from "../../ipc/client";
import type { KnownSshHost, RdpPin } from "../../ipc/types";

export function TrustStorePanel() {
  const [ssh, setSsh] = useState<KnownSshHost[]>([]);
  const [rdp, setRdp] = useState<RdpPin[]>([]);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setBusy(true);
    try {
      const [s, r] = await Promise.all([api.sshKnownHosts(), api.rdpPinnedHosts()]);
      setSsh(s);
      setRdp(r);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  return (
    <div style={{ overflow: "auto", flex: 1 }}>
      <div className="toolbar">
        <button onClick={() => void refresh()} disabled={busy}>
          Refresh
        </button>
      </div>
      <h3 style={{ padding: "8px 14px", margin: 0 }}>SSH known hosts</h3>
      {ssh.length === 0 ? (
        <p className="muted" style={{ padding: "0 14px" }}>
          Empty. Hosts get pinned the first time you accept their key.
        </p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {ssh.map((h, i) => (
            <li
              key={`${h.host}:${h.port}:${h.algo}`}
              style={{
                display: "flex",
                gap: 8,
                padding: "6px 14px",
                borderBottom: i < ssh.length - 1 ? "1px solid var(--border)" : "none",
              }}
            >
              <span style={{ flex: 1 }}>
                <div>
                  <strong>{h.host}</strong>:{h.port} <span className="muted">({h.algo})</span>
                </div>
                <div className="muted" style={{ fontFamily: "monospace", fontSize: 11 }}>
                  {h.key_b64.slice(0, 64)}…
                </div>
              </span>
              <button
                className="danger"
                onClick={async () => {
                  if (!window.confirm(`Forget ${h.host}:${h.port}?`)) return;
                  await api.sshForgetHost(h.host, h.port);
                  await refresh();
                }}
              >
                Forget
              </button>
            </li>
          ))}
        </ul>
      )}
      <h3 style={{ padding: "8px 14px", margin: "12px 0 0 0" }}>RDP pinned certs</h3>
      {rdp.length === 0 ? (
        <p className="muted" style={{ padding: "0 14px" }}>
          No RDP hosts pinned yet.
        </p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {rdp.map((h) => (
            <li
              key={`${h.host}:${h.port}`}
              style={{ display: "flex", gap: 8, padding: "6px 14px" }}
            >
              <span style={{ flex: 1 }}>
                <div>
                  <strong>{h.host}</strong>:{h.port}
                </div>
                <div className="muted" style={{ fontFamily: "monospace", fontSize: 11 }}>
                  {h.thumbprint_sha256.slice(0, 64)}
                </div>
              </span>
              <button
                className="danger"
                onClick={async () => {
                  if (!window.confirm(`Forget ${h.host}:${h.port}?`)) return;
                  await api.rdpForgetHost(h.host, h.port);
                  await refresh();
                }}
              >
                Forget
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
