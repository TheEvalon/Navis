import { useCallback, useEffect, useState } from "react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import { IpcError } from "../../ipc/client";
import "./sftp.css";

interface RemoteEntry {
  name: string;
  path: string;
  kind: "file" | "directory" | "symlink" | "other";
  size: number;
  modified_unix: number | null;
  mode: number;
}

export function SftpBrowser({ sessionId }: { sessionId: string }) {
  const [cwd, setCwd] = useState<string>(".");
  const [entries, setEntries] = useState<RemoteEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(
    async (path?: string) => {
      setLoading(true);
      setError(null);
      try {
        const target = path ?? cwd;
        const list = await invoke<RemoteEntry[]>("sftp_list", {
          sessionId,
          path: target,
        });
        const canonical = await invoke<string>("sftp_canonicalize", {
          sessionId,
          path: target,
        });
        setCwd(canonical);
        setEntries(list);
      } catch (err) {
        setError((err as IpcError).message ?? String(err));
      } finally {
        setLoading(false);
      }
    },
    [sessionId, cwd],
  );

  useEffect(() => {
    void refresh(".");
    // Only on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  return (
    <div className="sftp">
      <div className="sftp-toolbar">
        <button onClick={() => void refresh("..")} title="Up">
          ↑ Up
        </button>
        <input
          value={cwd}
          onChange={(e) => setCwd(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void refresh(cwd);
          }}
        />
        <button onClick={() => void refresh()} disabled={loading}>
          Reload
        </button>
        <button
          onClick={async () => {
            const name = window.prompt("New folder name?");
            if (!name) return;
            const target = `${cwd.replace(/\/$/, "")}/${name}`;
            try {
              setBusy("mkdir");
              await invoke("sftp_mkdir", { sessionId, path: target });
              await refresh();
            } catch (err) {
              setError((err as IpcError).message ?? String(err));
            } finally {
              setBusy(null);
            }
          }}
        >
          + Folder
        </button>
        <button
          onClick={async () => {
            const local = await openDialog({ multiple: false });
            if (!local || Array.isArray(local)) return;
            const remoteName = local.split(/[\\/]/).pop() ?? "uploaded";
            const remote = `${cwd.replace(/\/$/, "")}/${remoteName}`;
            try {
              setBusy(`Uploading ${remoteName}…`);
              await invoke("sftp_upload", {
                sessionId,
                localPath: local,
                remotePath: remote,
              });
              await refresh();
            } catch (err) {
              setError((err as IpcError).message ?? String(err));
            } finally {
              setBusy(null);
            }
          }}
        >
          ↑ Upload
        </button>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      {busy ? <div className="banner">{busy}</div> : null}
      <div className="sftp-table-wrap">
        <table className="sftp-table">
          <thead>
            <tr>
              <th />
              <th>Name</th>
              <th>Size</th>
              <th>Mode</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.path}>
                <td className="sftp-icon">{iconFor(e)}</td>
                <td
                  className="sftp-name"
                  onDoubleClick={() => {
                    if (e.kind === "directory") {
                      void refresh(e.path);
                    }
                  }}
                >
                  {e.name}
                </td>
                <td>{e.kind === "directory" ? "—" : humanBytes(e.size)}</td>
                <td>
                  <code>{toOctal(e.mode)}</code>
                </td>
                <td>
                  {e.kind !== "directory" ? (
                    <button
                      onClick={async () => {
                        const local = await saveDialog({ defaultPath: e.name });
                        if (!local) return;
                        try {
                          setBusy(`Downloading ${e.name}…`);
                          await invoke("sftp_download", {
                            sessionId,
                            remotePath: e.path,
                            localPath: local,
                          });
                        } catch (err) {
                          setError((err as IpcError).message ?? String(err));
                        } finally {
                          setBusy(null);
                        }
                      }}
                    >
                      ↓
                    </button>
                  ) : null}
                  <button
                    className="danger"
                    onClick={async () => {
                      if (!window.confirm(`Delete ${e.name}?`)) return;
                      try {
                        await invoke("sftp_remove", {
                          sessionId,
                          path: e.path,
                          isDir: e.kind === "directory",
                        });
                        await refresh();
                      } catch (err) {
                        setError((err as IpcError).message ?? String(err));
                      }
                    }}
                  >
                    🗑
                  </button>
                </td>
              </tr>
            ))}
            {entries.length === 0 && !loading ? (
              <tr>
                <td colSpan={5} className="muted" style={{ padding: 12 }}>
                  Empty.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function iconFor(e: RemoteEntry): string {
  switch (e.kind) {
    case "directory":
      return "📁";
    case "symlink":
      return "↪";
    case "file":
      return "📄";
    default:
      return "•";
  }
}

function humanBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function toOctal(mode: number): string {
  return (mode & 0o777).toString(8).padStart(3, "0");
}
