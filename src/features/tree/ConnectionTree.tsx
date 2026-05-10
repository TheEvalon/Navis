import { useMemo, useState } from "react";
import { Tree, type NodeRendererProps, type NodeApi } from "react-arborist";
import useResizeObserver from "use-resize-observer";
import { useAppStore } from "../../store/app";
import { api } from "../../ipc/client";
import type { Connection, Folder, Protocol } from "../../ipc/types";
import "./tree.css";

interface TreeNode {
  id: string;
  name: string;
  kind: "folder" | "connection";
  protocol?: Protocol;
  children?: TreeNode[];
  raw: Folder | Connection;
}

function buildTree(folders: Folder[], connections: Connection[]): TreeNode[] {
  const folderById = new Map<string, TreeNode>();
  for (const f of folders) {
    folderById.set(f.id, { id: f.id, name: f.name, kind: "folder", children: [], raw: f });
  }
  const roots: TreeNode[] = [];
  for (const f of folders) {
    const node = folderById.get(f.id)!;
    if (f.parent_id && folderById.has(f.parent_id)) {
      folderById.get(f.parent_id)!.children!.push(node);
    } else {
      roots.push(node);
    }
  }
  for (const c of connections) {
    const node: TreeNode = {
      id: c.id,
      name: c.name,
      kind: "connection",
      protocol: c.protocol,
      raw: c,
    };
    if (c.folder_id && folderById.has(c.folder_id)) {
      folderById.get(c.folder_id)!.children!.push(node);
    } else {
      roots.push(node);
    }
  }
  // Stable alphabetical sort within siblings.
  const sortRec = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    for (const n of nodes) if (n.children) sortRec(n.children);
  };
  sortRec(roots);
  return roots;
}

export function ConnectionTree() {
  const folders = useAppStore((s) => s.folders);
  const connections = useAppStore((s) => s.connections);
  const setSelected = useAppStore((s) => s.setSelected);
  const refresh = useAppStore((s) => s.refresh);
  const [search, setSearch] = useState("");
  const { ref, width = 320, height = 600 } = useResizeObserver<HTMLDivElement>();

  const data = useMemo(() => buildTree(folders, connections), [folders, connections]);

  return (
    <div className="tree-wrap">
      <div className="toolbar">
        <button title="New folder" onClick={() => onNewFolder(refresh)}>
          + Folder
        </button>
        <button
          className="primary"
          title="New connection"
          onClick={() => onNewConnection(setSelected, refresh)}
        >
          + Connection
        </button>
        <span style={{ flex: 1 }} />
        <button title="Export bundle" onClick={() => void onExport()}>
          ↗ Export
        </button>
        <button title="Import bundle" onClick={() => void onImport(refresh)}>
          ↙ Import
        </button>
      </div>
      <div className="tree-search">
        <input placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <div className="tree-host" ref={ref}>
        <Tree<TreeNode>
          data={data}
          width={width}
          height={height}
          rowHeight={28}
          indent={18}
          searchTerm={search}
          searchMatch={(node, term) => node.data.name.toLowerCase().includes(term.toLowerCase())}
          onSelect={(nodes: NodeApi<TreeNode>[]) => {
            const n = nodes[0];
            if (!n) {
              setSelected(null);
              return;
            }
            setSelected({ kind: n.data.kind, id: n.data.id });
          }}
          onMove={async ({ dragIds, parentId }) => {
            for (const id of dragIds) {
              const folder = folders.find((f) => f.id === id);
              const connection = connections.find((c) => c.id === id);
              try {
                if (folder) {
                  await api.updateFolder(id, {
                    parent_id: parentId,
                    name: folder.name,
                    default_credential_id: folder.default_credential_id,
                    sort_order: folder.sort_order,
                  });
                } else if (connection) {
                  await api.updateConnection(id, {
                    folder_id: parentId,
                    name: connection.name,
                    protocol: connection.protocol,
                    host: connection.host,
                    port: connection.port,
                    username: connection.username,
                    credential_id: connection.credential_id,
                    options: connection.options,
                  });
                }
              } catch (err) {
                console.error("move failed", err);
              }
            }
            await refresh();
          }}
        >
          {Node}
        </Tree>
      </div>
    </div>
  );
}

function Node({ node, style, dragHandle }: NodeRendererProps<TreeNode>) {
  const isOpen = node.isOpen;
  const isFolder = node.data.kind === "folder";
  return (
    <div
      ref={dragHandle}
      style={style}
      className={`tree-row ${node.isSelected ? "tree-row-selected" : ""}`}
      onClick={() => node.toggle()}
      onDoubleClick={async () => {
        if (!isFolder) {
          try {
            const result = await api.startSession(node.data.id);
            if (result.kind === "external") {
              const detail = result.credentials_prefilled
                ? " with credentials prefilled"
                : " (you'll be prompted for credentials)";
              window.alert(`Launched in ${result.client}${detail}.`);
            }
          } catch (err) {
            const msg = (err as Error).message ?? String(err);
            window.alert(`Failed to start session: ${msg}`);
          }
        }
      }}
    >
      <span className="tree-icon">
        {isFolder ? (isOpen ? "▼" : "▶") : protocolIcon(node.data.protocol)}
      </span>
      <span className="tree-name">{node.data.name}</span>
      {!isFolder ? (
        <span className="tree-host-text muted">{(node.data.raw as Connection).host}</span>
      ) : null}
    </div>
  );
}

function protocolIcon(protocol?: Protocol): string {
  switch (protocol) {
    case "ssh":
      return "$";
    case "sftp":
      return "≡";
    case "rdp":
      return "▣";
    default:
      return "•";
  }
}

async function onExport() {
  const bundle = await api.exportBundle();
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `navis-export-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function onImport(refresh: () => Promise<void>) {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = "application/json,.json";
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const bundle = JSON.parse(text);
      const summary = await api.importBundle(bundle);
      window.alert(
        `Imported: ${summary.folders_added} folders, ${summary.connections_added} connections, ${summary.credentials_added} credentials.`,
      );
      await refresh();
    } catch (err) {
      window.alert(`Import failed: ${(err as Error).message}`);
    }
  };
  input.click();
}

async function onNewFolder(refresh: () => Promise<void>) {
  const name = window.prompt("Folder name?");
  if (!name) return;
  await api.createFolder({ parent_id: null, name, default_credential_id: null });
  await refresh();
}

async function onNewConnection(
  setSelected: (s: { kind: "connection"; id: string }) => void,
  refresh: () => Promise<void>,
) {
  const name = window.prompt("Connection name?");
  if (!name) return;
  const host = window.prompt("Host?");
  if (!host) return;
  const c = await api.createConnection({
    folder_id: null,
    name,
    protocol: "ssh",
    host,
    username: null,
  });
  setSelected({ kind: "connection", id: c.id });
  await refresh();
}
