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
            await api.startSession(node.data.id);
          } catch (err) {
            console.warn("start session failed:", err);
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
