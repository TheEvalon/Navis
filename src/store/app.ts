import { create } from "zustand";
import { api } from "../ipc/client";
import type {
  Connection,
  CredentialProfile,
  Folder,
  SessionListItem,
  VaultStatus,
} from "../ipc/types";

interface SelectedTreeNode {
  kind: "folder" | "connection";
  id: string;
}

interface AppStore {
  folders: Folder[];
  connections: Connection[];
  credentials: CredentialProfile[];
  sessions: SessionListItem[];
  vault: VaultStatus;
  selected: SelectedTreeNode | null;
  loading: boolean;
  error: string | null;

  setSelected: (sel: SelectedTreeNode | null) => void;
  refresh: () => Promise<void>;
  refreshVault: () => Promise<void>;
  refreshSessions: () => Promise<void>;
}

export const useAppStore = create<AppStore>((set, get) => ({
  folders: [],
  connections: [],
  credentials: [],
  sessions: [],
  vault: { initialized: false, unlocked: false },
  selected: null,
  loading: false,
  error: null,

  setSelected: (sel) => set({ selected: sel }),

  refresh: async () => {
    set({ loading: true, error: null });
    try {
      const [folders, connections, credentials, sessions, vault] = await Promise.all([
        api.listFolders(),
        api.listConnections(),
        get().vault.unlocked ? api.listCredentials() : Promise.resolve([]),
        api.listSessions(),
        api.vaultStatus(),
      ]);
      set({ folders, connections, credentials, sessions, vault, loading: false });
    } catch (err) {
      set({ loading: false, error: (err as Error).message });
    }
  },

  refreshVault: async () => {
    const vault = await api.vaultStatus();
    set({ vault });
    if (vault.unlocked) {
      const credentials = await api.listCredentials();
      set({ credentials });
    } else {
      set({ credentials: [] });
    }
  },

  refreshSessions: async () => {
    const sessions = await api.listSessions();
    set({ sessions });
  },
}));
