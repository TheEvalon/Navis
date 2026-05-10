import { useState } from "react";
import { ConnectionTree } from "../features/tree/ConnectionTree";
import { ConnectionEditor } from "../features/connections/ConnectionEditor";
import { SessionTabs } from "../features/sessions/SessionTabs";
import { VaultGate } from "../features/vault/VaultGate";
import { CredentialsPanel } from "../features/credentials/CredentialsPanel";
import { TrustStorePanel } from "../features/trust/TrustStorePanel";
import { useAppStore } from "../store/app";
import "./shell.css";

type SidebarTab = "tree" | "credentials" | "trust";

export function Shell() {
  const [tab, setTab] = useState<SidebarTab>("tree");
  const error = useAppStore((s) => s.error);
  return (
    <div className="shell">
      <header className="shell-header">
        <div className="shell-title">Navis</div>
        <div className="shell-tabs">
          <button
            className={tab === "tree" ? "tab tab-active" : "tab"}
            onClick={() => setTab("tree")}
          >
            Connections
          </button>
          <button
            className={tab === "credentials" ? "tab tab-active" : "tab"}
            onClick={() => setTab("credentials")}
          >
            Credentials
          </button>
          <button
            className={tab === "trust" ? "tab tab-active" : "tab"}
            onClick={() => setTab("trust")}
          >
            Trust store
          </button>
        </div>
        <VaultGate />
      </header>
      {error ? (
        <div className="banner error">
          <strong>Error:</strong> {error}
        </div>
      ) : null}
      <div className="shell-body">
        <aside className="sidebar">
          {tab === "tree" ? (
            <ConnectionTree />
          ) : tab === "credentials" ? (
            <CredentialsPanel />
          ) : (
            <TrustStorePanel />
          )}
        </aside>
        <main className="main">
          <SessionTabs />
          <ConnectionEditor />
        </main>
      </div>
    </div>
  );
}
