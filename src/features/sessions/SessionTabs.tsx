import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useAppStore } from "../../store/app";
import type { SessionEvent, SessionListItem } from "../../ipc/types";
import { TerminalView } from "./TerminalView";
import { SftpBrowser } from "./SftpBrowser";
import { api } from "../../ipc/client";
import "./sessions.css";

export function SessionTabs() {
  const sessions = useAppStore((s) => s.sessions);
  const refreshSessions = useAppStore((s) => s.refreshSessions);
  const connections = useAppStore((s) => s.connections);
  const [active, setActive] = useState<string | null>(null);
  const [, force] = useState(0);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<SessionEvent>("navis:session", (ev) => {
      // Re-render on any session event so state badges update.
      force((n) => n + 1);
      if (ev.payload.type === "state") {
        void refreshSessions();
      }
    }).then((f) => (unlisten = f));
    return () => {
      unlisten?.();
    };
  }, [refreshSessions]);

  useEffect(() => {
    if (!active && sessions.length > 0) setActive(sessions[0]!.id);
    if (active && !sessions.find((s) => s.id === active)) {
      setActive(sessions[0]?.id ?? null);
    }
  }, [sessions, active]);

  if (sessions.length === 0) {
    return (
      <div className="session-tabs empty">
        <span className="muted">No active sessions. Double-click a connection to start one.</span>
      </div>
    );
  }

  const current = sessions.find((s) => s.id === active);

  return (
    <>
      <div className="session-tabs">
        {sessions.map((s) => (
          <SessionTab
            key={s.id}
            session={s}
            label={connections.find((c) => c.id === s.connection_id)?.name ?? s.connection_id}
            active={s.id === active}
            onSelect={() => setActive(s.id)}
            onClose={async () => {
              await api.closeSession(s.id);
              await refreshSessions();
            }}
          />
        ))}
      </div>
      <div className="session-body">
        {current ? (
          current.kind === "ssh" ? (
            <TerminalView sessionId={current.id} />
          ) : current.kind === "sftp" ? (
            <SftpBrowser sessionId={current.id} />
          ) : (
            <div className="empty-state">
              The RDP renderer is wired up in a follow-up commit. The trust store and connection
              editor for RDP are already functional.
            </div>
          )
        ) : null}
      </div>
    </>
  );
}

function SessionTab({
  session,
  label,
  active,
  onSelect,
  onClose,
}: {
  session: SessionListItem;
  label: string;
  active: boolean;
  onSelect: () => void;
  onClose: () => void;
}) {
  const dot =
    session.state === "connected"
      ? "var(--success)"
      : session.state === "connecting"
        ? "var(--warning)"
        : "var(--text-dim)";
  return (
    <div
      className={`session-tab ${active ? "session-tab-active" : ""}`}
      onClick={onSelect}
      title={`${session.kind.toUpperCase()} · ${session.state}`}
    >
      <span className="session-dot" style={{ background: dot }} />
      <span className="session-label">{label}</span>
      <button
        className="session-close"
        onClick={(e) => {
          e.stopPropagation();
          onClose();
        }}
      >
        ×
      </button>
    </div>
  );
}
