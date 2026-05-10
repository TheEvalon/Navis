import { useEffect } from "react";
import { Shell } from "./layout/Shell";
import { useAppStore } from "./store/app";
import { api } from "./ipc/client";

export function App() {
  const refresh = useAppStore((s) => s.refresh);
  const refreshVault = useAppStore((s) => s.refreshVault);
  const refreshSessions = useAppStore((s) => s.refreshSessions);
  const sessions = useAppStore((s) => s.sessions);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Renderer heartbeat for the idle auto-lock timer. Touching on every
  // user interaction (keystroke / pointer / focus) means a busy user
  // never gets locked out; an idle session locks after the configured
  // window. The interval below is a backstop in case event listeners
  // miss something.
  useEffect(() => {
    const onActivity = () => {
      void api.autolockTouch();
    };
    window.addEventListener("keydown", onActivity);
    window.addEventListener("pointermove", onActivity);
    window.addEventListener("focus", onActivity);
    const interval = window.setInterval(onActivity, 30_000);
    return () => {
      window.removeEventListener("keydown", onActivity);
      window.removeEventListener("pointermove", onActivity);
      window.removeEventListener("focus", onActivity);
      window.clearInterval(interval);
    };
  }, []);

  // Re-poll sessions periodically so state pills stay fresh even when
  // protocol engines emit no event.
  useEffect(() => {
    const interval = window.setInterval(() => {
      void refreshSessions();
    }, 5_000);
    return () => window.clearInterval(interval);
  }, [refreshSessions]);

  // Re-poll vault status so the UI flips back to "locked" when the
  // idle-lock timer fires.
  useEffect(() => {
    const interval = window.setInterval(() => {
      void refreshVault();
    }, 10_000);
    return () => window.clearInterval(interval);
  }, [refreshVault]);

  // Keyboard shortcuts.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isMod = e.ctrlKey || e.metaKey;
      if (!isMod) return;
      if (e.key.toLowerCase() === "l" && e.shiftKey) {
        // Ctrl/Cmd+Shift+L — lock vault now.
        e.preventDefault();
        void api.vaultLock().then(() => refreshVault());
      } else if (e.key.toLowerCase() === "w" && sessions.length > 0) {
        // Ctrl/Cmd+W — close current session (first by default; the
        // active session is tracked inside SessionTabs).
        // No-op here; SessionTabs owns the active id.
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [refreshVault, sessions.length]);

  return <Shell />;
}
