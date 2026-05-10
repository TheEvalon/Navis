import { useEffect, useRef } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import { listen } from "@tauri-apps/api/event";
import { api } from "../../ipc/client";
import type { SessionEvent } from "../../ipc/types";
import "xterm/css/xterm.css";

export function TerminalView({ sessionId }: { sessionId: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const term = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: "ui-monospace, 'SF Mono', Menlo, Consolas, monospace",
      fontSize: 13,
      theme: {
        background: "#0a0d12",
        foreground: "#e6e9ef",
        cursor: "#4f8cff",
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(ref.current);
    termRef.current = term;
    fit.fit();

    const onResize = () => {
      try {
        fit.fit();
        const { cols, rows } = term;
        void api.resizeSession(sessionId, cols, rows);
      } catch {
        // ignore
      }
    };
    window.addEventListener("resize", onResize);

    const dataDisposable = term.onData((data) => {
      const bytes = Array.from(new TextEncoder().encode(data));
      void api.sendInput(sessionId, bytes);
    });

    let unlisten: (() => void) | undefined;
    listen<SessionEvent>("navis:session", (ev) => {
      const p = ev.payload;
      if (p.type === "output" && p.session_id === sessionId) {
        term.write(new Uint8Array(p.data));
      } else if (p.type === "state" && p.session_id === sessionId) {
        if (p.state === "disconnected" || p.state === "failed") {
          term.write(
            `\r\n\x1b[33m[session ${p.state}${p.message ? `: ${p.message}` : ""}]\x1b[0m\r\n`,
          );
        }
      }
    }).then((f) => (unlisten = f));

    // Initial size sync.
    requestAnimationFrame(() => {
      onResize();
    });

    return () => {
      window.removeEventListener("resize", onResize);
      dataDisposable.dispose();
      unlisten?.();
      term.dispose();
      termRef.current = null;
    };
  }, [sessionId]);

  return <div className="terminal-host" ref={ref} />;
}
