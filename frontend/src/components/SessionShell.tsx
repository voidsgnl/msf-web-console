import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { sessionSocketUrl } from "../lib/api";

/**
 * Interactive terminal for one live session (shell or meterpreter), bridged
 * to the backend's /api/sessions/ws/{id} WebSocket. Unlike the msfconsole
 * view, there's no separate "prompt" message here - a real shell/meterpreter
 * session's prompt is just part of its normal output stream.
 */
export function SessionShell({ sessionId, onClose }: { sessionId: number; onClose: () => void }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [sessionType, setSessionType] = useState<string | null>(null);
  const [fatalError, setFatalError] = useState<string | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    let cancelled = false;

    const term = new Terminal({
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 13,
      theme: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        cursor: "#3fb950",
      },
      cursorBlink: true,
      convertEol: true,
      cols: 120,
      rows: 30,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);

    const safeFit = () => {
      const el = containerRef.current;
      if (!el || el.clientWidth === 0 || el.clientHeight === 0) return;
      try {
        fit.fit();
      } catch {
        // retried on next resize
      }
    };

    let socket: WebSocket | null = null;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (cancelled) return;
        safeFit();

        socket = new WebSocket(sessionSocketUrl(sessionId));

        socket.onmessage = (event) => {
          const msg = JSON.parse(event.data);
          if (msg.type === "ready") {
            setSessionType(msg.session_type ?? null);
          } else if (msg.type === "output") {
            term.write(msg.data);
          } else if (msg.type === "error") {
            setFatalError(msg.data);
            term.write(`\r\n\x1b[31m[error] ${msg.data}\x1b[0m\r\n`);
          }
        };

        socket.onclose = () => {
          term.write("\r\n\x1b[90m[session connection closed]\x1b[0m\r\n");
        };

        let inputBuffer = "";
        term.onData((data) => {
          term.write(data);
          if (data === "\r") {
            term.write("\n");
            if (socket && socket.readyState === WebSocket.OPEN) {
              socket.send(JSON.stringify({ type: "input", data: inputBuffer + "\n" }));
            }
            inputBuffer = "";
          } else if (data === "\u007f") {
            if (inputBuffer.length > 0) {
              inputBuffer = inputBuffer.slice(0, -1);
              term.write("\b \b");
            }
          } else {
            inputBuffer += data;
          }
        });
      });
    });

    const resizeObserver = new ResizeObserver(() => safeFit());
    resizeObserver.observe(containerRef.current);

    return () => {
      cancelled = true;
      resizeObserver.disconnect();
      socket?.close();
      term.dispose();
    };
  }, [sessionId]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between h-10 bg-bg-secondary border-b border-border px-3 text-xs">
        <div className="flex items-center gap-2 text-gray-400">
          <button onClick={onClose} className="hover:text-gray-200">
            ← back to sessions
          </button>
          <span className="text-gray-600">|</span>
          <span className="font-mono text-gray-300">session #{sessionId}</span>
          {sessionType && (
            <span className="font-mono text-gray-600">({sessionType})</span>
          )}
        </div>
        {fatalError && <span className="text-danger">{fatalError}</span>}
      </div>
      <div className="flex-1 min-h-0">
        <div ref={containerRef} className="xterm-wrapper w-full h-full p-2" />
      </div>
    </div>
  );
}
