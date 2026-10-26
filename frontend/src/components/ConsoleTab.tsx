import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { consoleSocketUrl } from "../lib/api";

/**
 * One live msfconsole instance, bridged to the backend WebSocket, which in
 * turn bridges to a real console created via console.create on msfrpcd.
 * Mounting this component opens a new console; unmounting closes it.
 */
export function ConsoleTab() {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 13,
      theme: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        cursor: "#3fb950",
      },
      cursorBlink: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    fit.fit();
    termRef.current = term;

    const socket = new WebSocket(consoleSocketUrl());
    socketRef.current = socket;

    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === "output") {
        term.write(msg.data);
      } else if (msg.type === "error") {
        term.write(`\r\n\x1b[31m[error] ${msg.data}\x1b[0m\r\n`);
      }
    };

    socket.onclose = () => {
      term.write("\r\n\x1b[90m[console closed]\x1b[0m\r\n");
    };

    let inputBuffer = "";
    term.onData((data) => {
      // Echo locally and buffer until newline, then send the full line —
      // msfconsole expects line-based input over console.write.
      term.write(data);
      if (data === "\r") {
        term.write("\n");
        socket.readyState === WebSocket.OPEN &&
          socket.send(JSON.stringify({ type: "input", data: inputBuffer + "\n" }));
        inputBuffer = "";
      } else if (data === "\u007f") {
        // backspace
        if (inputBuffer.length > 0) {
          inputBuffer = inputBuffer.slice(0, -1);
          term.write("\b \b");
        }
      } else {
        inputBuffer += data;
      }
    });

    const resizeObserver = new ResizeObserver(() => fit.fit());
    resizeObserver.observe(containerRef.current);

    return () => {
      resizeObserver.disconnect();
      socket.close();
      term.dispose();
    };
  }, []);

  return <div ref={containerRef} className="xterm-wrapper w-full h-full p-2" />;
}
