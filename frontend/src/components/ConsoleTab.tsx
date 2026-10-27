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
      // msfconsole runs outside a real TTY and emits bare \n line endings
      // (no \r). xterm.js doesn't return the cursor to column 0 on a bare
      // \n by default, so each line picks up where the last one's cursor
      // stopped - producing a scattered/staircase render of the banner.
      // convertEol treats \n as \r\n, which fixes that.
      convertEol: true,
      // Generous default so a mis-timed first fit doesn't wrap the banner
      // into a narrow column before the real size is known.
      cols: 120,
      rows: 30,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current);
    termRef.current = term;

    const safeFit = () => {
      const el = containerRef.current;
      if (!el || el.clientWidth === 0 || el.clientHeight === 0) return;
      try {
        fit.fit();
      } catch {
        // container not measurable yet; next resize/raf will retry
      }
    };

    // The flex layout may not have settled its height on the very first
    // paint, so fit() right after term.open() can compute a near-zero
    // column count and wrap the incoming banner into a mangled mess.
    // Defer the first real fit (and the socket connection, so the banner
    // arrives after sizing is correct) across a couple of animation
    // frames, which is enough for layout to stabilize.
    let socket: WebSocket | null = null;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (cancelled) return;
        safeFit();

        socket = new WebSocket(consoleSocketUrl());
        socketRef.current = socket;

        socket.onmessage = (event) => {
          const msg = JSON.parse(event.data);
          if (msg.type === "output") {
            term.write(msg.data);
          } else if (msg.type === "prompt") {
            // msfrpcd sends the prompt (e.g. "msf6 > ") separately from
            // output text, so it has to be written explicitly - without
            // this the console never shows where you're meant to type.
            term.write(`\x1b[32m${msg.data}\x1b[0m`);
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
            if (socket && socket.readyState === WebSocket.OPEN) {
              socket.send(JSON.stringify({ type: "input", data: inputBuffer + "\n" }));
            }
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
  }, []);

  return <div ref={containerRef} className="xterm-wrapper w-full h-full p-2" />;
}
