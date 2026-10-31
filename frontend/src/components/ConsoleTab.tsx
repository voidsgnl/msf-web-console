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
    let inputBuffer = "";

    const term = new Terminal({
      fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, monospace",
      fontSize: 13,
      lineHeight: 1.3,
      scrollback: 10000,
      cursorStyle: "bar",
      cursorWidth: 2,
      // Full ANSI palette tuned to the app's dark theme so msfconsole's
      // coloured output ([+] green, [-] red, [*] blue, warnings yellow) reads
      // clearly instead of falling back to xterm's harsh defaults.
      theme: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        cursor: "#3fb950",
        cursorAccent: "#0d1117",
        selectionBackground: "rgba(56, 139, 253, 0.35)",
        black: "#484f58",
        red: "#ff7b72",
        green: "#3fb950",
        yellow: "#d29922",
        blue: "#58a6ff",
        magenta: "#bc8cff",
        cyan: "#39c5cf",
        white: "#b1bac4",
        brightBlack: "#6e7681",
        brightRed: "#ffa198",
        brightGreen: "#56d364",
        brightYellow: "#e3b341",
        brightBlue: "#79c0ff",
        brightMagenta: "#d2a8ff",
        brightCyan: "#56d4dd",
        brightWhite: "#f0f6fc",
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

    const handleTerminalSelectionQuery = (event: Event) => {
      const detail = (event as CustomEvent<{ text: string }>).detail;
      if (detail) detail.text = term.getSelection();
    };

    const announceContext = (message: string) => {
      window.dispatchEvent(new CustomEvent("msf-context-notice", { detail: message }));
    };

    const handleContextAction = async (event: Event) => {
      const detail = (event as CustomEvent<{ action: string; kind: string }>).detail;
      if (detail?.kind !== "console") return;
      if (detail.action === "select-all-terminal") {
        term.selectAll();
        announceContext("Terminal output selected.");
      } else if (detail.action === "clear-terminal") {
        term.clear();
        term.clearSelection();
        inputBuffer = "";
        announceContext("Terminal display cleared. This does not clear Metasploit sessions or jobs.");
      } else if (detail.action === "paste-terminal") {
        try {
          const text = await navigator.clipboard.readText();
          term.paste(text);
          announceContext("Clipboard text pasted into the terminal.");
        } catch {
          announceContext("Clipboard access was blocked. Use your browser's permitted paste shortcut instead.");
        }
      }
    };

    window.addEventListener("msf-terminal-selection-query", handleTerminalSelectionQuery);
    window.addEventListener("msf-context-action", handleContextAction);

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

        socket.onclose = (event) => {
          if (cancelled) return;
          if (event.code === 4401 || event.code === 4403) {
            window.dispatchEvent(new CustomEvent("msf-auth-required"));
            term.write("\r\n\x1b[31m[login required] Your session expired. Sign in again to reconnect.\x1b[0m\r\n");
            return;
          }
          term.write("\r\n\x1b[90m[console closed]\x1b[0m\r\n");
        };

        term.onData((data) => {
          // The backend bridges complete console lines. Process a pasted
          // multi-line string character by character so each newline submits
          // the current line instead of being swallowed into the input buffer.
          const normalized = data.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
          for (const character of normalized) {
            if (character === "\n") {
              term.write("\r\n");
              if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ type: "input", data: inputBuffer + "\n" }));
              }
              inputBuffer = "";
            } else if (character === "\u007f" || character === "\b") {
              if (inputBuffer.length > 0) {
                inputBuffer = inputBuffer.slice(0, -1);
                term.write("\b \b");
              }
            } else {
              term.write(character);
              inputBuffer += character;
            }
          }
        });
      });
    });

    const resizeObserver = new ResizeObserver(() => safeFit());
    resizeObserver.observe(containerRef.current);

    return () => {
      cancelled = true;
      resizeObserver.disconnect();
      window.removeEventListener("msf-terminal-selection-query", handleTerminalSelectionQuery);
      window.removeEventListener("msf-context-action", handleContextAction);
      socket?.close();
      term.dispose();
    };
  }, []);

  return <div ref={containerRef} className="xterm-wrapper w-full h-full p-3" />;
}
