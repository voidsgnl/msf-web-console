import { useEffect, useRef, useState } from "react";

type ContextSnapshot = {
  id: number;
  x: number;
  y: number;
  target: HTMLElement;
  scope: HTMLElement | null;
  row: HTMLTableRowElement | null;
  editor: HTMLElement | null;
  selectedText: string;
  selectionStart: number | null;
  selectionEnd: number | null;
  range: Range | null;
  href: string | null;
};

type MenuItem = {
  label: string;
  hint?: string;
  disabled?: boolean;
  tone?: "danger";
  run: () => void | Promise<void>;
};

function closestEditor(target: HTMLElement): HTMLElement | null {
  const editor = target.closest<HTMLElement>('input, textarea, [contenteditable="true"], [contenteditable=""]');
  if (!editor) return null;
  if (editor instanceof HTMLInputElement) {
    if (editor.disabled || editor.readOnly || /^(button|submit|reset|checkbox|radio|file|image|hidden|color|range)$/i.test(editor.type)) {
      return null;
    }
  }
  if (editor instanceof HTMLTextAreaElement && (editor.disabled || editor.readOnly)) return null;
  return editor;
}

function inputSelection(editor: HTMLElement | null): { start: number | null; end: number | null; text: string } {
  if (editor instanceof HTMLInputElement || editor instanceof HTMLTextAreaElement) {
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    return {
      start,
      end,
      text: start !== null && end !== null ? editor.value.slice(start, end) : "",
    };
  }
  return { start: null, end: null, text: "" };
}

function selectedRange(): Range | null {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return null;
  try {
    return selection.getRangeAt(0).cloneRange();
  } catch {
    return null;
  }
}

async function writeClipboard(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Try the legacy clipboard command below for browsers that deny the async API.
  }

  const fallback = document.createElement("textarea");
  fallback.value = value;
  fallback.setAttribute("aria-hidden", "true");
  fallback.style.position = "fixed";
  fallback.style.left = "-9999px";
  fallback.style.top = "0";
  document.body.appendChild(fallback);
  fallback.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  } finally {
    fallback.remove();
  }
  return copied;
}

function editableSelectionExists(context: ContextSnapshot): boolean {
  if (!context.editor) return false;
  if (context.editor instanceof HTMLInputElement || context.editor instanceof HTMLTextAreaElement) {
    return context.selectionStart !== null
      && context.selectionEnd !== null
      && context.selectionEnd > context.selectionStart;
  }
  return Boolean(context.range && !context.range.collapsed);
}

function replaceInputSelection(editor: HTMLInputElement | HTMLTextAreaElement, text: string, start: number, end: number) {
  editor.focus();
  try {
    editor.setRangeText(text, start, end, "end");
  } catch {
    // Some input types (for example number/date) don't expose a text selection.
    // Replace the field value rather than failing the paste action.
    editor.value = text;
  }
  editor.dispatchEvent(new Event("input", { bubbles: true }));
}

function replaceRichSelection(editor: HTMLElement, range: Range | null, text: string) {
  editor.focus();
  const activeRange = range?.cloneRange() ?? selectedRange();
  if (activeRange) {
    activeRange.deleteContents();
    if (text) {
      const node = document.createTextNode(text);
      activeRange.insertNode(node);
      activeRange.setStartAfter(node);
    }
    activeRange.collapse(true);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(activeRange);
  } else if (text) {
    document.execCommand("insertText", false, text);
  }
  editor.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: text ? "insertText" : "deleteByCut", data: text || null }));
}

function clickedText(context: ContextSnapshot): string {
  const scopeText = context.row?.innerText?.trim();
  if (scopeText) return scopeText;
  const label = context.scope?.dataset.contextLabel?.trim();
  const scopeBody = context.scope?.innerText?.trim();
  if (scopeBody) return label && label !== scopeBody ? `${label}\n${scopeBody}` : scopeBody;
  if (context.target instanceof HTMLInputElement || context.target instanceof HTMLTextAreaElement) {
    return context.target.value;
  }
  // Don't turn a right-click on empty layout space into "copy the entire app".
  // Without a selection, only copy a small text element or an explicit control/link.
  if (context.target.matches("a, button, code, pre, [data-copy-value]") || context.target.children.length === 0) {
    return context.target.innerText?.trim() || context.target.textContent?.trim() || "";
  }
  return "";
}

function labelForButton(button: HTMLButtonElement): string {
  return (button.getAttribute("title") || button.getAttribute("aria-label") || button.innerText || button.textContent || "Action")
    .replace(/\s+/g, " ")
    .trim();
}

function contextualButtons(context: ContextSnapshot): HTMLButtonElement[] {
  const container = context.row ?? context.scope;
  if (!container) return [];
  return Array.from(container.querySelectorAll<HTMLButtonElement>("button"))
    .filter((button) => {
      if (button.disabled || button.closest("[data-app-context-menu]")) return false;
      const label = labelForButton(button);
      return /inspect|interact|open|view|details|stop|terminate|download|export|enrich|host|copy|hide details/i.test(label);
    })
    .filter((button, index, list) => list.findIndex((other) => labelForButton(other) === labelForButton(button)) === index);
}

function dataValue(context: ContextSnapshot, key: string): string {
  const value = context.scope?.dataset[key] ?? context.row?.dataset[key] ?? "";
  if (key === "contextKind" && !value && context.target.closest(".xterm")) return "console";
  return value;
}

function dispatchContextAction(context: ContextSnapshot, action: string): void {
  window.dispatchEvent(new CustomEvent("msf-context-action", {
    detail: {
      action,
      kind: dataValue(context, "contextKind"),
      index: dataValue(context, "contextIndex"),
      value: dataValue(context, "contextValue"),
    },
  }));
}

function clickRowButton(context: ContextSnapshot, pattern: RegExp): boolean {
  const container = context.row ?? context.scope;
  const button = Array.from(container?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((candidate) => pattern.test(labelForButton(candidate)) && !candidate.disabled);
  if (!button) return false;
  button.click();
  return true;
}

function contextSpecificItems(
  context: ContextSnapshot,
  announce: (message: string) => void,
  close: () => void
): MenuItem[] {
  const kind = dataValue(context, "contextKind");
  const value = dataValue(context, "contextValue");
  const cves = dataValue(context, "contextCves")
    .split(",")
    .map((id) => id.trim().toUpperCase())
    .filter((id) => /^CVE-\d{4}-\d{4,7}$/.test(id));
  let references: string[] = [];
  try {
    const parsed = JSON.parse(dataValue(context, "contextReferences") || "[]");
    if (Array.isArray(parsed)) {
      references = parsed
        .filter((item): item is string => typeof item === "string" && /^https?:\/\//i.test(item))
        .slice(0, 8);
    }
  } catch {
    references = [];
  }
  const items: MenuItem[] = [];
  const add = (label: string, run: MenuItem["run"], hint?: string) => items.push({ label, run, hint });
  const separator = () => items.push({ label: "", disabled: true, run: () => {} });
  const dispatch = (action: string) => () => { dispatchContextAction(context, action); close(); };
  const copyValue = (text: string, message: string) => async () => {
    const ok = await writeClipboard(text);
    announce(ok ? message : "Clipboard access was blocked.");
    close();
  };

  if (["hosts", "services", "vulns", "creds"].includes(kind)) {
    separator();
    add(kind === "vulns" ? "Inspect vulnerability" : kind === "hosts" ? "Inspect host" : kind === "services" ? "Inspect service" : "Inspect credential",
      dispatch("inspect-record"));
    add("Export record JSON", dispatch("export-record"));
    if (kind === "hosts") {
      add("Copy host address", copyValue(value, "Host address copied."), "Ctrl+C");
      add("View related services", dispatch("view-services"));
      add("View vulnerabilities", dispatch("view-vulns"));
    } else if (kind === "services") {
      add("Copy service endpoint", copyValue(value, "Service value copied."));
      add("View host", dispatch("view-host"));
      add("View vulnerabilities", dispatch("view-vulns"));
    } else if (kind === "vulns") {
      add("Enrich via NVD", dispatch("enrich-vuln"));
      if (cves.length) {
        add(cves.length === 1 ? "Copy CVE identifier" : "Copy CVE identifiers", copyValue(cves.join("\n"), "CVE identifier(s) copied."));
        cves.forEach((id) => add(`Open ${id} advisory`, () => {
          window.open(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`, "_blank", "noopener,noreferrer");
          close();
        }));
      }
      references.forEach((url, index) => add(`Open advisory reference ${index + 1}`, () => {
        window.open(url, "_blank", "noopener,noreferrer");
        close();
      }));
    } else if (kind === "creds") {
      add("Copy username", copyValue(value, "Username copied."));
    }
    return items;
  }

  if (kind === "loot") {
    separator();
    add("Inspect evidence", dispatch("inspect-evidence"));
    add("Copy evidence metadata", dispatch("copy-evidence"));
    add("Export evidence metadata", dispatch("export-evidence"));
    add("Download artifact", () => {
      if (!clickRowButton(context, /download/i)) announce("This evidence record has no available download action.");
      close();
    });
    return items;
  }

  if (kind === "console") {
    separator();
    add("Paste into terminal", dispatch("paste-terminal"));
    add("Select all terminal output", dispatch("select-all-terminal"));
    add("Clear terminal display", dispatch("clear-terminal"));
    return items;
  }

  if (kind === "session") {
    separator();
    add("Inspect session details", dispatch("inspect-session"));
    add("Open interactive shell", () => {
      if (!clickRowButton(context, /interact/i)) announce("This session is no longer available.");
      close();
    });
    add("Copy session ID", copyValue(value, "Session ID copied."));
    add("Terminate session", () => {
      if (!clickRowButton(context, /terminate/i)) announce("This session is no longer available.");
      close();
    });
    return items;
  }

  if (kind === "job") {
    separator();
    add("Inspect job", () => {
      if (!clickRowButton(context, /inspect|hide details/i)) announce("Job details are no longer available.");
      close();
    });
    add("Copy job ID", copyValue(value, "Job ID copied."));
    add("Stop job", () => {
      if (!clickRowButton(context, /^stop$/i)) announce("This job is no longer available.");
      close();
    });
    return items;
  }

  if (kind === "module") {
    separator();
    add("Open module details", () => {
      context.scope?.click();
      close();
    });
    add("Copy module path", copyValue(value || dataValue(context, "contextLabel"), "Module path copied."));
    return items;
  }

  return items;
}

function buildItems(
  context: ContextSnapshot,
  announce: (message: string) => void,
  close: () => void
): MenuItem[] {
  const items: MenuItem[] = [];
  const hasSelection = Boolean(context.selectedText);
  const textToCopy = context.selectedText || (context.editor || dataValue(context, "contextKind") === "console" ? "" : clickedText(context));
  const hasEditorSelection = editableSelectionExists(context);
  const editor = context.editor;

  items.push({
    label: hasSelection ? "Copy selection" : "Copy text",
    hint: hasSelection ? "Ctrl+C" : undefined,
    disabled: !textToCopy,
    run: async () => {
      const ok = await writeClipboard(textToCopy);
      announce(ok ? "Copied to clipboard." : "Clipboard access was blocked.");
      close();
    },
  });

  items.push({
    label: "Cut",
    hint: "Ctrl+X",
    disabled: !hasEditorSelection,
    run: async () => {
      if (!editor || !hasEditorSelection) return;
      const cutText = context.selectedText;
      const copied = await writeClipboard(cutText);
      if (!copied) {
        announce("Clipboard access was blocked; nothing was cut.");
        close();
        return;
      }
      if ((editor instanceof HTMLInputElement || editor instanceof HTMLTextAreaElement)
        && context.selectionStart !== null && context.selectionEnd !== null) {
        replaceInputSelection(editor, "", context.selectionStart, context.selectionEnd);
      } else {
        replaceRichSelection(editor, context.range, "");
      }
      announce("Cut to clipboard.");
      close();
    },
  });

  items.push({
    label: "Paste",
    hint: "Ctrl+V",
    disabled: !editor,
    run: async () => {
      if (!editor) return;
      try {
        const text = await navigator.clipboard.readText();
        if (editor instanceof HTMLInputElement || editor instanceof HTMLTextAreaElement) {
          const start = context.selectionStart ?? editor.value.length;
          const end = context.selectionEnd ?? start;
          replaceInputSelection(editor, text, start, end);
        } else {
          replaceRichSelection(editor, context.range, text);
        }
        announce("Pasted from clipboard.");
      } catch {
        announce("Paste was blocked by browser clipboard permissions. Try Ctrl+V instead.");
      }
      close();
    },
  });

  items.push({
    label: "Select all",
    hint: "Ctrl+A",
    run: () => {
      if (editor instanceof HTMLInputElement || editor instanceof HTMLTextAreaElement) {
        editor.focus();
        try {
          editor.setSelectionRange(0, editor.value.length);
        } catch {
          editor.select();
        }
      } else if (editor) {
        editor.focus();
        const range = document.createRange();
        range.selectNodeContents(editor);
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
      } else {
        document.execCommand("selectAll");
      }
      close();
    },
  });

  items.push({
    label: "Undo",
    hint: "Ctrl+Z",
    disabled: !editor,
    run: () => {
      editor?.focus();
      document.execCommand("undo");
      close();
    },
  });
  items.push({
    label: "Redo",
    hint: "Ctrl+Shift+Z",
    disabled: !editor,
    run: () => {
      editor?.focus();
      document.execCommand("redo");
      close();
    },
  });

  if (context.href) {
    items.push({
      label: "Open link in new tab",
      run: () => {
        window.open(context.href!, "_blank", "noopener,noreferrer");
        close();
      },
    });
    items.push({
      label: "Copy link address",
      run: async () => {
        const ok = await writeClipboard(context.href!);
        announce(ok ? "Link copied to clipboard." : "Clipboard access was blocked.");
        close();
      },
    });
  }

  const specificItems = contextSpecificItems(context, announce, close);
  if (specificItems.length) {
    items.push(...specificItems);
    return items;
  }

  const actions = contextualButtons(context);
  if (context.scope instanceof HTMLButtonElement && context.scope.dataset.contextKind) {
    items.push({
      label: "Activate item",
      run: () => {
        context.scope?.click();
        close();
      },
    });
  }

  if (context.row || context.scope?.dataset.contextKind) {
    items.push({
      label: "Copy item details",
      run: async () => {
        const ok = await writeClipboard(clickedText(context));
        announce(ok ? "Item details copied." : "Clipboard access was blocked.");
        close();
      },
    });
  }

  if (actions.length) {
    items.push({ label: "", disabled: true, run: () => {} });
    for (const button of actions) {
      items.push({
        label: labelForButton(button),
        run: () => {
          if (!button.isConnected || button.disabled) {
            announce("That action is no longer available.");
          } else {
            button.click();
          }
          close();
        },
      });
    }
  }
  return items;
}

export function ContextMenu() {
  const [context, setContext] = useState<ContextSnapshot | null>(null);
  const [notice, setNotice] = useState("");
  const menuRef = useRef<HTMLDivElement>(null);
  const noticeTimer = useRef<number | null>(null);
  const idRef = useRef(0);

  const announce = (message: string) => {
    setNotice(message);
    if (noticeTimer.current !== null) window.clearTimeout(noticeTimer.current);
    noticeTimer.current = window.setTimeout(() => setNotice(""), 2400);
  };
  const close = () => setContext(null);

  useEffect(() => {
    const handleContextMenu = (event: MouseEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null;
      if (!target) return;
      if (target.closest("[data-native-context-menu], [data-context-menu-ignore], [data-app-context-menu]")) return;

      event.preventDefault();
      const terminal = target.closest<HTMLElement>(".xterm");
      const editor = closestEditor(target);
      const input = inputSelection(editor);
      const range = editor && !(editor instanceof HTMLInputElement) && !(editor instanceof HTMLTextAreaElement)
        ? selectedRange()
        : null;
      const terminalSelection = { text: "" };
      if (terminal) window.dispatchEvent(new CustomEvent("msf-terminal-selection-query", { detail: terminalSelection }));
      const selection = terminal
        ? terminalSelection.text || window.getSelection()?.toString() || ""
        : input.text || window.getSelection()?.toString() || "";
      const row = target.closest<HTMLTableRowElement>("tr");
      const scope = target.closest<HTMLElement>("[data-context-kind]") ?? row ?? terminal;
      const link = target.closest<HTMLAnchorElement>("a[href]");

      setContext({
        id: ++idRef.current,
        x: event.clientX,
        y: event.clientY,
        target,
        scope,
        row,
        editor,
        selectedText: selection,
        selectionStart: input.start,
        selectionEnd: input.end,
        range,
        href: link?.href ?? null,
      });
    };

    const handleOutsideClick = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) close();
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (!context) return;
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
      const buttons = Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('button[role="menuitem"]:not(:disabled)') ?? []);
      if (!buttons.length) return;
      event.preventDefault();
      const current = buttons.indexOf(document.activeElement as HTMLButtonElement);
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = current < 0 ? (step > 0 ? 0 : buttons.length - 1) : (current + step + buttons.length) % buttons.length;
      buttons[next]?.focus();
    };

    const handleContextNotice = (event: Event) => {
      const message = (event as CustomEvent<string>).detail;
      if (typeof message === "string" && message) announce(message);
    };

    document.addEventListener("contextmenu", handleContextMenu);
    document.addEventListener("click", handleOutsideClick);
    document.addEventListener("keydown", handleKeyDown);
    window.addEventListener("msf-context-notice", handleContextNotice);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("contextmenu", handleContextMenu);
      document.removeEventListener("click", handleOutsideClick);
      document.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("msf-context-notice", handleContextNotice);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
      if (noticeTimer.current !== null) window.clearTimeout(noticeTimer.current);
    };
    // The menu's key handler needs the current open/closed state.
  }, [context]);

  useEffect(() => {
    if (!context) return;
    const frame = window.requestAnimationFrame(() => {
      const menu = menuRef.current;
      if (!menu) return;
      const bounds = menu.getBoundingClientRect();
      const x = Math.max(8, Math.min(context.x, window.innerWidth - bounds.width - 8));
      const y = Math.max(8, Math.min(context.y, window.innerHeight - bounds.height - 8));
      if (x !== context.x || y !== context.y) {
        setContext((current) => current?.id === context.id ? { ...current, x, y } : current);
      }
      menu.querySelector<HTMLButtonElement>('button[role="menuitem"]:not(:disabled)')?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [context?.id]);

  const items = context ? buildItems(context, announce, close) : [];
  const contextKind = context?.scope?.dataset.contextKind;
  const contextLabel = context?.scope?.dataset.contextLabel
    || context?.scope?.innerText.trim().slice(0, 100)
    || "";

  return (
    <>
      {context && (
        <div
          ref={menuRef}
          data-app-context-menu
          role="menu"
          aria-label="Application context menu"
          className="fixed z-[100] w-64 max-h-[min(70vh,520px)] overflow-y-auto rounded-md border border-border bg-[#111820] p-1.5 text-xs text-gray-200 shadow-2xl shadow-black/60"
          style={{ left: context.x, top: context.y }}
          onContextMenu={(event) => event.preventDefault()}
        >
          {context && (contextLabel || contextKind) && (
            <div className="border-b border-border/80 px-2 py-2">
              <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-gray-500">
                {contextKind || "Item"}
              </div>
              <div className="mt-1 truncate font-mono text-[11px] text-gray-200" title={contextLabel}>
                {contextLabel}
              </div>
            </div>
          )}
          <div className="py-1">
            {items.map((item, index) => item.label ? (
              <button
                key={`${item.label}-${index}`}
                type="button"
                role="menuitem"
                disabled={item.disabled}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => void item.run()}
                className={`flex w-full items-center justify-between gap-3 rounded px-2 py-1.5 text-left transition-colors focus:outline-none focus:bg-bg-tertiary disabled:cursor-not-allowed disabled:opacity-30 ${item.tone === "danger" ? "text-danger hover:bg-danger/10" : "hover:bg-bg-tertiary"}`}
              >
                <span>{item.label}</span>
                {item.hint && <span className="shrink-0 text-[10px] text-gray-600">{item.hint}</span>}
              </button>
            ) : (
              <div key={`separator-${index}`} role="separator" className="my-1 border-t border-border/80" />
            ))}
          </div>
          <div className="border-t border-border/70 px-2 py-1.5 text-[9px] text-gray-600">
            MSF Web Console · Esc to close
          </div>
        </div>
      )}
      {notice && (
        <div role="status" className="fixed bottom-4 right-4 z-[110] rounded border border-border bg-[#111820] px-3 py-2 text-xs text-gray-200 shadow-lg">
          {notice}
        </div>
      )}
    </>
  );
}
