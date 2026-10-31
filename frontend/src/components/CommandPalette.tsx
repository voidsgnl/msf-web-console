import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";
import { NAV } from "./Sidebar";
import type { View } from "./Sidebar";

export type PaletteAction = {
  id: string;
  label: string;
  hint?: string;
  keywords?: string;
  run: () => void;
};

type PaletteItem = {
  id: string;
  label: string;
  hint?: string;
  group: string;
  keywords: string;
  icon?: ReactNode;
  run: () => void;
};

const NO_ACTIONS: PaletteAction[] = [];

export function CommandPalette({
  open,
  onClose,
  onSelectView,
  actions = NO_ACTIONS,
}: {
  open: boolean;
  onClose: () => void;
  onSelectView: (view: View) => void;
  actions?: PaletteAction[];
}) {
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const items = useMemo<PaletteItem[]>(() => {
    const views: PaletteItem[] = NAV.map((item) => ({
      id: `view-${item.id}`,
      label: `Go to ${item.label}`,
      hint: item.description,
      group: "Navigate",
      keywords: `${item.id} ${item.label} ${item.description}`,
      icon: item.icon,
      run: () => onSelectView(item.id),
    }));
    const extra: PaletteItem[] = actions.map((action) => ({
      id: action.id,
      label: action.label,
      hint: action.hint,
      group: "Actions",
      keywords: action.keywords ?? "",
      run: action.run,
    }));
    return [...views, ...extra];
  }, [actions, onSelectView]);

  const filtered = useMemo(() => {
    const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return items;
    return items.filter((item) => {
      const haystack = `${item.label} ${item.group} ${item.keywords}`.toLowerCase();
      return tokens.every((token) => haystack.includes(token));
    });
  }, [items, query]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setIndex(0);
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [open]);

  useEffect(() => {
    setIndex(0);
  }, [query]);

  useEffect(() => {
    const active = listRef.current?.querySelector('[data-active="true"]');
    if (active instanceof HTMLElement) active.scrollIntoView({ block: "nearest" });
  }, [index, filtered]);

  if (!open) return null;

  const choose = (item: PaletteItem | undefined) => {
    if (!item) return;
    onClose();
    item.run();
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setIndex((current) => (filtered.length === 0 ? 0 : (current + 1) % filtered.length));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setIndex((current) => (filtered.length === 0 ? 0 : (current - 1 + filtered.length) % filtered.length));
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(filtered[index]);
    } else if (event.key === "Escape") {
      event.preventDefault();
      onClose();
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[14vh] backdrop-blur-sm animate-fade-in"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="w-full max-w-xl overflow-hidden rounded-xl border border-border-strong bg-bg-secondary shadow-pop animate-pop-in"
      >
        <div className="flex items-center gap-3 border-b border-border px-4">
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.75}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            className="shrink-0 text-gray-500"
          >
            <circle cx="11" cy="11" r="7" />
            <line x1="21" y1="21" x2="16.5" y2="16.5" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Jump to a view or run an action…"
            aria-label="Search commands"
            className="h-12 w-full border-0 bg-transparent text-sm text-gray-100 outline-none placeholder:text-gray-600"
          />
          <span className="kbd">Esc</span>
        </div>

        <div ref={listRef} role="listbox" className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="px-3 py-8 text-center text-sm text-gray-500">No matching commands</div>
          ) : (
            filtered.map((item, itemIndex) => {
              const isActive = itemIndex === index;
              const showGroup = itemIndex === 0 || filtered[itemIndex - 1].group !== item.group;
              return (
                <div key={item.id}>
                  {showGroup && (
                    <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-gray-600">
                      {item.group}
                    </div>
                  )}
                  <button
                    type="button"
                    role="option"
                    aria-selected={isActive}
                    data-active={isActive}
                    onMouseEnter={() => setIndex(itemIndex)}
                    onClick={() => choose(item)}
                    className={`flex h-10 w-full items-center gap-3 rounded-md px-3 text-left text-sm transition-colors ${
                      isActive ? "bg-accent/10 text-white" : "text-gray-300"
                    }`}
                  >
                    <span className={`flex w-[18px] shrink-0 justify-center ${isActive ? "text-accent" : "text-gray-500"}`}>
                      {item.icon}
                    </span>
                    <span className="flex-1 truncate">{item.label}</span>
                    {item.hint && <span className="hidden truncate text-xs text-gray-500 sm:inline">{item.hint}</span>}
                  </button>
                </div>
              );
            })
          )}
        </div>

        <div className="flex items-center gap-4 border-t border-border bg-bg-primary/40 px-4 py-2 text-[11px] text-gray-500">
          <span className="flex items-center gap-1.5"><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
          <span className="flex items-center gap-1.5"><span className="kbd">↵</span> select</span>
        </div>
      </div>
    </div>
  );
}
