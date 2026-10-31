import { useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { ConsoleTab } from "./ConsoleTab";

let nextId = 1;

export function ConsoleView() {
  const [tabs, setTabs] = useState<number[]>([nextId++]);
  const [active, setActive] = useState<number>(tabs[0]);

  const addTab = () => {
    const id = nextId++;
    setTabs((t) => [...t, id]);
    setActive(id);
  };

  const closeTab = (id: number) => {
    setTabs((t) => {
      const remaining = t.filter((x) => x !== id);
      if (active === id && remaining.length > 0) setActive(remaining[remaining.length - 1]);
      return remaining.length > 0 ? remaining : [nextId++];
    });
  };

  const onTabKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>, id: number) => {
    if (event.target !== event.currentTarget) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      setActive(id);
    }
  };

  return (
    <div className="flex h-full flex-col bg-bg-primary">
      <div
        role="tablist"
        aria-label="Console tabs"
        className="flex h-11 shrink-0 items-end gap-1 overflow-x-auto border-b border-border bg-bg-secondary px-3"
      >
        {tabs.map((id, i) => {
          const isActive = active === id;
          return (
            <div
              key={id}
              role="tab"
              tabIndex={0}
              aria-selected={isActive}
              onClick={() => setActive(id)}
              onKeyDown={(event) => onTabKeyDown(event, id)}
              className={`group relative flex h-9 shrink-0 cursor-pointer items-center gap-2 rounded-t-md border border-b-0 px-3 font-mono text-xs transition-colors ${
                isActive
                  ? "border-border bg-bg-primary text-gray-100"
                  : "border-transparent text-gray-500 hover:bg-bg-tertiary hover:text-gray-300"
              }`}
            >
              {isActive && <span className="absolute inset-x-0 top-0 h-[2px] rounded-t bg-accent" aria-hidden="true" />}
              <span className={`h-1.5 w-1.5 rounded-full ${isActive ? "bg-accent" : "bg-gray-600"}`} aria-hidden="true" />
              <span>console #{i + 1}</span>
              {tabs.length > 1 && (
                <button
                  type="button"
                  aria-label={`Close console #${i + 1}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    closeTab(id);
                  }}
                  className="flex h-4 w-4 items-center justify-center rounded text-gray-500 hover:bg-bg-elevated hover:text-danger"
                >
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" aria-hidden="true">
                    <line x1="6" y1="6" x2="18" y2="18" />
                    <line x1="18" y1="6" x2="6" y2="18" />
                  </svg>
                </button>
              )}
            </div>
          );
        })}
        <button
          type="button"
          onClick={addTab}
          className="mb-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-gray-500 transition-colors hover:bg-bg-tertiary hover:text-gray-200"
          title="New console tab"
          aria-label="New console tab"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" aria-hidden="true">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
        </button>
      </div>

      <div className="relative min-h-0 flex-1">
        {tabs.map((id) => (
          <div key={id} className="absolute inset-0" style={{ display: active === id ? "block" : "none" }}>
            <ConsoleTab />
          </div>
        ))}
      </div>
    </div>
  );
}
