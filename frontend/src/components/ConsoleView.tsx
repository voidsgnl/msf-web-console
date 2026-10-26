import { useState } from "react";
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

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center h-10 bg-bg-secondary border-b border-border px-2 gap-1 overflow-x-auto">
        {tabs.map((id, i) => (
          <div
            key={id}
            onClick={() => setActive(id)}
            className={`flex items-center gap-2 h-7 px-3 rounded-t text-xs font-mono cursor-pointer ${
              active === id ? "bg-bg-primary text-gray-100" : "text-gray-500 hover:text-gray-300"
            }`}
          >
            <span>console #{i + 1}</span>
            {tabs.length > 1 && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(id);
                }}
                className="hover:text-danger"
              >
                ×
              </button>
            )}
          </div>
        ))}
        <button
          onClick={addTab}
          className="h-7 w-7 flex items-center justify-center text-gray-500 hover:text-gray-200 text-sm"
          title="New console tab"
        >
          +
        </button>
      </div>

      <div className="flex-1 min-h-0 relative">
        {tabs.map((id) => (
          <div key={id} className="absolute inset-0" style={{ display: active === id ? "block" : "none" }}>
            <ConsoleTab />
          </div>
        ))}
      </div>
    </div>
  );
}
