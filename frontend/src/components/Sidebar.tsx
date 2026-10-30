import { useState } from "react";

export type View = "console" | "scan" | "recipes" | "modules" | "sessions" | "hosts" | "jobs";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "console", label: "Console", icon: "❯_" },
  { id: "scan", label: "Scan", icon: "◎" },
  { id: "recipes", label: "Recipes", icon: "▤" },
  { id: "modules", label: "Modules", icon: "▦" },
  { id: "sessions", label: "Sessions", icon: "⬡" },
  { id: "hosts", label: "Hosts / DB", icon: "⛁" },
  { id: "jobs", label: "Jobs", icon: "⚙" },
];

export function Sidebar({
  active,
  onSelect,
  connected,
}: {
  active: View;
  onSelect: (v: View) => void;
  connected: boolean;
}) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div
      className={`flex flex-col bg-bg-secondary border-r border-border transition-all ${
        collapsed ? "w-14" : "w-56"
      }`}
    >
      <div className="h-14 flex items-center px-4 border-b border-border justify-between">
        {!collapsed && (
          <span className="font-mono text-sm font-medium text-gray-100 tracking-tight">
            msf-console
          </span>
        )}
        <button
          onClick={() => setCollapsed((c) => !c)}
          className="text-gray-500 hover:text-gray-300 text-xs"
          title="Toggle sidebar"
        >
          {collapsed ? "»" : "«"}
        </button>
      </div>

      <nav className="flex-1 py-2">
        {NAV.map((item) => (
          <button
            key={item.id}
            onClick={() => onSelect(item.id)}
            className={`w-full flex items-center gap-3 px-4 h-9 text-sm transition-colors ${
              active === item.id
                ? "bg-bg-tertiary text-gray-100 border-l-2 border-accent"
                : "text-gray-400 hover:text-gray-200 hover:bg-bg-tertiary border-l-2 border-transparent"
            }`}
          >
            <span className="font-mono w-4 text-center">{item.icon}</span>
            {!collapsed && <span>{item.label}</span>}
          </button>
        ))}
      </nav>

      <div className="px-4 h-10 flex items-center gap-2 border-t border-border text-xs">
        <span
          className={`w-2 h-2 rounded-full ${connected ? "bg-accent" : "bg-danger"}`}
        />
        {!collapsed && (
          <span className="text-gray-500">{connected ? "msfrpcd connected" : "disconnected"}</span>
        )}
      </div>
    </div>
  );
}
