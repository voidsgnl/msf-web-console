import { useState } from "react";
import type { ReactNode } from "react";

export type View = "console" | "scan" | "recipes" | "modules" | "sessions" | "hosts" | "jobs";

export type NavItem = {
  id: View;
  label: string;
  description: string;
  group: string;
  icon: ReactNode;
};

function Icon({ children }: { children: ReactNode }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="shrink-0"
    >
      {children}
    </svg>
  );
}

export const NAV: NavItem[] = [
  {
    id: "console",
    label: "Console",
    description: "Live msfconsole terminal",
    group: "Operate",
    icon: (
      <Icon>
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </Icon>
    ),
  },
  {
    id: "scan",
    label: "Scan",
    description: "Discover hosts and services",
    group: "Operate",
    icon: (
      <Icon>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="5" />
        <circle cx="12" cy="12" r="1" />
      </Icon>
    ),
  },
  {
    id: "recipes",
    label: "Recipes",
    description: "Saved workflows",
    group: "Operate",
    icon: (
      <Icon>
        <path d="M4 5h16" />
        <path d="M4 12h16" />
        <path d="M4 19h10" />
      </Icon>
    ),
  },
  {
    id: "modules",
    label: "Modules",
    description: "Browse, check and run modules",
    group: "Framework",
    icon: (
      <Icon>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </Icon>
    ),
  },
  {
    id: "sessions",
    label: "Sessions",
    description: "Active sessions and shells",
    group: "Framework",
    icon: (
      <Icon>
        <rect x="3" y="4" width="18" height="12" rx="2" />
        <line x1="8" y1="20" x2="16" y2="20" />
        <line x1="12" y1="16" x2="12" y2="20" />
      </Icon>
    ),
  },
  {
    id: "hosts",
    label: "Hosts / DB",
    description: "Workspace database views",
    group: "Framework",
    icon: (
      <Icon>
        <ellipse cx="12" cy="5" rx="8" ry="3" />
        <path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" />
        <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
      </Icon>
    ),
  },
  {
    id: "jobs",
    label: "Jobs",
    description: "Running and queued jobs",
    group: "Framework",
    icon: (
      <Icon>
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </Icon>
    ),
  },
];

const GROUPS = ["Operate", "Framework"];
const COLLAPSE_KEY = "msf-sidebar-collapsed";

function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

export function Sidebar({
  active,
  onSelect,
  connected,
}: {
  active: View;
  onSelect: (v: View) => void;
  connected: boolean;
}) {
  const [collapsed, setCollapsed] = useState<boolean>(readCollapsed);

  const toggle = () => {
    setCollapsed((current) => {
      const next = !current;
      try {
        window.localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
      } catch {
        // storage unavailable; the toggle still works for this session
      }
      return next;
    });
  };

  return (
    <aside
      aria-label="Primary"
      className={`flex shrink-0 flex-col border-r border-border bg-bg-secondary transition-[width] duration-200 ${
        collapsed ? "w-[60px]" : "w-60"
      }`}
    >
      <div className={`flex h-14 shrink-0 items-center gap-2.5 border-b border-border ${collapsed ? "justify-center" : "px-4"}`}>
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent-dim font-mono text-sm font-bold text-black shadow-glow">
          M
        </span>
        {!collapsed && (
          <div className="min-w-0 leading-tight">
            <div className="truncate font-mono text-[13px] font-semibold text-gray-100">msf-console</div>
            <div className="truncate text-[10px] uppercase tracking-[0.18em] text-gray-500">Metasploit UI</div>
          </div>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {GROUPS.map((group, groupIndex) => (
          <div key={group} className={groupIndex > 0 ? "mt-4" : ""}>
            {collapsed ? (
              groupIndex > 0 && <div className="mx-2 mb-2 border-t border-border" />
            ) : (
              <div className="mb-1.5 px-2.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-gray-600">
                {group}
              </div>
            )}
            <div className="space-y-0.5">
              {NAV.filter((item) => item.group === group).map((item) => {
                const isActive = active === item.id;
                const shortcut = NAV.indexOf(item) + 1;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onSelect(item.id)}
                    aria-current={isActive ? "page" : undefined}
                    title={collapsed ? `${item.label} (Alt+${shortcut})` : undefined}
                    className={`group relative flex h-9 w-full items-center gap-3 rounded-md px-2.5 text-sm transition-colors ${
                      collapsed ? "justify-center" : ""
                    } ${
                      isActive
                        ? "bg-accent/10 text-white"
                        : "text-gray-400 hover:bg-bg-tertiary hover:text-gray-100"
                    }`}
                  >
                    {isActive && (
                      <span className="absolute bottom-1.5 left-0 top-1.5 w-[3px] rounded-r bg-accent" aria-hidden="true" />
                    )}
                    <span className={isActive ? "text-accent" : "text-gray-500 group-hover:text-gray-300"}>
                      {item.icon}
                    </span>
                    {!collapsed && (
                      <>
                        <span className="flex-1 truncate text-left">{item.label}</span>
                        <span className="hidden font-mono text-[10px] text-gray-600 group-hover:inline">Alt+{shortcut}</span>
                      </>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="shrink-0 space-y-1 border-t border-border p-2">
        <div
          role="status"
          title={connected ? "msfrpcd connected" : "msfrpcd unreachable"}
          className={`flex h-9 items-center gap-2.5 rounded-md px-2.5 text-xs ${
            connected ? "bg-accent/5" : "bg-danger/10"
          } ${collapsed ? "justify-center" : ""}`}
        >
          <span className="relative flex h-2 w-2 shrink-0">
            {connected && (
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-60" />
            )}
            <span className={`relative inline-flex h-2 w-2 rounded-full ${connected ? "bg-accent" : "bg-danger"}`} />
          </span>
          {!collapsed && (
            <span className={connected ? "text-gray-400" : "text-danger"}>
              {connected ? "msfrpcd connected" : "msfrpcd offline"}
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={`flex h-8 w-full items-center gap-2.5 rounded-md px-2.5 text-xs text-gray-500 transition-colors hover:bg-bg-tertiary hover:text-gray-300 ${
            collapsed ? "justify-center" : ""
          }`}
        >
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
            className={`shrink-0 transition-transform ${collapsed ? "rotate-180" : ""}`}
          >
            <polyline points="11 17 6 12 11 7" />
            <polyline points="18 17 13 12 18 7" />
          </svg>
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
