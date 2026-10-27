import { useEffect, useState } from "react";
import { Sidebar, View } from "./components/Sidebar";
import { ConsoleView } from "./components/ConsoleView";
import { ModuleBrowser } from "./components/ModuleBrowser";
import { SessionsView } from "./components/SessionsView";
import { HostsView } from "./components/HostsView";
import { JobsView } from "./components/JobsView";
import { WorkspaceSwitcher } from "./components/WorkspaceSwitcher";
import { api } from "./lib/api";

export default function App() {
  const [view, setView] = useState<View>("console");
  const [connected, setConnected] = useState(false);
  const [checked, setChecked] = useState(false);
  const [workspaceRevision, setWorkspaceRevision] = useState(0);

  useEffect(() => {
    const check = () =>
      api
        .status()
        .then((s) => setConnected(s.connected))
        .catch(() => setConnected(false))
        .finally(() => setChecked(true));
    check();
    const t = setInterval(check, 10000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <Sidebar active={view} onSelect={setView} connected={connected} />

      <div className="flex-1 flex flex-col min-w-0">
        {checked && !connected && (
          <div className="bg-warning/10 border-b border-warning/30 text-warning text-xs px-4 py-2">
            Cannot reach msfrpcd. Start it and check backend/.env — see README for the exact
            command.
          </div>
        )}

        <div className="relative z-20 h-12 shrink-0 flex items-center justify-end px-4 border-b border-border bg-bg-secondary">
          <WorkspaceSwitcher onWorkspaceChanged={() => setWorkspaceRevision((revision) => revision + 1)} />
        </div>

        <div className="flex-1 min-h-0">
          {view === "console" && <ConsoleView />}
          {view === "modules" && <ModuleBrowser onViewSessions={() => setView("sessions")} />}
          {view === "sessions" && <SessionsView />}
          {view === "hosts" && <HostsView key={workspaceRevision} />}
          {view === "jobs" && <JobsView />}
        </div>
      </div>
    </div>
  );
}
