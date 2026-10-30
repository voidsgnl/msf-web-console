import { useEffect, useState } from "react";
import { Sidebar, View } from "./components/Sidebar";
import { ConsoleView } from "./components/ConsoleView";
import { ModuleBrowser, ModuleSearchRequest } from "./components/ModuleBrowser";
import { ScanWizard } from "./components/ScanWizard";
import { RecipesView } from "./components/RecipesView";
import { SessionsView } from "./components/SessionsView";
import { HostsView } from "./components/HostsView";
import { JobsView } from "./components/JobsView";
import { WorkspaceSwitcher } from "./components/WorkspaceSwitcher";
import { LoginView } from "./components/LoginView";
import { ContextMenu } from "./components/ContextMenu";
import { api } from "./lib/api";

type AuthStatus = "checking" | "authenticated" | "unauthenticated";

export default function App() {
  const [view, setView] = useState<View>("console");
  // Each view mounts the first time it's opened, then stays mounted (hidden
  // with CSS) instead of unmounting on every switch - so a module execution
  // keeps polling, a job/session detail panel stays open, and search/filter
  // state survives even if you check another tab mid-run and come back.
  const [visitedViews, setVisitedViews] = useState<Set<View>>(() => new Set(["console"]));
  const [connected, setConnected] = useState(false);
  const [checked, setChecked] = useState(false);
  const [workspaceRevision, setWorkspaceRevision] = useState(0);
  const [moduleSearchRequest, setModuleSearchRequest] = useState<ModuleSearchRequest | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus>("checking");
  const [authConfigured, setAuthConfigured] = useState<boolean | null>(null);
  const [username, setUsername] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.auth.session()
      .then((result) => {
        if (!active) return;
        setAuthConfigured(result.configured);
        setUsername(result.username ?? "");
        setAuthStatus(result.authenticated ? "authenticated" : "unauthenticated");
      })
      .catch((cause: unknown) => {
        if (!active) return;
        setAuthConfigured(null);
        setAuthStatus("unauthenticated");
        setAuthError(cause instanceof Error ? cause.message : "Unable to contact the backend.");
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const requireLogin = () => {
      setUsername("");
      setAuthStatus("unauthenticated");
      setAuthError("Your login session expired or is no longer valid. Please sign in again.");
    };
    window.addEventListener("msf-auth-required", requireLogin);
    return () => window.removeEventListener("msf-auth-required", requireLogin);
  }, []);

  useEffect(() => {
    if (authStatus !== "authenticated") return;
    let active = true;
    const check = () =>
      api.status()
        .then((status) => { if (active) setConnected(status.connected); })
        .catch(() => { if (active) setConnected(false); })
        .finally(() => { if (active) setChecked(true); });
    void check();
    const timer = window.setInterval(() => void check(), 10000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [authStatus]);

  const visit = (next: View) => {
    setView(next);
    setVisitedViews((current) => (current.has(next) ? current : new Set(current).add(next)));
  };

  // Drives the module browser's search from outside (the scan wizard's
  // "Investigate in Modules" button) and switches to that tab.
  const investigateModules = (type: string, query: string) => {
    setModuleSearchRequest({ type, query, nonce: Date.now() });
    visit("modules");
  };

  const finishLogin = (name: string) => {
    setUsername(name);
    setAuthConfigured(true);
    setAuthError(null);
    setAuthStatus("authenticated");
  };

  const logout = async () => {
    try {
      await api.auth.logout();
    } catch (cause: unknown) {
      setAuthError(cause instanceof Error ? cause.message : "Logout request failed.");
    } finally {
      setUsername("");
      setAuthStatus("unauthenticated");
      setConnected(false);
      setChecked(false);
    }
  };

  if (authStatus === "checking") {
    return (
      <main className="flex h-screen w-screen items-center justify-center bg-bg-primary">
        <div className="text-xs uppercase tracking-[0.2em] text-gray-500">Checking local session…</div>
      </main>
    );
  }

  if (authStatus !== "authenticated") {
    return (
      <LoginView
        configured={authConfigured}
        initialError={authError}
        onAuthenticated={finishLogin}
      />
    );
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <ContextMenu />
      <Sidebar active={view} onSelect={visit} connected={connected} />

      <div className="flex min-w-0 flex-1 flex-col">
        {checked && !connected && (
          <div className="border-b border-warning/30 bg-warning/10 px-4 py-2 text-xs text-warning">
            Cannot reach msfrpcd. Start it and check backend/.env — see README for the exact command.
          </div>
        )}

        <div className="relative z-20 flex h-12 shrink-0 items-center justify-end gap-3 border-b border-border bg-bg-secondary px-4">
          <span className="hidden max-w-40 truncate text-[10px] text-gray-500 sm:inline" title={username}>
            Signed in as <span className="text-gray-300">{username}</span>
          </span>
          <WorkspaceSwitcher onWorkspaceChanged={() => setWorkspaceRevision((revision) => revision + 1)} />
          <button
            type="button"
            onClick={() => void logout()}
            className="rounded border border-border px-2.5 py-1.5 text-xs text-gray-400 hover:bg-bg-tertiary hover:text-gray-100"
          >
            Sign out
          </button>
        </div>

        <div className="min-h-0 flex-1 relative">
          {visitedViews.has("console") && (
            <div className="absolute inset-0" style={{ display: view === "console" ? "block" : "none" }}>
              <ConsoleView />
            </div>
          )}
          {visitedViews.has("scan") && (
            <div className="absolute inset-0 overflow-y-auto" style={{ display: view === "scan" ? "block" : "none" }}>
              <ScanWizard onInvestigate={investigateModules} />
            </div>
          )}
          {visitedViews.has("recipes") && (
            <div className="absolute inset-0 overflow-y-auto" style={{ display: view === "recipes" ? "block" : "none" }}>
              <RecipesView onOpenModule={investigateModules} />
            </div>
          )}
          {visitedViews.has("modules") && (
            <div className="absolute inset-0 overflow-hidden" style={{ display: view === "modules" ? "block" : "none" }}>
              <ModuleBrowser
                onViewSessions={() => visit("sessions")}
                onViewJobs={() => visit("jobs")}
                externalSearchRequest={moduleSearchRequest}
              />
            </div>
          )}
          {visitedViews.has("sessions") && (
            <div className="absolute inset-0 overflow-y-auto" style={{ display: view === "sessions" ? "block" : "none" }}>
              <SessionsView />
            </div>
          )}
          {visitedViews.has("hosts") && (
            <div className="absolute inset-0 overflow-y-auto" style={{ display: view === "hosts" ? "block" : "none" }}>
              <HostsView key={workspaceRevision} />
            </div>
          )}
          {visitedViews.has("jobs") && (
            <div className="absolute inset-0 overflow-y-auto" style={{ display: view === "jobs" ? "block" : "none" }}>
              <JobsView />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
