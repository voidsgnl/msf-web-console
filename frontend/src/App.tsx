import { useCallback, useEffect, useMemo, useState } from "react";
import { Sidebar, NAV } from "./components/Sidebar";
import type { View } from "./components/Sidebar";
import { ConsoleView } from "./components/ConsoleView";
import { ModuleBrowser } from "./components/ModuleBrowser";
import type { ModuleSearchRequest, TargetContext } from "./components/ModuleBrowser";
import { WebSecurityView } from "./components/WebSecurityView";
import { RecipesView } from "./components/RecipesView";
import { SessionsView } from "./components/SessionsView";
import { HostsView } from "./components/HostsView";
import { JobsView } from "./components/JobsView";
import { WorkspaceSwitcher } from "./components/WorkspaceSwitcher";
import { LoginView } from "./components/LoginView";
import { ContextMenu } from "./components/ContextMenu";
import { CommandPalette } from "./components/CommandPalette";
import type { PaletteAction } from "./components/CommandPalette";
import { Spinner } from "./components/ui";
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
  const [paletteOpen, setPaletteOpen] = useState(false);

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

  const visit = useCallback((next: View) => {
    setView(next);
    setVisitedViews((current) => (current.has(next) ? current : new Set(current).add(next)));
  }, []);

  // Keyboard shortcuts: Ctrl/Cmd+K opens the command palette, Alt+1..8 jumps
  // straight to a view (matches the order shown in the sidebar).
  useEffect(() => {
    if (authStatus !== "authenticated") return;
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
        return;
      }
      if (event.altKey && !event.ctrlKey && !event.metaKey && event.code.startsWith("Digit")) {
        const target = NAV[Number(event.code.slice(5)) - 1];
        if (target) {
          event.preventDefault();
          visit(target.id);
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [authStatus, visit]);

  // Drives the module browser's search from supported investigation workflows.
  const investigateModules = (type: string, query: string, targetContext?: TargetContext) => {
    setModuleSearchRequest({ type, query, nonce: Date.now(), targetContext });
    visit("modules");
  };

  const finishLogin = (name: string) => {
    setUsername(name);
    setAuthConfigured(true);
    setAuthError(null);
    setAuthStatus("authenticated");
  };

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch (cause: unknown) {
      setAuthError(cause instanceof Error ? cause.message : "Logout request failed.");
    } finally {
      setUsername("");
      setAuthStatus("unauthenticated");
      setConnected(false);
      setChecked(false);
      setPaletteOpen(false);
    }
  }, []);

  const paletteActions = useMemo<PaletteAction[]>(
    () => [
      {
        id: "sign-out",
        label: "Sign out",
        hint: "End this local session",
        keywords: "logout log out exit",
        run: () => void logout(),
      },
    ],
    [logout],
  );

  if (authStatus === "checking") {
    return (
      <main className="flex h-screen w-screen flex-col items-center justify-center gap-3 bg-bg-primary">
        <Spinner className="h-5 w-5 text-accent" />
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

  const current = NAV.find((item) => item.id === view);
  const initial = username.trim().charAt(0).toUpperCase() || "?";

  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <ContextMenu />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onSelectView={visit}
        actions={paletteActions}
      />
      <Sidebar active={view} onSelect={visit} connected={connected} />

      <div className="flex min-w-0 flex-1 flex-col">
        {checked && !connected && (
          <div
            role="alert"
            className="flex items-center gap-2 border-b border-warning/30 bg-warning/10 px-4 py-2 text-xs text-warning"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="shrink-0">
              <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>Cannot reach msfrpcd. Start it and check backend/.env — see README for the exact command.</span>
          </div>
        )}

        <header className="relative z-20 flex h-14 shrink-0 items-center gap-3 border-b border-border bg-bg-secondary px-4">
          <div className="min-w-0">
            <h1 className="truncate text-sm font-semibold text-gray-100">{current?.label}</h1>
            <p className="hidden truncate text-[11px] text-gray-500 md:block">{current?.description}</p>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              aria-label="Open command palette"
              className="hidden h-8 items-center gap-2 rounded-md border border-border-strong bg-bg-primary px-2.5 text-xs text-gray-500 transition-colors hover:border-gray-600 hover:text-gray-300 sm:flex"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="11" cy="11" r="7" />
                <line x1="21" y1="21" x2="16.5" y2="16.5" />
              </svg>
              <span>Jump to…</span>
              <span className="kbd">Ctrl K</span>
            </button>

            <WorkspaceSwitcher onWorkspaceChanged={() => setWorkspaceRevision((revision) => revision + 1)} />

            <div className="flex items-center gap-2 border-l border-border pl-3">
              <span
                className="flex h-7 w-7 items-center justify-center rounded-full bg-bg-elevated text-xs font-semibold text-gray-200"
                title={`Signed in as ${username}`}
                aria-hidden="true"
              >
                {initial}
              </span>
              <span className="hidden max-w-32 truncate text-xs text-gray-400 lg:inline" title={username}>
                {username}
              </span>
              <button
                type="button"
                onClick={() => void logout()}
                className="btn btn-ghost btn-sm"
              >
                Sign out
              </button>
            </div>
          </div>
        </header>

        <div className="min-h-0 flex-1 relative">
          {visitedViews.has("console") && (
            <div className="absolute inset-0" style={{ display: view === "console" ? "block" : "none" }}>
              <ConsoleView />
            </div>
          )}
          {visitedViews.has("web-security") && (
            <div className="absolute inset-0 overflow-y-auto" style={{ display: view === "web-security" ? "block" : "none" }}>
              <WebSecurityView />
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
