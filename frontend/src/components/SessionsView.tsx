import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { SessionShell } from "./SessionShell";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function display(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return typeof value === "string" || typeof value === "number" ? String(value) : JSON.stringify(value);
}

export function SessionsView() {
  const [sessions, setSessions] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [stoppingSessionId, setStoppingSessionId] = useState<number | null>(null);
  const [activeSessionId, setActiveSessionId] = useState<number | null>(null);
  const activeSessionRef = useRef<number | null>(null);
  const mounted = useRef(true);
  const refreshInFlight = useRef(false);
  const refreshAgain = useRef(false);
  const requestGeneration = useRef(0);

  activeSessionRef.current = activeSessionId;

  const refresh = useCallback(async (manual = false) => {
    if (activeSessionRef.current !== null) return;
    if (refreshInFlight.current) {
      refreshAgain.current = true;
      return;
    }
    refreshInFlight.current = true;
    if (manual) setRefreshing(true);
    const generation = ++requestGeneration.current;
    try {
      const data = await api.sessions.list();
      if (mounted.current && generation === requestGeneration.current) {
        setSessions(data && typeof data === "object" ? data : {});
        setError(null);
      }
    } catch (e: unknown) {
      if (mounted.current && generation === requestGeneration.current) {
        setError(errorMessage(e));
      }
    } finally {
      refreshInFlight.current = false;
      if (mounted.current) {
        setLoading(false);
        setRefreshing(false);
      }
      if (refreshAgain.current && mounted.current && activeSessionRef.current === null) {
        refreshAgain.current = false;
        void refresh();
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    if (activeSessionId !== null) return;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      mounted.current = false;
      requestGeneration.current += 1;
      window.clearInterval(timer);
    };
  }, [activeSessionId, refresh]);

  const stopSession = async (id: number, info: string) => {
    if (!window.confirm(`Terminate session ${id}${info ? ` (${info})` : ""}? This will close the remote session.`)) return;
    setStoppingSessionId(id);
    setActionError(null);
    setNotice(null);
    try {
      await api.sessions.stop(id);
      if (mounted.current) setNotice(`Termination requested for session ${id}.`);
      await refresh(true);
    } catch (e: unknown) {
      if (mounted.current) setActionError(`Could not terminate session ${id}: ${errorMessage(e)}`);
    } finally {
      if (mounted.current) setStoppingSessionId(null);
    }
  };

  if (activeSessionId !== null) {
    return (
      <SessionShell
        sessionId={activeSessionId}
        onClose={() => {
          setActiveSessionId(null);
        }}
      />
    );
  }

  const entries = Object.entries(sessions);

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-3 gap-3">
        <div>
          <h2 className="text-sm text-gray-200">Active Sessions</h2>
          <p className="mt-1 text-[10px] text-gray-600">
            {entries.length} active {entries.length === 1 ? "session" : "sessions"} · auto-refreshes every 5 seconds
          </p>
        </div>
        <button
          onClick={() => void refresh(true)}
          disabled={refreshing}
          className="text-xs text-gray-500 hover:text-gray-300 disabled:opacity-50"
        >
          {refreshing ? "refreshing…" : "refresh"}
        </button>
      </div>

      {error && (
        <div role="alert" className="mb-3 rounded border border-danger/30 bg-danger/5 p-3 text-xs text-danger">
          <p className="font-medium">Could not load sessions</p>
          <p className="mt-1 break-words">{error}</p>
          <button onClick={() => void refresh(true)} className="mt-2 underline">Try again</button>
          {entries.length > 0 && <p className="mt-2 text-gray-400">Showing the last successfully loaded session list.</p>}
        </div>
      )}
      {actionError && (
        <div role="alert" className="mb-3 rounded border border-danger/30 bg-danger/5 p-3 text-xs text-danger">
          {actionError}
        </div>
      )}
      {notice && (
        <div role="status" className="mb-3 rounded border border-accent/30 bg-accent/5 p-3 text-xs text-accent">
          {notice}
        </div>
      )}

      {loading && entries.length === 0 && !error && (
        <div className="text-xs text-gray-500">Loading active sessions…</div>
      )}
      {!loading && !error && entries.length === 0 && (
        <div className="rounded border border-border bg-bg-secondary/50 p-4 text-xs text-gray-500">
          No active sessions. Sessions created by a module or console command will appear here.
        </div>
      )}

      {entries.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-left text-gray-500 border-b border-border">
                <th className="py-2 pr-4">ID</th>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4">Target</th>
                <th className="py-2 pr-4">Via</th>
                <th className="py-2 pr-4">Info</th>
                <th className="py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(([id, session]: [string, any]) => {
                const target = [session.target_host, session.target_port]
                  .filter((value) => value !== null && value !== undefined && value !== "")
                  .join(":") || "—";
                const info = display(session.info, "");
                const numericId = Number(id);
                return (
                  <tr key={id} className="border-b border-border/50 text-gray-300">
                    <td className="py-2 pr-4 align-top text-accent">{id}</td>
                    <td className="py-2 pr-4 align-top">{display(session.type)}</td>
                    <td className="py-2 pr-4 align-top">{target}</td>
                    <td className="py-2 pr-4 align-top break-words">{display(session.via_exploit)}</td>
                    <td className="py-2 pr-4 align-top max-w-xs break-words">{info || "—"}</td>
                    <td className="py-2 align-top">
                      <div className="flex gap-3">
                        <button
                          onClick={() => setActiveSessionId(numericId)}
                          className="text-accent hover:underline"
                        >
                          interact
                        </button>
                        <button
                          onClick={() => void stopSession(numericId, info)}
                          disabled={!Number.isInteger(numericId) || stoppingSessionId !== null}
                          className="text-danger hover:underline disabled:opacity-50"
                        >
                          {stoppingSessionId === numericId ? "terminating…" : "terminate"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
