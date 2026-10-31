import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { SessionShell } from "./SessionShell";
import { ConfirmDialog } from "./ConfirmDialog";
import { Badge, Button, Skeleton } from "./ui";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sanitizedSessionValue(value: unknown, key = ""): unknown {
  if (/password|passwd|secret|token|credential|private|api.?key/i.test(key)) return "[redacted]";
  if (Array.isArray(value)) return value.map((item) => sanitizedSessionValue(item));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([field]) => !/path/i.test(field)).map(([field, nested]) => [field, sanitizedSessionValue(nested, field)]));
  return value;
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
  const [pendingTermination, setPendingTermination] = useState<{ id: number; info: string } | null>(null);
  const [activeSessionId, setActiveSessionId] = useState<number | null>(null);
  const [inspectedSession, setInspectedSession] = useState<{ id: string; session: Record<string, unknown> } | null>(null);
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
    return () => {
      mounted.current = false;
      requestGeneration.current += 1;
    };
  }, []);

  useEffect(() => {
    if (activeSessionId !== null) {
      requestGeneration.current += 1;
      refreshAgain.current = false;
      return;
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      requestGeneration.current += 1;
      window.clearInterval(timer);
    };
  }, [activeSessionId, refresh]);

  useEffect(() => {
    const handleContextAction = (event: Event) => {
      const detail = (event as CustomEvent<{ action: string; kind: string; value: string }>).detail;
      if (detail?.kind !== "session" || detail.action !== "inspect-session") return;
      const session = sessions[detail.value];
      if (session && typeof session === "object") setInspectedSession({ id: detail.value, session });
    };
    window.addEventListener("msf-context-action", handleContextAction);
    return () => window.removeEventListener("msf-context-action", handleContextAction);
  }, [sessions]);

  const stopSession = async (id: number, info: string) => {
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
    <div className="p-4 md:p-6">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-gray-100">Active sessions</h2>
            <Badge tone={entries.length > 0 ? "accent" : "neutral"}>{entries.length}</Badge>
          </div>
          <p className="mt-1 text-[11px] text-gray-500">
            {entries.length} active {entries.length === 1 ? "session" : "sessions"} · auto-refreshes every 5 seconds
          </p>
        </div>
        <Button small onClick={() => void refresh(true)} disabled={refreshing} loading={refreshing}>
          {refreshing ? "Refreshing…" : "Refresh"}
        </Button>
      </div>

      {error && (
        <div role="alert" className="mb-3 rounded-lg border border-danger/30 bg-danger/5 p-3 text-xs text-danger">
          <p className="font-medium">Could not load sessions</p>
          <p className="mt-1 break-words">{error}</p>
          <button type="button" onClick={() => void refresh(true)} className="mt-2 underline">Try again</button>
          {entries.length > 0 && <p className="mt-2 text-gray-400">Showing the last successfully loaded session list.</p>}
        </div>
      )}
      {actionError && (
        <div role="alert" className="mb-3 rounded-lg border border-danger/30 bg-danger/5 p-3 text-xs text-danger">
          {actionError}
        </div>
      )}
      {notice && (
        <div role="status" className="mb-3 rounded-lg border border-accent/30 bg-accent/5 p-3 text-xs text-accent">
          {notice}
        </div>
      )}

      {loading && entries.length === 0 && !error && (
        <div className="card space-y-3 p-4" role="status" aria-label="Loading active sessions">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
        </div>
      )}
      {!loading && !error && entries.length === 0 && (
        <div className="card p-5 text-xs text-gray-500">
          <p>No active sessions right now. A session shows up here the moment an exploit or payload succeeds - from the module browser, or from a <span className="font-mono text-gray-400">exploit</span>/<span className="font-mono text-gray-400">sessions -i</span> command in the console.</p>
          <p className="mt-2 text-gray-400">If you ran something and expected a session but don't see one, it usually means one of:</p>
          <ul className="mt-1.5 list-disc space-y-1 pl-4">
            <li>The exploit/payload is still running - check the <span className="font-mono text-gray-300">Jobs</span> tab, it keeps tracking in the background.</li>
            <li>The target wasn't vulnerable, unreachable, or the exploit failed - the module's run result or the console output will say why.</li>
            <li>For a reverse payload (e.g. <span className="font-mono text-gray-300">reverse_tcp</span>), <span className="font-mono text-gray-300">LHOST</span>/<span className="font-mono text-gray-300">LPORT</span> must be reachable from the target - a wrong or unreachable LHOST is the most common reason nothing connects back.</li>
            <li>For a bind payload, the target's port must be reachable from this machine.</li>
          </ul>
        </div>
      )}

      {entries.length > 0 && (
        <div className="card overflow-x-auto">
          <table className="data-table font-mono text-xs">
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Target</th>
                <th>Via</th>
                <th>Info</th>
                <th>Actions</th>
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
                  <tr key={id} data-context-kind="session" data-context-label={`Session ${id} · ${display(session.type)}`} data-context-index={id} data-context-value={id}>
                    <td className="align-top font-semibold text-accent">{id}</td>
                    <td className="align-top"><Badge tone="info">{display(session.type)}</Badge></td>
                    <td className="align-top">{target}</td>
                    <td className="align-top break-words">{display(session.via_exploit)}</td>
                    <td className="align-top max-w-xs break-words">{info || "—"}</td>
                    <td className="align-top">
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setActiveSessionId(numericId)}
                          className="btn btn-sm border-accent/40 bg-accent/10 text-accent hover:bg-accent/20 hover:text-accent"
                        >
                          Interact
                        </button>
                        <button
                          type="button"
                          onClick={() => setPendingTermination({ id: numericId, info })}
                          disabled={!Number.isInteger(numericId) || stoppingSessionId !== null}
                          className="btn btn-sm btn-danger"
                        >
                          {stoppingSessionId === numericId ? "Terminating…" : "Terminate"}
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
      {inspectedSession && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-fade-in" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setInspectedSession(null); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="session-inspector-title" className="flex max-h-[80vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-border-strong bg-bg-secondary shadow-pop animate-pop-in">
            <div className="flex items-start justify-between border-b border-border p-4">
              <div><h2 id="session-inspector-title" className="text-sm font-semibold text-gray-100">Session {inspectedSession.id}</h2><p className="mt-1 text-xs text-gray-500">Read-only session metadata</p></div>
              <button type="button" onClick={() => setInspectedSession(null)} className="btn btn-ghost btn-sm">Close</button>
            </div>
            <div className="min-h-0 overflow-auto p-4"><dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {Object.entries(inspectedSession.session).filter(([key]) => !/path/i.test(key)).map(([key, value]) => (
                <div key={key} className="min-w-0 rounded-lg border border-border bg-bg-primary/50 p-3"><dt className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-500">{key.replace(/_/g, " ")}</dt><dd className="whitespace-pre-wrap break-words font-mono text-xs text-gray-200">{JSON.stringify(sanitizedSessionValue(value, key), null, 2) ?? "—"}</dd></div>
              ))}
            </dl></div>
          </section>
        </div>
      )}
      <ConfirmDialog
        open={pendingTermination !== null}
        title="Terminate session?"
        description={pendingTermination
          ? `Terminate session ${pendingTermination.id}${pendingTermination.info ? ` (${pendingTermination.info})` : ""}? This will close the remote session.`
          : ""}
        confirmLabel="Terminate session"
        cancelLabel="Keep session"
        onCancel={() => setPendingTermination(null)}
        onConfirm={async () => {
          if (!pendingTermination) return;
          await stopSession(pendingTermination.id, pendingTermination.info);
          setPendingTermination(null);
        }}
      />
    </div>
  );
}
