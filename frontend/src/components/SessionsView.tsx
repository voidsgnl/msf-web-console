import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { SessionShell } from "./SessionShell";

export function SessionsView() {
  const [sessions, setSessions] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [activeSessionId, setActiveSessionId] = useState<number | null>(null);

  const refresh = () => {
    setLoading(true);
    api.sessions.list().then((s) => {
      setSessions(s);
      setLoading(false);
    });
  };

  useEffect(() => {
    refresh();
    // Pause the list poll while actively interacting with a session - no
    // need to keep hammering session.list in the background, and it avoids
    // any chance of a refresh re-render disturbing the open terminal.
    if (activeSessionId !== null) return;
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [activeSessionId]);

  if (activeSessionId !== null) {
    return (
      <SessionShell
        sessionId={activeSessionId}
        onClose={() => {
          setActiveSessionId(null);
          refresh();
        }}
      />
    );
  }

  const entries = Object.entries(sessions);

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm text-gray-200">Active Sessions</h2>
        <button onClick={refresh} className="text-xs text-gray-500 hover:text-gray-300">
          refresh
        </button>
      </div>

      {loading && entries.length === 0 && <div className="text-xs text-gray-600">Loading…</div>}
      {!loading && entries.length === 0 && (
        <div className="text-xs text-gray-600">No active sessions.</div>
      )}

      {entries.length > 0 && (
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="text-left text-gray-500 border-b border-border">
              <th className="py-1.5 pr-4">ID</th>
              <th className="py-1.5 pr-4">Type</th>
              <th className="py-1.5 pr-4">Target</th>
              <th className="py-1.5 pr-4">Via</th>
              <th className="py-1.5 pr-4">Info</th>
              <th className="py-1.5"></th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([id, s]: [string, any]) => (
              <tr key={id} className="border-b border-border/50 text-gray-300">
                <td className="py-1.5 pr-4 text-accent">{id}</td>
                <td className="py-1.5 pr-4">{s.type}</td>
                <td className="py-1.5 pr-4">
                  {s.target_host}:{s.target_port}
                </td>
                <td className="py-1.5 pr-4">{s.via_exploit}</td>
                <td className="py-1.5 pr-4 truncate max-w-xs">{s.info}</td>
                <td className="py-1.5 flex gap-3">
                  <button
                    onClick={() => setActiveSessionId(Number(id))}
                    className="text-accent hover:underline"
                  >
                    interact
                  </button>
                  <button
                    onClick={() => api.sessions.stop(Number(id)).then(refresh)}
                    className="text-danger hover:underline"
                  >
                    kill
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
