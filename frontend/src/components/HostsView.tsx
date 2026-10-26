import { useEffect, useState } from "react";
import { api } from "../lib/api";

type Tab = "hosts" | "services" | "vulns" | "loot" | "creds";

export function HostsView() {
  const [tab, setTab] = useState<Tab>("hosts");
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const loaders: Record<Tab, () => Promise<any>> = {
      hosts: () => api.db.hosts().then((r) => r.hosts),
      services: () => api.db.services().then((r) => r.services),
      vulns: () => api.db.vulns().then((r) => r.vulns),
      loot: () => api.db.loot().then((r) => r.loot),
      creds: () => api.db.creds().then((r) => r.creds),
    };
    loaders[tab]()
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, [tab]);

  const columns = rows.length > 0 ? Object.keys(rows[0]).slice(0, 6) : [];

  return (
    <div className="flex flex-col h-full">
      <div className="flex gap-1 h-10 items-center px-3 border-b border-border">
        {(["hosts", "services", "vulns", "loot", "creds"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 h-7 rounded text-xs font-mono ${
              tab === t ? "bg-bg-tertiary text-accent" : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-3">
        {loading && <div className="text-xs text-gray-600">Loading…</div>}
        {!loading && rows.length === 0 && <div className="text-xs text-gray-600">No data.</div>}
        {rows.length > 0 && (
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-left text-gray-500 border-b border-border">
                {columns.map((c) => (
                  <th key={c} className="py-1.5 pr-4">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i} className="border-b border-border/50 text-gray-300">
                  {columns.map((c) => (
                    <td key={c} className="py-1.5 pr-4 truncate max-w-xs">
                      {String(row[c] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
