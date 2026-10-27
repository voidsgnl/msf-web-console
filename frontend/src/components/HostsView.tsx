import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";

type Tab = "hosts" | "services" | "vulns" | "loot" | "creds";
type LootRecord = Record<string, unknown>;

type SelectedLoot = {
  record: LootRecord;
  index: number;
};

function stringifyValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function formatLootDate(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  const numeric = typeof value === "number" ? value : Number(value);
  const date = Number.isFinite(numeric) && numeric > 0
    ? new Date(numeric < 100000000000 ? numeric * 1000 : numeric)
    : new Date(String(value));
  return Number.isNaN(date.getTime()) ? stringifyValue(value) : date.toLocaleString();
}

function formatLootValue(key: string, value: unknown): string {
  if (key === "created_at" || key === "updated_at") return formatLootDate(value);
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function safeFilename(value: unknown): string {
  const base = stringifyValue(value).trim().replace(/[^a-z0-9._-]+/gi, "_").replace(/^\.+/, "");
  return (base || "loot-record").slice(0, 100);
}

function downloadJson(value: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(value, null, 2) + "\n"], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = safeFilename(filename);
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function lootName(record: LootRecord): string {
  return stringifyValue(record.name || record.filename || record.info) || "Untitled loot";
}

export function HostsView() {
  const [tab, setTab] = useState<Tab>("hosts");
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lootQuery, setLootQuery] = useState("");
  const [selectedLoot, setSelectedLoot] = useState<SelectedLoot | null>(null);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    setNotice("");
    setSelectedLoot(null);

    const loaders: Record<Tab, () => Promise<any[]>> = {
      hosts: () => api.db.hosts().then((r) => r.hosts),
      services: () => api.db.services().then((r) => r.services),
      vulns: () => api.db.vulns().then((r) => r.vulns),
      loot: () => api.db.loot().then((r) => r.loot),
      creds: () => api.db.creds().then((r) => r.creds),
    };

    loaders[tab]()
      .then((result) => {
        if (active) setRows(Array.isArray(result) ? result : []);
      })
      .catch((cause: unknown) => {
        if (!active) return;
        setRows([]);
        setError(cause instanceof Error ? cause.message : "Unable to load database records.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [tab]);

  const filteredLoot = useMemo(() => {
    const query = lootQuery.trim().toLowerCase();
    return (rows as LootRecord[])
      .map((record, index) => ({ record, index }))
      .filter(({ record }) => !query || stringifyValue(record).toLowerCase().includes(query));
  }, [rows, lootQuery]);

  const columns = rows.length > 0 ? Object.keys(rows[0]).slice(0, 6) : [];

  async function copyLootRecord(record: LootRecord) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(record, null, 2));
      setNotice("Record copied to clipboard.");
    } catch {
      setNotice("Clipboard access was blocked. Use Export JSON instead.");
    }
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex gap-1 h-10 shrink-0 items-center px-3 border-b border-border">
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

      {tab === "loot" ? (
        <div className="flex-1 min-h-0 flex flex-col p-3 gap-3">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-sm font-semibold text-gray-200">Loot &amp; Evidence</h2>
              <p className="mt-1 text-xs text-gray-500">
                Inspect records returned by the active Metasploit workspace and export evidence metadata.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                aria-label="Search loot records"
                value={lootQuery}
                onChange={(event) => setLootQuery(event.target.value)}
                placeholder="Search name, host, type, info…"
                className="w-full sm:w-64 h-8 rounded border border-border bg-bg-secondary px-2 text-xs text-gray-200 outline-none focus:border-accent"
              />
              <button
                disabled={filteredLoot.length === 0}
                onClick={() => downloadJson(
                  filteredLoot.map(({ record }) => record),
                  `msf-loot-export-${new Date().toISOString().slice(0, 10)}.json`
                )}
                className="h-8 px-3 rounded border border-border text-xs text-gray-300 hover:bg-bg-tertiary disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Export JSON
              </button>
            </div>
          </div>

          {notice && (
            <div role="status" className="text-xs text-accent">{notice}</div>
          )}
          {loading && <div className="text-xs text-gray-600">Loading loot records…</div>}
          {!loading && error && (
            <div role="alert" className="rounded border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300">
              Could not load loot records: {error}
            </div>
          )}
          {!loading && !error && rows.length === 0 && (
            <div className="rounded border border-border p-5 text-xs text-gray-500">
              No loot records in this workspace.
            </div>
          )}
          {!loading && !error && rows.length > 0 && filteredLoot.length === 0 && (
            <div className="text-xs text-gray-500">No loot records match “{lootQuery}”.</div>
          )}

          {!loading && !error && filteredLoot.length > 0 && (
            <div className="flex-1 min-h-0 overflow-auto border border-border rounded">
              <table className="w-full text-xs font-mono">
                <thead className="sticky top-0 bg-bg-secondary z-10">
                  <tr className="text-left text-gray-500 border-b border-border">
                    <th className="py-2 px-3 font-medium">Name / Info</th>
                    <th className="py-2 px-3 font-medium">Type</th>
                    <th className="py-2 px-3 font-medium">Host</th>
                    <th className="py-2 px-3 font-medium">Service</th>
                    <th className="py-2 px-3 font-medium">Captured</th>
                    <th className="py-2 px-3 font-medium text-right">Record</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLoot.map(({ record, index }) => (
                    <tr key={`${stringifyValue(record.name)}-${stringifyValue(record.ltype)}-${stringifyValue(record.host)}-${index}`}
                      className="border-b border-border/50 text-gray-300 hover:bg-bg-tertiary/60">
                      <td className="py-2 px-3 max-w-sm">
                        <div className="truncate text-gray-200">{lootName(record)}</div>
                        {record.info && record.info !== record.name && (
                          <div className="mt-1 truncate text-gray-600">{stringifyValue(record.info)}</div>
                        )}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">{stringifyValue(record.ltype) || "—"}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{stringifyValue(record.host) || "—"}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{stringifyValue(record.service) || "—"}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{formatLootDate(record.created_at)}</td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={() => { setSelectedLoot({ record, index }); setNotice(""); }}
                          className="rounded border border-border px-2 py-1 text-accent hover:bg-bg-secondary"
                          aria-label={`Inspect ${lootName(record)}`}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="border-t border-border bg-bg-secondary/60 px-3 py-2 text-[11px] text-gray-600">
                {filteredLoot.length} of {rows.length} records · File bytes are not provided by the standard Framework loot-list RPC call.
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="flex-1 overflow-auto p-3">
          {loading && <div className="text-xs text-gray-600">Loading…</div>}
          {!loading && error && <div role="alert" className="text-xs text-red-300">{error}</div>}
          {!loading && !error && rows.length === 0 && <div className="text-xs text-gray-600">No data.</div>}
          {rows.length > 0 && (
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="text-left text-gray-500 border-b border-border">
                  {columns.map((c) => (
                    <th key={c} className="py-1.5 pr-4">{c}</th>
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
      )}

      {selectedLoot && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelectedLoot(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="loot-detail-title"
            className="flex max-h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded border border-border bg-bg-primary shadow-2xl"
          >
            <div className="flex items-start justify-between gap-4 border-b border-border p-4">
              <div className="min-w-0">
                <h2 id="loot-detail-title" className="truncate text-sm font-semibold text-gray-100">
                  {lootName(selectedLoot.record)}
                </h2>
                <p className="mt-1 text-xs text-gray-500">
                  Loot record · row {selectedLoot.index + 1} · active workspace
                </p>
              </div>
              <button onClick={() => setSelectedLoot(null)} className="rounded px-2 py-1 text-xs text-gray-400 hover:bg-bg-tertiary">
                Close
              </button>
            </div>
            <div className="flex gap-2 border-b border-border p-3">
              <button
                onClick={() => void copyLootRecord(selectedLoot.record)}
                className="rounded border border-border px-3 py-1.5 text-xs text-gray-300 hover:bg-bg-tertiary"
              >
                Copy record
              </button>
              <button
                onClick={() => downloadJson(
                  selectedLoot.record,
                  `loot-${safeFilename(lootName(selectedLoot.record))}.json`
                )}
                className="rounded border border-border px-3 py-1.5 text-xs text-gray-300 hover:bg-bg-tertiary"
              >
                Export record JSON
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              <dl className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {Object.entries(selectedLoot.record).map(([key, value]) => (
                  <div key={key} className="min-w-0 rounded border border-border/70 p-3">
                    <dt className="mb-1 text-[11px] uppercase tracking-wide text-gray-500">{key.replace(/_/g, " ")}</dt>
                    <dd className="whitespace-pre-wrap break-words text-xs text-gray-200">
                      {formatLootValue(key, value)}
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="mt-4 text-[11px] leading-relaxed text-gray-600">
                This view exports the metadata returned by Metasploit. The standard Framework RPC response does not include a stable loot ID, a retrievable file path, or the file bytes, so this interface does not pretend that a metadata export is the original artifact.
              </p>
              {notice && <div role="status" className="mt-3 text-xs text-accent">{notice}</div>}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
