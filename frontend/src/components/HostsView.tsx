import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { CveEnrichment } from "../lib/api";

type Tab = "hosts" | "services" | "vulns" | "loot" | "creds";
type LootRecord = Record<string, unknown>;

type SelectedLoot = {
  record: LootRecord;
  index: number;
};

type SelectedRecord = {
  record: Record<string, unknown>;
  index: number;
};

const DATABASE_COLUMN_PREFERENCES: Partial<Record<Tab, string[]>> = {
  hosts: ["address", "name", "mac", "os_name", "os_flavor", "state", "purpose", "created_at"],
  services: ["host", "port", "proto", "name", "state", "info"],
  vulns: ["host", "name", "severity", "port", "service", "refs", "info", "created_at"],
  creds: ["username", "private_type", "service", "host", "port", "proof", "created_at"],
};

const SENSITIVE_FIELD = /password|passwd|private_data|private_key|secret|token|api[_-]?key|credential|(^|_)hash($|_)/i;
const CVE_ID_PATTERN = /CVE-\d{4}-\d{4,7}/gi;

function isSensitiveField(key: string): boolean {
  return SENSITIVE_FIELD.test(key);
}

function extractCveIds(record: Record<string, unknown>): string[] {
  let text: string;
  try {
    text = JSON.stringify(record);
  } catch {
    return [];
  }
  const matches = text.match(CVE_ID_PATTERN) ?? [];
  return Array.from(new Set(matches.map((match) => match.toUpperCase()))).sort();
}

function extractHttpReferences(record: Record<string, unknown>): string[] {
  let text = "";
  try {
    text = JSON.stringify(record);
  } catch {
    return [];
  }
  const matches = text.match(/https?:\\/\\/[^\\s"'<>]+/gi) ?? [];
  return Array.from(new Set(matches.map((url) => url.replace(/[),.;]+$/, ""))))
    .filter((url) => /^https?:\\/\\//i.test(url))
    .slice(0, 8);
}

function redactSensitiveFields(value: unknown, revealSensitive = false, key = ""): unknown {
  if (key && isSensitiveField(key) && !revealSensitive) return "[redacted]";
  if (Array.isArray(value)) return value.map((item) => redactSensitiveFields(item, revealSensitive));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([field]) => !/path/i.test(field) && field !== "data" && field !== "download_id")
        .map(([field, nested]) => [field, redactSensitiveFields(nested, revealSensitive, field)])
    );
  }
  return value;
}

function hasSensitiveFields(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasSensitiveFields);
  if (!value || typeof value !== "object") return false;
  return Object.entries(value as Record<string, unknown>).some(
    ([key, nested]) => isSensitiveField(key) || hasSensitiveFields(nested)
  );
}

function relatedHostValue(record: Record<string, unknown>): string {
  for (const key of ["address", "host_address", "target_host", "host", "host_ip"]) {
    const value = record[key];
    if (typeof value === "string" || typeof value === "number") {
      const rendered = String(value).trim();
      if (rendered) return rendered;
    }
    if (value && typeof value === "object") {
      const host = value as Record<string, unknown>;
      const nested = host.address ?? host.name ?? host.host;
      if (typeof nested === "string" || typeof nested === "number") {
        const rendered = String(nested).trim();
        if (rendered) return rendered;
      }
    }
  }
  return "";
}

function recordValue(key: string, value: unknown, revealSensitive = false): string {
  if (isSensitiveField(key) && !revealSensitive) return "[redacted]";
  if (key === "created_at" || key === "updated_at" || key === "opened_at") {
    return formatLootDate(value);
  }
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") {
    try {
      return JSON.stringify(redactSensitiveFields(value, revealSensitive), null, 2);
    } catch {
      return "[unavailable]";
    }
  }
  return String(value);
}

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

function formatBytes(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  const bytes = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return String(bytes) + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return String(size.toFixed(size < 10 ? 1 : 0)) + " " + units[unit];
}

function omitServerPaths(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(omitServerPaths);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => !/path/i.test(key) && key !== "data")
        .map(([key, nested]) => [key, omitServerPaths(nested)])
    );
  }
  return value;
}

function metadataForExport(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(metadataForExport);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => key !== "download_id" && key !== "data" && !/path/i.test(key))
        .map(([key, nested]) => [key, metadataForExport(nested)])
    );
  }
  return value;
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
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function lootName(record: LootRecord): string {
  return stringifyValue(record.name || record.filename || record.info) || "Untitled loot";
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = safeFilename(filename);
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function HostsView() {
  const [tab, setTab] = useState<Tab>("hosts");
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const [lootQuery, setLootQuery] = useState("");
  const [recordQuery, setRecordQuery] = useState("");
  const [recordFilterField, setRecordFilterField] = useState("");
  const [recordFilterValue, setRecordFilterValue] = useState("");
  const [selectedRecord, setSelectedRecord] = useState<SelectedRecord | null>(null);
  const [showSensitiveFields, setShowSensitiveFields] = useState(false);
  const [selectedLoot, setSelectedLoot] = useState<SelectedLoot | null>(null);
  const [notice, setNotice] = useState("");
  const [reportBusy, setReportBusy] = useState(false);
  const [reportNotice, setReportNotice] = useState("");
  const [cveResults, setCveResults] = useState<Record<string, CveEnrichment | { error: string } | null>>({});
  const [cveBusy, setCveBusy] = useState(false);
  const [cveNotice, setCveNotice] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    setNotice("");
    setSelectedLoot(null);
    setSelectedRecord(null);
    setShowSensitiveFields(false);
    setRecordFilterField("");
    setRecordFilterValue("");

    const loaders: Record<Tab, () => Promise<any[]>> = {
      hosts: () => api.db.hosts().then((r) => r.hosts),
      services: () => api.db.services().then((r) => r.services),
      vulns: () => api.db.vulns().then((r) => r.vulns),
      loot: () => api.db.loot().then((r) => r.loot),
      creds: () => api.db.creds().then((r) => r.creds),
    };

    loaders[tab]()
      .then((result) => {
        if (!active) return;
        const records = Array.isArray(result) ? result : [];
        setRows(tab === "loot" ? records.map((record) => omitServerPaths(record)) : records);
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
  }, [tab, reloadToken]);

  const filteredLoot = useMemo(() => {
    const query = lootQuery.trim().toLowerCase();
    return (rows as LootRecord[])
      .map((record, index) => ({ record, index }))
      .filter(({ record }) => !query || stringifyValue(metadataForExport(record)).toLowerCase().includes(query));
  }, [rows, lootQuery]);

  const databaseRows = rows as Record<string, unknown>[];

  const databaseFilterFields = useMemo(() => {
    const keys = new Set<string>();
    for (const row of databaseRows) {
      for (const key of Object.keys(row)) {
        if (!isSensitiveField(key) && !/path/i.test(key) && key !== "data" && key !== "download_id") {
          keys.add(key);
        }
      }
    }
    return Array.from(keys).sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const databaseFilterValues = useMemo(() => {
    if (!recordFilterField) return [];
    const values = new Set<string>();
    for (const row of databaseRows) {
      const value = stringifyValue(row[recordFilterField]).trim();
      if (value) values.add(value);
    }
    return Array.from(values).sort((a, b) => a.localeCompare(b)).slice(0, 250);
  }, [rows, recordFilterField]);

  const filteredDatabaseRows = useMemo(() => {
    const query = recordQuery.trim().toLowerCase();
    return databaseRows
      .map((record, index) => ({ record, index }))
      .filter(({ record }) => {
        if (query && !stringifyValue(redactSensitiveFields(record)).toLowerCase().includes(query)) {
          return false;
        }
        if (recordFilterField && recordFilterValue &&
            stringifyValue(record[recordFilterField]) !== recordFilterValue) {
          return false;
        }
        return true;
      });
  }, [rows, recordQuery, recordFilterField, recordFilterValue]);

  const databaseColumns = useMemo(() => {
    const allKeys = Array.from(new Set(databaseRows.flatMap((row) => Object.keys(row))))
      .filter((key) => !isSensitiveField(key) && !/path/i.test(key) && key !== "data" && key !== "download_id");
    const preferred = DATABASE_COLUMN_PREFERENCES[tab] ?? [];
    const selected = preferred.filter((key) => allKeys.includes(key));
    for (const key of allKeys) {
      if (!selected.includes(key) && selected.length < 6) selected.push(key);
    }
    return selected.slice(0, 6);
  }, [rows, tab]);

  function navigateToDatabaseTab(nextTab: Tab, query: string) {
    const nextQuery = query.trim();
    setRecordQuery(nextQuery);
    setRecordFilterField("");
    setRecordFilterValue("");
    setSelectedRecord(null);
    setTab(nextTab);
  }

  async function copyDatabaseRecord(record: Record<string, unknown>) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(redactSensitiveFields(record), null, 2));
      setNotice("Record metadata copied. Sensitive fields and server paths were omitted.");
    } catch {
      setNotice("Clipboard access was blocked. Select Export JSON instead.");
    }
  }

  function exportDatabaseRecords() {
    downloadJson(
      filteredDatabaseRows.map(({ record }) => redactSensitiveFields(record)),
      `msf-${tab}-export-${new Date().toISOString().slice(0, 10)}.json`
    );
    setNotice(`Exported ${filteredDatabaseRows.length} ${tab} record(s); sensitive fields and server paths were omitted.`);
  }

  async function copyLootRecord(record: LootRecord) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(metadataForExport(record), null, 2));
      setNotice("Record copied to clipboard.");
    } catch {
      setNotice("Clipboard access was blocked. Use Export JSON instead.");
    }
  }

  async function downloadLootArtifact(record: LootRecord) {
    const downloadId = stringifyValue(record.download_id);
    if (!/^\d{1,3}\.[a-f0-9]{64}$/.test(downloadId)) {
      setNotice("This record has no valid download reference. Refresh the loot list.");
      return;
    }
    setNotice("Preparing artifact download…");
    try {
      const result = await api.db.downloadLoot(downloadId);
      saveBlob(result.blob, result.filename);
      setNotice("Artifact download started.");
    } catch (cause: unknown) {
      setNotice(cause instanceof Error ? `Download failed: ${cause.message}` : "Artifact download failed.");
    }
  }

  async function generateAssessmentReport() {
    setReportBusy(true);
    setReportNotice("");
    try {
      const result = await api.db.downloadReport();
      saveBlob(result.blob, result.filename);
      setReportNotice("Report download started.");
    } catch (cause: unknown) {
      setReportNotice(cause instanceof Error ? `Report failed: ${cause.message}` : "Report generation failed.");
    } finally {
      setReportBusy(false);
    }
  }

  async function enrichVulnCves(record: Record<string, unknown>) {
    const cveIds = extractCveIds(record);
    if (cveIds.length === 0) {
      setCveResults({});
      setCveNotice("No CVE identifiers were found in this record's fields.");
      return;
    }
    setCveBusy(true);
    setCveNotice("");
    const results: Record<string, CveEnrichment | { error: string } | null> = {};
    for (const cveId of cveIds) {
      try {
        results[cveId] = await api.cve.lookup(cveId);
      } catch (cause: unknown) {
        results[cveId] = { error: cause instanceof Error ? cause.message : "Lookup failed." };
      }
    }
    setCveResults(results);
    setCveBusy(false);
  }

  useEffect(() => {
    const handleContextAction = (event: Event) => {
      const detail = (event as CustomEvent<{ action: string; kind: string; index: string; value?: string }>).detail;
      if (!detail || detail.kind !== tab) return;
      const index = Number(detail.index);
      if (!Number.isInteger(index) || index < 0) return;

      if (tab === "loot") {
        const match = filteredLoot.find((item) => item.index === index);
        if (!match) return;
        if (detail.action === "inspect-evidence") {
          setSelectedLoot(match);
          setNotice("");
        } else if (detail.action === "copy-evidence") {
          void copyLootRecord(match.record);
        } else if (detail.action === "export-evidence") {
          downloadJson(metadataForExport(match.record), `msf-loot-record-${index + 1}.json`);
          setNotice("Exported sanitized evidence metadata.");
        }
        return;
      }

      const match = filteredDatabaseRows.find((item) => item.index === index);
      if (!match) return;
      const record = match.record;
      const relatedHost = relatedHostValue(record);
      if (detail.action === "inspect-record") {
        setSelectedRecord({ record, index });
        setShowSensitiveFields(false);
        setNotice("");
        setCveResults({});
        setCveNotice("");
      } else if (detail.action === "export-record") {
        downloadJson(redactSensitiveFields(record), `msf-${tab}-record-${index + 1}.json`);
        setNotice("Exported sanitized record JSON.");
      } else if (detail.action === "enrich-vuln" && tab === "vulns") {
        setSelectedRecord({ record, index });
        setShowSensitiveFields(false);
        setNotice("");
        setCveResults({});
        setCveNotice("");
        void enrichVulnCves(record);
      } else if (detail.action === "view-services" && tab === "hosts" && relatedHost) {
        navigateToDatabaseTab("services", relatedHost);
      } else if (detail.action === "view-vulns" && relatedHost) {
        navigateToDatabaseTab("vulns", relatedHost);
      } else if (detail.action === "view-host" && relatedHost) {
        navigateToDatabaseTab("hosts", relatedHost);
      }
    };

    window.addEventListener("msf-context-action", handleContextAction);
    return () => window.removeEventListener("msf-context-action", handleContextAction);
  }, [tab, filteredDatabaseRows, filteredLoot]);

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex justify-between gap-3 h-10 shrink-0 items-center px-3 border-b border-border">
        <div className="flex min-w-0 gap-1 items-center">
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
        <div className="flex min-w-0 items-center gap-2">
          {reportNotice && (
            <span role="status" className="hidden max-w-xs truncate text-[11px] text-accent md:inline">
              {reportNotice}
            </span>
          )}
          <button
            onClick={() => void generateAssessmentReport()}
            disabled={reportBusy}
            className="h-7 shrink-0 rounded border border-border px-3 text-xs text-gray-300 hover:bg-bg-tertiary disabled:cursor-wait disabled:opacity-50"
          >
            {reportBusy ? "Generating…" : "Generate report"}
          </button>
        </div>
      </div>

      {tab === "loot" ? (
        <div className="flex-1 min-h-0 flex flex-col p-3 gap-3">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-sm font-semibold text-gray-200">Loot &amp; Evidence</h2>
              <p className="mt-1 text-xs text-gray-500">
                Inspect evidence records, export metadata, and download inline artifacts or files explicitly allowed in backend configuration.
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
                  filteredLoot.map(({ record }) => metadataForExport(record)),
                  `msf-loot-export-${new Date().toISOString().slice(0, 10)}.json`
                )}
                className="h-8 px-3 rounded border border-border text-xs text-gray-300 hover:bg-bg-tertiary disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Export JSON
              </button>
            </div>
          </div>

          {notice && !selectedLoot && (
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
                    <th className="py-2 px-3 font-medium">Size</th>
                    <th className="py-2 px-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLoot.map(({ record, index }) => (
                    <tr key={`${stringifyValue(record.name)}-${stringifyValue(record.ltype)}-${stringifyValue(record.host)}-${index}`}
                      data-context-kind="loot"
                      data-context-label={lootName(record)}
                      data-context-index={index}
                      data-context-value={lootName(record)}
                      className="border-b border-border/50 text-gray-300 hover:bg-bg-tertiary/60">
                      <td className="py-2 px-3 max-w-sm">
                        <div className="truncate text-gray-200">{lootName(record)}</div>
                        {Boolean(record.info) && record.info !== record.name && (
                          <div className="mt-1 truncate text-gray-600">{stringifyValue(record.info)}</div>
                        )}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">{stringifyValue(record.ltype) || "—"}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{stringifyValue(record.host) || "—"}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{stringifyValue(record.service) || "—"}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{formatLootDate(record.created_at)}</td>
                      <td className="py-2 px-3 whitespace-nowrap">{formatBytes(record.size)}</td>
                      <td className="py-2 px-3">
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => { setSelectedLoot({ record, index }); setNotice(""); }}
                            className="rounded border border-border px-2 py-1 text-accent hover:bg-bg-secondary"
                            aria-label={lootName(record)}
                          >
                            Inspect
                          </button>
                          <button
                            disabled={record.has_data !== true}
                            title={record.has_data === true ? "Download artifact data" : "No inline data or readable allowlisted file is available"}
                            onClick={() => void downloadLootArtifact(record)}
                            className="rounded border border-border px-2 py-1 text-gray-300 hover:bg-bg-secondary disabled:cursor-not-allowed disabled:opacity-40"
                          >
                            Download
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="border-t border-border bg-bg-secondary/60 px-3 py-2 text-[11px] text-gray-600">
                {filteredLoot.length} of {rows.length} records · Downloads are available for records with inline data or a readable allowlisted file.
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="flex-1 min-h-0 flex flex-col gap-3 overflow-auto p-3">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <h2 className="text-sm font-semibold capitalize text-gray-200">
                {tab === "vulns" ? "Vulnerabilities" : tab === "creds" ? "Credential Records" : tab}
              </h2>
              <p className="mt-1 text-xs text-gray-500">
                Search across record metadata, filter by a field, inspect full records, and follow host relationships.
              </p>
            </div>
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
              <button
                onClick={() => setReloadToken((current) => current + 1)}
                disabled={loading}
                className="h-8 rounded border border-border px-3 text-xs text-gray-300 hover:bg-bg-tertiary disabled:opacity-40"
              >
                {loading ? "Loading…" : "Refresh"}
              </button>
              <input
                aria-label={`Search ${tab} records`}
                value={recordQuery}
                onChange={(event) => setRecordQuery(event.target.value)}
                placeholder="Search host, port, service, OS, info…"
                className="h-8 w-full rounded border border-border bg-bg-secondary px-2 text-xs text-gray-200 outline-none focus:border-accent sm:w-64"
              />
              <select
                aria-label="Filter records by field"
                value={recordFilterField}
                onChange={(event) => {
                  setRecordFilterField(event.target.value);
                  setRecordFilterValue("");
                }}
                className="h-8 rounded border border-border bg-bg-secondary px-2 text-xs text-gray-200 outline-none focus:border-accent"
              >
                <option value="">All fields</option>
                {databaseFilterFields.map((field) => <option key={field} value={field}>{field}</option>)}
              </select>
              <select
                aria-label="Filter records by value"
                value={recordFilterValue}
                disabled={!recordFilterField}
                onChange={(event) => setRecordFilterValue(event.target.value)}
                className="h-8 max-w-48 rounded border border-border bg-bg-secondary px-2 text-xs text-gray-200 outline-none focus:border-accent disabled:opacity-40"
              >
                <option value="">Any value</option>
                {databaseFilterValues.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
              <button
                onClick={exportDatabaseRecords}
                disabled={filteredDatabaseRows.length === 0}
                className="h-8 rounded border border-border px-3 text-xs text-gray-300 hover:bg-bg-tertiary disabled:cursor-not-allowed disabled:opacity-40"
              >
                Export JSON
              </button>
            </div>
          </div>

          {notice && <div role="status" className="text-xs text-accent">{notice}</div>}
          {loading && <div className="text-xs text-gray-600">Loading {tab} records…</div>}
          {!loading && error && (
            <div role="alert" className="rounded border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300">
              Could not load {tab} records: {error}
              <button
                onClick={() => setReloadToken((current) => current + 1)}
                className="ml-2 underline"
              >
                Try again
              </button>
            </div>
          )}
          {!loading && !error && rows.length === 0 && (
            <div className="rounded border border-border p-5 text-xs text-gray-500">
              No {tab === "vulns" ? "vulnerability" : tab === "creds" ? "credential" : tab} records in this workspace.
            </div>
          )}
          {!loading && !error && rows.length > 0 && filteredDatabaseRows.length === 0 && (
            <div className="rounded border border-border p-5 text-xs text-gray-500">
              No records match the current search and filters.
              <button
                onClick={() => { setRecordQuery(""); setRecordFilterField(""); setRecordFilterValue(""); }}
                className="ml-2 text-accent hover:underline"
              >
                Clear filters
              </button>
            </div>
          )}

          {!loading && !error && filteredDatabaseRows.length > 0 && (
            <div className="flex-1 min-h-0 overflow-auto rounded border border-border">
              <table className="w-full text-xs font-mono">
                <thead className="sticky top-0 z-10 bg-bg-secondary">
                  <tr className="border-b border-border text-left text-gray-500">
                    {databaseColumns.map((column) => (
                      <th key={column} className="px-3 py-2 font-medium">{column}</th>
                    ))}
                    <th className="px-3 py-2 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDatabaseRows.map(({ record, index }) => {
                    const host = relatedHostValue(record);
                    return (
                      <tr
                        key={`${tab}-${index}`}
                        data-context-kind={tab}
                        data-context-label={`${tab} · ${stringifyValue(record.address ?? record.name ?? record.host ?? index + 1)}`}
                        data-context-index={index}
                        data-context-value={stringifyValue(tab === "hosts" ? record.address ?? record.name : tab === "creds" ? record.username : record.id ?? record.address ?? record.host ?? record.name)}
                        data-context-host={host}
                        data-context-cves={tab === "vulns" ? extractCveIds(record).join(",") : ""}
                        data-context-references={tab === "vulns" ? JSON.stringify(extractHttpReferences(record)) : "[]"}
                        className="border-b border-border/50 text-gray-300 hover:bg-bg-tertiary/50">
                        {databaseColumns.map((column) => (
                          <td key={column} className="max-w-xs truncate px-3 py-2" title={recordValue(column, record[column])}>
                            {recordValue(column, record[column])}
                          </td>
                        ))}
                        <td className="whitespace-nowrap px-3 py-2 text-right">
                          <div className="flex justify-end gap-2">
                            {host && tab !== "hosts" && (
                              <button
                                onClick={() => navigateToDatabaseTab("hosts", host)}
                                className="rounded border border-border px-2 py-1 text-gray-400 hover:text-accent"
                                title={`Find host ${host}`}
                              >
                                Host
                              </button>
                            )}
                            <button
                              onClick={() => {
                                setSelectedRecord({ record, index });
                                setShowSensitiveFields(false);
                                setNotice("");
                                setCveResults({});
                                setCveNotice("");
                              }}
                              className="rounded border border-border px-2 py-1 text-accent hover:bg-bg-secondary"
                            >
                              Inspect
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border bg-bg-secondary/60 px-3 py-2 text-[11px] text-gray-500">
                <span>{filteredDatabaseRows.length} of {rows.length} records</span>
                <span>Sensitive fields are redacted from table, search and export.</span>
              </div>
            </div>
          )}
        </div>
      )}

      {selectedRecord && tab !== "loot" && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelectedRecord(null);
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="database-record-title"
            data-context-kind={tab}
            data-context-label={`${tab} record ${selectedRecord.index + 1}`}
            className="flex max-h-[85vh] w-full max-w-4xl flex-col overflow-hidden rounded border border-border bg-bg-primary shadow-2xl"
          >
            <div className="flex items-start justify-between gap-4 border-b border-border p-4">
              <div className="min-w-0">
                <h2 id="database-record-title" className="text-sm font-semibold capitalize text-gray-100">
                  {tab === "vulns" ? "Vulnerability" : tab === "creds" ? "Credential" : tab.slice(0, -1)} record
                </h2>
                <p className="mt-1 text-xs text-gray-500">Record {selectedRecord.index + 1} · active workspace · {tab}</p>
              </div>
              <button onClick={() => setSelectedRecord(null)} className="rounded px-2 py-1 text-xs text-gray-400 hover:bg-bg-tertiary">
                Close
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
              <button
                onClick={() => void copyDatabaseRecord(selectedRecord.record)}
                className="rounded border border-border px-3 py-1.5 text-xs text-gray-300 hover:bg-bg-tertiary"
              >
                Copy sanitized metadata
              </button>
              <button
                onClick={() => downloadJson(redactSensitiveFields(selectedRecord.record), `msf-${tab}-record-${selectedRecord.index + 1}.json`)}
                className="rounded border border-border px-3 py-1.5 text-xs text-gray-300 hover:bg-bg-tertiary"
              >
                Export record JSON
              </button>
              {hasSensitiveFields(selectedRecord.record) && (
                <button
                  onClick={() => setShowSensitiveFields((visible) => !visible)}
                  className="rounded border border-warning/30 px-3 py-1.5 text-xs text-warning hover:bg-warning/5"
                >
                  {showSensitiveFields ? "Hide sensitive fields" : "Reveal sensitive fields"}
                </button>
              )}
              {tab === "vulns" && (
                <button
                  onClick={() => void enrichVulnCves(selectedRecord.record)}
                  disabled={cveBusy}
                  className="rounded border border-border px-3 py-1.5 text-xs text-accent hover:bg-bg-tertiary disabled:cursor-wait disabled:opacity-50"
                >
                  {cveBusy ? "Looking up NVD…" : "Enrich via NVD"}
                </button>
              )}
            </div>
            <div className="flex-1 overflow-auto p-4">
              <dl className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {Object.entries(selectedRecord.record)
                  .filter(([key]) => !/path/i.test(key) && key !== "data" && key !== "download_id")
                  .map(([key, value]) => (
                    <div key={key} className="min-w-0 rounded border border-border/70 p-3">
                      <dt className="mb-1 text-[11px] uppercase tracking-wide text-gray-500">{key.replace(/_/g, " ")}</dt>
                      <dd className="whitespace-pre-wrap break-words text-xs text-gray-200">
                        {recordValue(key, value, showSensitiveFields)}
                      </dd>
                    </div>
                  ))}
              </dl>

              {tab === "vulns" && (
                <div className="mt-4 rounded border border-border bg-bg-secondary/50 p-3">
                  <h3 className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">NVD enrichment</h3>
                  {cveNotice && <p className="mt-2 text-xs text-gray-500">{cveNotice}</p>}
                  {!cveNotice && Object.keys(cveResults).length === 0 && !cveBusy && (
                    <p className="mt-2 text-xs text-gray-500">
                      Look up CVE identifiers referenced by this record against the National Vulnerability Database.
                    </p>
                  )}
                  {Object.keys(cveResults).length > 0 && (
                    <div className="mt-3 space-y-2">
                      {Object.entries(cveResults).map(([cveId, info]) => {
                        const errorInfo = info && "error" in info ? info.error : null;
                        const enrichment = info && !("error" in info) ? (info as CveEnrichment) : null;
                        return (
                          <div key={cveId} className="rounded border border-border/70 p-2">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-mono text-xs text-gray-200">{cveId}</span>
                              {enrichment?.cvss?.base_score != null && (
                                <span className="rounded bg-bg-tertiary px-2 py-0.5 text-[10px] text-gray-300">
                                  CVSS {enrichment.cvss.base_score} ({enrichment.cvss.base_severity ?? "—"})
                                </span>
                              )}
                            </div>
                            {errorInfo && <p className="mt-1 text-xs text-red-300">{errorInfo}</p>}
                            {!errorInfo && enrichment?.description && (
                              <p className="mt-1 text-xs text-gray-400">{enrichment.description}</p>
                            )}
                            {!errorInfo && enrichment === null && (
                              <p className="mt-1 text-xs text-gray-500">Not found in the NVD.</p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                  <p className="mt-2 text-[10px] text-gray-600">
                    Requires network access from the backend to services.nvd.nist.gov. Results are cached server-side.
                  </p>
                </div>
              )}

              {relatedHostValue(selectedRecord.record) && (
                <div className="mt-4 rounded border border-border bg-bg-secondary/50 p-3">
                  <h3 className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Related records</h3>
                  <p className="mt-1 text-xs text-gray-500">Host reference: {relatedHostValue(selectedRecord.record)}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {tab !== "hosts" && (
                      <button
                        onClick={() => navigateToDatabaseTab("hosts", relatedHostValue(selectedRecord.record))}
                        className="rounded border border-border px-3 py-1.5 text-xs text-accent hover:bg-bg-tertiary"
                      >
                        Find host
                      </button>
                    )}
                    {tab !== "services" && (
                      <button
                        onClick={() => navigateToDatabaseTab("services", relatedHostValue(selectedRecord.record))}
                        className="rounded border border-border px-3 py-1.5 text-xs text-accent hover:bg-bg-tertiary"
                      >
                        Services on host
                      </button>
                    )}
                    {tab !== "vulns" && (
                      <button
                        onClick={() => navigateToDatabaseTab("vulns", relatedHostValue(selectedRecord.record))}
                        className="rounded border border-border px-3 py-1.5 text-xs text-accent hover:bg-bg-tertiary"
                      >
                        Vulnerabilities on host
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
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
                  metadataForExport(selectedLoot.record),
                  `loot-${safeFilename(lootName(selectedLoot.record))}.json`
                )}
                className="rounded border border-border px-3 py-1.5 text-xs text-gray-300 hover:bg-bg-tertiary"
              >
                Export record JSON
              </button>
              <button
                disabled={selectedLoot.record.has_data !== true}
                title={selectedLoot.record.has_data === true ? "Download artifact data" : "No inline data or readable allowlisted file is available"}
                onClick={() => void downloadLootArtifact(selectedLoot.record)}
                className="rounded border border-border px-3 py-1.5 text-xs text-gray-300 hover:bg-bg-tertiary disabled:cursor-not-allowed disabled:opacity-40"
              >
                Download original
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              <dl className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {Object.entries(selectedLoot.record).filter(([key]) => key !== "download_id").map(([key, value]) => (
                  <div key={key} className="min-w-0 rounded border border-border/70 p-3">
                    <dt className="mb-1 text-[11px] uppercase tracking-wide text-gray-500">{key.replace(/_/g, " ")}</dt>
                    <dd className="whitespace-pre-wrap break-words text-xs text-gray-200">
                      {formatLootValue(key, value)}
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="mt-4 text-[11px] leading-relaxed text-gray-600">
                This view exports metadata separately from the artifact. Downloads use bytes supplied by Metasploit or a database-registered file explicitly allowed through MSF_LOOT_ALLOWED_FILES or MSF_LOOT_ALLOWED_DIRS in backend/.env. Server paths are never sent to the browser, and the browser cannot choose a filesystem path.
              </p>
              {notice && <div role="status" className="mt-3 text-xs text-accent">{notice}</div>}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
