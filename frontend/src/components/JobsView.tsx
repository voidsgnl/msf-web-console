import type { ReactNode } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";

type JobInfo = Record<string, unknown>;

const SENSITIVE_FIELD = /pass(word|wd)?|secret|token|credential|private|api.?key|access.?key|auth|^key$/i;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isSensitiveField(key: string): boolean {
  return SENSITIVE_FIELD.test(key);
}

function formatLabel(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^\w/, (char) => char.toUpperCase());
}

function textValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not provided";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string" || typeof value === "number") return String(value);
  return Array.isArray(value) ? `${value.length} item${value.length === 1 ? "" : "s"}` : "Structured value";
}

function formatStartTime(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not provided";
  const numeric = typeof value === "number" ? value : Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 100000000000 ? numeric * 1000 : numeric)
    : new Date(String(value));
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function durationSince(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Unavailable";
  const numeric = typeof value === "number" ? value : Number(value);
  const started = Number.isFinite(numeric) ? (numeric < 100000000000 ? numeric * 1000 : numeric) : Date.parse(String(value));
  if (!Number.isFinite(started) || started <= 0) return "Unavailable";
  const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

function sanitizeJobInfo(value: unknown, fieldName = ""): unknown {
  if (isSensitiveField(fieldName)) return "[redacted]";
  if (Array.isArray(value)) return value.map((item) => sanitizeJobInfo(item));
  if (isObject(value)) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !/path/i.test(key) && key !== "data" && key !== "download_id")
        .map(([key, nested]) => [key, sanitizeJobInfo(nested, key)])
    );
  }
  return value;
}

function safeValue(value: unknown, fieldName = "", depth = 0): ReactNode {
  if (isSensitiveField(fieldName)) {
    return <span className="font-mono text-warning">•••••••• <span className="text-[10px] text-gray-500">(masked)</span></span>;
  }
  if (value === null || value === undefined || value === "") {
    return <span className="text-gray-600">Not provided</span>;
  }
  if (typeof value === "boolean") return <span>{value ? "Enabled" : "Disabled"}</span>;
  if (typeof value === "string" || typeof value === "number") {
    return <span className="break-words">{String(value)}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-gray-600">None</span>;
    if (depth >= 3) return <span className="text-gray-400">{value.length} items</span>;
    if (value.every((item) => ["string", "number", "boolean"].includes(typeof item))) {
      return <span className="break-words">{value.map((item) => String(item)).join(", ")}</span>;
    }
    return (
      <div className="space-y-2">
        {value.map((item, index) => (
          <div key={index} className="rounded border border-border/60 bg-bg-primary/50 p-2">
            {safeValue(item, "", depth + 1)}
          </div>
        ))}
      </div>
    );
  }
  if (isObject(value)) {
    const fields = Object.entries(value);
    if (!fields.length) return <span className="text-gray-600">No fields</span>;
    if (depth >= 3) return <span className="text-gray-400">{fields.length} fields</span>;
    return (
      <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {fields
          .filter(([key]) => !/path/i.test(key) && key !== "data" && key !== "download_id")
          .map(([key, nested]) => (
            <div key={key} className="min-w-0 rounded border border-border/60 bg-bg-primary/40 p-2">
              <dt className="mb-1 text-[10px] uppercase tracking-wide text-gray-500">{formatLabel(key)}</dt>
              <dd className="text-xs text-gray-200">{safeValue(nested, key, depth + 1)}</dd>
            </div>
          ))}
      </dl>
    );
  }
  return <span className="text-gray-400">Unavailable value</span>;
}

export function JobsView() {
  const [jobs, setJobs] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [stoppingJobId, setStoppingJobId] = useState<string | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [jobInfo, setJobInfo] = useState<JobInfo | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const mounted = useRef(true);
  const refreshInFlight = useRef(false);
  const refreshAgain = useRef(false);
  const detailRequest = useRef(0);

  const refresh = useCallback(async (manual = false) => {
    if (refreshInFlight.current) {
      refreshAgain.current = true;
      return;
    }
    refreshInFlight.current = true;
    if (manual) setRefreshing(true);
    try {
      const data = await api.jobs.list();
      if (mounted.current) {
        setJobs(data && typeof data === "object" ? data : {});
        setError(null);
      }
    } catch (e: unknown) {
      if (mounted.current) setError(errorMessage(e));
    } finally {
      refreshInFlight.current = false;
      if (mounted.current) {
        setLoading(false);
        setRefreshing(false);
      }
      if (refreshAgain.current && mounted.current) {
        refreshAgain.current = false;
        void refresh();
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
      detailRequest.current += 1;
    };
  }, [refresh]);

  const showJobInfo = async (id: string, toggle = true) => {
    if (toggle && selectedJobId === id) {
      detailRequest.current += 1;
      setSelectedJobId(null);
      setJobInfo(null);
      setDetailError(null);
      return;
    }

    const requestId = ++detailRequest.current;
    setSelectedJobId(id);
    setJobInfo(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      const data = await api.jobs.info(id);
      if (mounted.current && requestId === detailRequest.current) {
        setJobInfo(data && typeof data === "object" ? data : { result: data });
      }
    } catch (e: unknown) {
      if (mounted.current && requestId === detailRequest.current) {
        setDetailError(errorMessage(e));
      }
    } finally {
      if (mounted.current && requestId === detailRequest.current) setDetailLoading(false);
    }
  };

  const stopJob = async (id: string, name: string) => {
    if (!window.confirm(`Stop job ${id} (${name})? This interrupts the running task.`)) return;
    setStoppingJobId(id);
    setActionError(null);
    setNotice(null);
    try {
      await api.jobs.stop(id);
      if (mounted.current) {
        setNotice(`Stop requested for job ${id}.`);
        if (selectedJobId === id) {
          setSelectedJobId(null);
          setJobInfo(null);
          detailRequest.current += 1;
        }
      }
      await refresh(true);
    } catch (e: unknown) {
      if (mounted.current) setActionError(`Could not stop job ${id}: ${errorMessage(e)}`);
    } finally {
      if (mounted.current) setStoppingJobId(null);
    }
  };

  const entries = Object.entries(jobs);
  const jobTitle = selectedJobId && jobInfo
    ? String(jobInfo.name ?? jobInfo.module ?? entries.find(([id]) => id === selectedJobId)?.[1] ?? `Job ${selectedJobId}`)
    : selectedJobId ? `Job ${selectedJobId}` : "";
  const datastore = jobInfo && isObject(jobInfo.datastore) ? jobInfo.datastore : {};
  const optionEntries = Object.entries(datastore)
    .filter(([key]) => !/path/i.test(key) && key !== "data" && key !== "download_id")
    .sort(([a], [b]) => a.localeCompare(b));
  const knownFields = new Set(["jid", "name", "start_time", "uripath", "datastore"]);
  const additionalFields = jobInfo
    ? Object.entries(jobInfo).filter(([key]) => !knownFields.has(key) && !/path/i.test(key) && key !== "data")
    : [];

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-3 gap-3">
        <div>
          <h2 className="text-sm text-gray-200">Running Jobs</h2>
          <p className="mt-1 text-[10px] text-gray-600">
            {entries.length} active {entries.length === 1 ? "job" : "jobs"} · auto-refreshes every 5 seconds
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
          <p className="font-medium">Could not load jobs</p>
          <p className="mt-1 break-words">{error}</p>
          <button onClick={() => void refresh(true)} className="mt-2 underline">Try again</button>
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
        <div className="text-xs text-gray-500">Loading running jobs…</div>
      )}
      {!loading && !error && entries.length === 0 && (
        <div className="rounded border border-border bg-bg-secondary/50 p-4 text-xs text-gray-500">
          No running jobs. Jobs started from the console or module browser will appear here.
        </div>
      )}

      {entries.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-left text-gray-500 border-b border-border">
                <th className="py-2 pr-4">ID</th>
                <th className="py-2 pr-4">Name</th>
                <th className="py-2 pr-4">Details</th>
                <th className="py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(([id, rawName]) => {
                const name = typeof rawName === "string"
                  ? rawName
                  : isObject(rawName)
                    ? String(rawName.name ?? rawName.module ?? "Unnamed job")
                    : "Unnamed job";
                const isSelected = selectedJobId === id;
                return (
                  <tr key={id} data-context-kind="job" data-context-label={`Job ${id} · ${name}`} className="border-b border-border/50 text-gray-300">
                    <td className="py-2 pr-4 align-top text-accent">{id}</td>
                    <td className="py-2 pr-4 align-top break-words">{name}</td>
                    <td className="py-2 pr-4 align-top">
                      <button onClick={() => void showJobInfo(id)} className="text-accent hover:underline">
                        {isSelected ? "hide details" : "inspect"}
                      </button>
                    </td>
                    <td className="py-2 align-top">
                      <button
                        onClick={() => void stopJob(id, name)}
                        disabled={stoppingJobId !== null}
                        className="text-danger hover:underline disabled:opacity-50"
                      >
                        {stoppingJobId === id ? "stopping…" : "stop"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedJobId && (
        <section className="mt-4 overflow-hidden rounded-lg border border-border bg-bg-secondary/60">
          <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
            <div className="min-w-0">
              <p className="text-[10px] uppercase tracking-widest text-gray-500">Job inspection</p>
              <h3 className="mt-1 break-words text-sm font-semibold text-gray-100">{jobTitle}</h3>
              <p className="mt-1 text-[11px] text-gray-500">A formatted view of the information returned by Metasploit.</p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                onClick={() => {
                  if (!jobInfo) return;
                  const exportable = sanitizeJobInfo(jobInfo);

                  const blob = new Blob([JSON.stringify(exportable, null, 2)], { type: "application/json;charset=utf-8" });
                  const url = URL.createObjectURL(blob);
                  const anchor = document.createElement("a");
                  anchor.href = url;
                  anchor.download = `job-${selectedJobId}-details.json`;
                  anchor.click();
                  URL.revokeObjectURL(url);
                }}
                disabled={!jobInfo}
                className="rounded border border-border px-2 py-1.5 text-[10px] text-gray-300 hover:bg-bg-tertiary disabled:opacity-40"
              >
                Export sanitized JSON
              </button>
              <button
                onClick={() => void showJobInfo(selectedJobId, false)}
                disabled={detailLoading}
                className="rounded border border-border px-2 py-1.5 text-[10px] text-gray-400 hover:bg-bg-tertiary disabled:opacity-50"
              >
                {detailLoading ? "loading…" : "reload"}
              </button>
            </div>
          </div>
          <div className="space-y-4 p-4">
            {detailLoading && <p className="text-xs text-gray-500">Loading job details…</p>}
            {detailError && (
              <div role="alert" className="rounded border border-danger/30 bg-danger/5 p-3 text-xs text-danger">
                <p>Could not load this job's details: {detailError}</p>
                <button onClick={() => void showJobInfo(selectedJobId, false)} className="mt-2 underline">Try again</button>
              </div>
            )}
            {jobInfo && !detailLoading && (
              <>
                <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                  <div className="min-w-0 rounded border border-border/70 bg-bg-primary/40 p-3">
                    <dt className="mb-1 text-[10px] uppercase tracking-widest text-gray-500">Job ID</dt>
                    <dd className="font-mono text-sm text-accent">{textValue(jobInfo.jid ?? selectedJobId)}</dd>
                  </div>
                  <div className="min-w-0 rounded border border-border/70 bg-bg-primary/40 p-3 sm:col-span-2">
                    <dt className="mb-1 text-[10px] uppercase tracking-widest text-gray-500">Job name</dt>
                    <dd className="break-words text-xs text-gray-200">{textValue(jobInfo.name ?? jobTitle)}</dd>
                  </div>
                  <div className="min-w-0 rounded border border-border/70 bg-bg-primary/40 p-3">
                    <dt className="mb-1 text-[10px] uppercase tracking-widest text-gray-500">Running time</dt>
                    <dd className="text-xs text-gray-200">{durationSince(jobInfo.start_time)}</dd>
                  </div>
                  <div className="min-w-0 rounded border border-border/70 bg-bg-primary/40 p-3 sm:col-span-2">
                    <dt className="mb-1 text-[10px] uppercase tracking-widest text-gray-500">Started</dt>
                    <dd className="text-xs text-gray-200">{formatStartTime(jobInfo.start_time)}</dd>
                  </div>
                  {jobInfo.uripath !== undefined && (
                    <div className="min-w-0 rounded border border-border/70 bg-bg-primary/40 p-3 sm:col-span-2">
                      <dt className="mb-1 text-[10px] uppercase tracking-widest text-gray-500">URI route</dt>
                      <dd className="break-words font-mono text-xs text-gray-200">{textValue(jobInfo.uripath)}</dd>
                    </div>
                  )}
                </dl>

                {optionEntries.length > 0 && (
                  <section className="rounded-lg border border-border bg-bg-primary/30">
                    <div className="border-b border-border px-3 py-2">
                      <h4 className="text-[11px] font-semibold uppercase tracking-widest text-gray-300">Job configuration</h4>
                      <p className="mt-1 text-[11px] text-gray-500">
                        {optionEntries.length} options · secret-like values are masked
                      </p>
                    </div>
                    <dl className="grid grid-cols-1 gap-2 p-3 sm:grid-cols-2 lg:grid-cols-3">
                      {optionEntries.map(([key, value]) => (
                        <div key={key} className="min-w-0 rounded border border-border/60 bg-bg-secondary/50 p-2.5">
                          <dt className="mb-1 text-[10px] uppercase tracking-wide text-gray-500">{formatLabel(key)}</dt>
                          <dd className="break-words font-mono text-xs text-gray-200">{safeValue(value, key)}</dd>
                        </div>
                      ))}
                    </dl>
                  </section>
                )}

                {additionalFields.length > 0 && (
                  <section className="rounded-lg border border-border bg-bg-primary/30">
                    <div className="border-b border-border px-3 py-2">
                      <h4 className="text-[11px] font-semibold uppercase tracking-widest text-gray-300">Additional details</h4>
                      <p className="mt-1 text-[11px] text-gray-500">Other metadata from Metasploit, formatted and filtered for sensitive values.</p>
                    </div>
                    <dl className="grid grid-cols-1 gap-2 p-3 sm:grid-cols-2">
                      {additionalFields.map(([key, value]) => (
                        <div key={key} className="min-w-0 rounded border border-border/60 bg-bg-secondary/50 p-2.5">
                          <dt className="mb-1 text-[10px] uppercase tracking-wide text-gray-500">{formatLabel(key)}</dt>
                          <dd className="break-words text-xs text-gray-200">{safeValue(value, key)}</dd>
                        </div>
                      ))}
                    </dl>
                  </section>
                )}

                {optionEntries.length === 0 && additionalFields.length === 0 && jobInfo.uripath === undefined && (
                  <p className="text-xs text-gray-500">No additional details were provided for this job.</p>
                )}
                <p className="text-[10px] text-gray-600">
                  Metasploit exposes job metadata and the module datastore here; detailed execution output is available in the console or module result view when supported.
                </p>
              </>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
