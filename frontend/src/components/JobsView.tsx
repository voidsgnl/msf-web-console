import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";

type JobInfo = Record<string, unknown>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function pretty(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
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
                  : String((rawName as Record<string, unknown> | null)?.name ?? pretty(rawName) ?? "Unknown job");
                const isSelected = selectedJobId === id;
                return (
                  <tr key={id} className="border-b border-border/50 text-gray-300">
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
        <section className="mt-4 rounded border border-border bg-bg-secondary/60 overflow-hidden">
          <div className="flex items-center justify-between gap-3 border-b border-border px-3 py-2">
            <h3 className="text-xs font-semibold text-gray-300">Job {selectedJobId} details</h3>
            <button
              onClick={() => void showJobInfo(selectedJobId, false)}
              disabled={detailLoading}
              className="text-[10px] text-gray-500 hover:text-gray-300 disabled:opacity-50"
            >
              {detailLoading ? "loading…" : "reload"}
            </button>
          </div>
          <div className="p-3">
            {detailLoading && <p className="text-xs text-gray-500">Loading job details…</p>}
            {detailError && (
              <div role="alert" className="text-xs text-danger">
                <p>Could not load this job's details: {detailError}</p>
                <button onClick={() => void showJobInfo(selectedJobId, false)} className="mt-2 underline">Try again</button>
              </div>
            )}
            {jobInfo && !detailLoading && (
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words text-[11px] leading-5 text-gray-300">
                {pretty(jobInfo)}
              </pre>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
