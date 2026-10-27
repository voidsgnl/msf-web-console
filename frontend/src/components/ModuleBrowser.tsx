import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";

type ModuleRef = { type: string; name: string };
type SessionSummary = { id: string; session: Record<string, any> };
type ExecutionProgress = {
  phase: "submitting" | "running" | "completed" | "timeout" | "error";
  message: string;
  jobId?: string;
  sessions: SessionSummary[];
};

const POLL_INTERVAL_MS = 2000;
const EXECUTION_TIMEOUT_MS = 90000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function ModuleBrowser({ onViewSessions }: { onViewSessions: () => void }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState<string>("exploit");
  const [results, setResults] = useState<ModuleRef[]>([]);
  const [selected, setSelected] = useState<ModuleRef | null>(null);
  const [info, setInfo] = useState<{ info: any; options: any } | null>(null);
  const [optionValues, setOptionValues] = useState<Record<string, string>>({});
  const [executing, setExecuting] = useState(false);
  const [progress, setProgress] = useState<ExecutionProgress | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const search = async (q: string, selectedType = type) => {
    setQuery(q);
    if (q.length < 2) {
      setResults([]);
      setSearchError(null);
      return;
    }
    try {
      setSearchError(null);
      const res = await api.modules.search(q, selectedType);
      if (mounted.current) setResults(res.results);
    } catch (e: any) {
      console.error("module search failed:", e);
      if (mounted.current) {
        setSearchError(e.message ?? String(e));
        setResults([]);
      }
    }
  };

  const select = async (mod: ModuleRef) => {
    setSelected(mod);
    setProgress(null);
    setInfo(null);
    setInfoError(null);
    setLoadingInfo(true);
    try {
      const data = await api.modules.info(mod.type, mod.name);
      if (!mounted.current) return;
      setInfo(data);
      const defaults: Record<string, string> = {};
      for (const [key, opt] of Object.entries<any>(data.options || {})) {
        if (opt.default !== undefined && opt.default !== null) defaults[key] = String(opt.default);
      }
      setOptionValues(defaults);
    } catch (e: any) {
      console.error("module info failed:", e);
      if (mounted.current) setInfoError(e.message ?? String(e));
    } finally {
      if (mounted.current) setLoadingInfo(false);
    }
  };

  const execute = async () => {
    if (!selected || executing) return;
    setExecuting(true);
    setProgress({
      phase: "submitting",
      message: "Submitting module to Metasploit…",
      sessions: [],
    });

    try {
      // Capture the current sessions before execution so only sessions created
      // by this run are highlighted in the result panel.
      const before = await api.sessions.list();
      const previousSessionIds = new Set(Object.keys(before ?? {}));
      const result = await api.modules.execute(selected.type, selected.name, optionValues);
      const rawJobId = result?.job_id ?? result?.jobId;
      const jobId = rawJobId === undefined || rawJobId === null ? undefined : String(rawJobId);

      if (!mounted.current) return;
      setProgress({
        phase: "running",
        message: jobId
          ? "Module accepted. Waiting for the job to finish or a session to open…"
          : "Module submitted. Watching for new sessions…",
        jobId,
        sessions: [],
      });

      const startedAt = Date.now();
      let jobObserved = false;

      while (mounted.current && Date.now() - startedAt < EXECUTION_TIMEOUT_MS) {
        await sleep(POLL_INTERVAL_MS);
        if (!mounted.current) return;

        const [jobsResult, sessionsResult] = await Promise.allSettled([
          api.jobs.list(),
          api.sessions.list(),
        ]);

        const jobs = jobsResult.status === "fulfilled" ? jobsResult.value ?? {} : {};
        const sessions = sessionsResult.status === "fulfilled" ? sessionsResult.value ?? {} : {};
        const activeJobIds = Object.keys(jobs).map(String);
        if (jobId && activeJobIds.includes(jobId)) jobObserved = true;

        const newSessions = Object.entries(sessions)
          .filter(([id]) => !previousSessionIds.has(String(id)))
          .map(([id, session]) => ({ id: String(id), session: session as Record<string, any> }));

        if (newSessions.length > 0) {
          setProgress({
            phase: "running",
            message: `${newSessions.length} new session${newSessions.length === 1 ? "" : "s"} detected. You can open Sessions to interact with ${newSessions.length === 1 ? "it" : "them"}.`,
            jobId,
            sessions: newSessions,
          });
        }

        // Only call a job finished after it has appeared in job.list and then
        // disappeared; a newly submitted job may take a moment to be listed.
        if (jobId && jobObserved && !activeJobIds.includes(jobId)) {
          setProgress({
            phase: "completed",
            message: newSessions.length
              ? "Job finished and a new session was detected."
              : "Job finished. No new session was detected during this run.",
            jobId,
            sessions: newSessions,
          });
          return;
        }

        if (!jobId && newSessions.length > 0) {
          setProgress({
            phase: "completed",
            message: "A new session was detected.",
            sessions: newSessions,
          });
          return;
        }
      }

      if (mounted.current) {
        setProgress((current) => current ? {
          ...current,
          phase: "timeout",
          message: current.sessions.length
            ? "Still waiting for the job to settle. New session(s) are available below."
            : "No completion signal or new session was detected within 90 seconds. Check Jobs for the current job status.",
        } : null);
      }
    } catch (e: any) {
      if (mounted.current) {
        setProgress({
          phase: "error",
          message: e.message ?? String(e),
          sessions: [],
        });
      }
    } finally {
      if (mounted.current) setExecuting(false);
    }
  };

  const statusStyle = (phase: ExecutionProgress["phase"]) => {
    if (phase === "completed") return "text-emerald-400";
    if (phase === "error") return "text-danger";
    if (phase === "timeout") return "text-warning";
    return "text-accent";
  };

  return (
    <div className="flex h-full">
      {/* Search + results column */}
      <div className="w-80 border-r border-border flex flex-col">
        <div className="p-3 border-b border-border space-y-2">
          <select
            value={type}
            onChange={(e) => {
              const nextType = e.target.value;
              setType(nextType);
              if (query) void search(query, nextType);
            }}
            className="w-full bg-bg-tertiary border border-border rounded px-2 py-1.5 text-sm text-gray-200"
          >
            {["exploit", "auxiliary", "post", "payload", "encoder", "nop"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <input
            value={query}
            onChange={(e) => void search(e.target.value)}
            placeholder="Search modules…"
            className="w-full bg-bg-tertiary border border-border rounded px-2 py-1.5 text-sm text-gray-200 font-mono placeholder:text-gray-600"
          />
        </div>
        <div className="flex-1 overflow-y-auto">
          {results.map((r) => (
            <button
              key={r.name}
              onClick={() => void select(r)}
              className={`w-full text-left px-3 py-2 text-xs font-mono border-b border-border/50 hover:bg-bg-tertiary ${
                selected?.name === r.name ? "bg-bg-tertiary text-accent" : "text-gray-300"
              }`}
            >
              {r.name}
            </button>
          ))}
          {searchError && (
            <div className="p-3 text-xs text-danger">Search failed: {searchError}</div>
          )}
          {!searchError && query.length >= 2 && results.length === 0 && (
            <div className="p-3 text-xs text-gray-600">No matches</div>
          )}
        </div>
      </div>

      {/* Detail / options column */}
      <div className="flex-1 overflow-y-auto p-4">
        {!selected && <div className="text-sm text-gray-600">Select a module to view details and options.</div>}

        {selected && loadingInfo && <div className="text-sm text-gray-600">Loading {selected.name}…</div>}

        {selected && infoError && (
          <div className="text-sm text-danger">Failed to load module info: {infoError}</div>
        )}

        {selected && info && (
          <div className="space-y-4 max-w-2xl">
            <div>
              <h2 className="font-mono text-sm text-gray-100">{selected.name}</h2>
              <p className="text-xs text-gray-500 mt-1">{String(info.info?.description ?? "").slice(0, 400)}</p>
            </div>

            <div>
              <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Options</h3>
              <div className="space-y-1.5">
                {Object.entries<any>(info.options || {}).map(([key, opt]) => (
                  <div key={key} className="grid grid-cols-[120px_1fr_auto] items-center gap-2 text-xs">
                    <label className="font-mono text-gray-400">
                      {key}
                      {opt.required && <span className="text-danger">*</span>}
                    </label>
                    <input
                      value={optionValues[key] ?? ""}
                      onChange={(e) => setOptionValues((v) => ({ ...v, [key]: e.target.value }))}
                      className="bg-bg-tertiary border border-border rounded px-2 py-1 text-gray-200 font-mono"
                    />
                    <span className="text-gray-600">{opt.type}</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={() => void execute()}
              disabled={executing}
              className="bg-accent-dim hover:bg-accent text-black font-medium text-sm px-4 py-1.5 rounded disabled:opacity-50"
            >
              {executing ? "Running…" : "Execute"}
            </button>

            {progress && (
              <section className="rounded border border-border bg-bg-secondary p-3 space-y-3" aria-live="polite">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className={`text-xs font-semibold uppercase tracking-wide ${statusStyle(progress.phase)}`}>
                      {progress.phase === "submitting" ? "Submitting" :
                        progress.phase === "running" ? "In progress" :
                        progress.phase === "completed" ? "Completed" :
                        progress.phase === "timeout" ? "Needs attention" : "Failed"}
                    </div>
                    <p className="text-sm text-gray-200 mt-1">{progress.message}</p>
                    {progress.jobId && (
                      <p className="text-xs text-gray-500 mt-1 font-mono">Job ID: {progress.jobId}</p>
                    )}
                  </div>
                  {progress.sessions.length > 0 && (
                    <button
                      onClick={onViewSessions}
                      className="shrink-0 bg-accent-dim hover:bg-accent text-black text-xs font-medium px-3 py-1.5 rounded"
                    >
                      Open Sessions
                    </button>
                  )}
                </div>

                {progress.sessions.length > 0 && (
                  <div className="space-y-1.5">
                    <h3 className="text-xs uppercase tracking-wide text-gray-500">New sessions</h3>
                    {progress.sessions.map(({ id, session }) => (
                      <div key={id} className="flex items-center justify-between gap-3 border border-border/70 rounded px-2.5 py-2">
                        <div className="min-w-0">
                          <div className="text-xs text-emerald-400 font-mono">Session {id} · {String(session.type ?? "session")}</div>
                          <div className="text-xs text-gray-400 truncate">
                            {String(session.target_host ?? session.session_host ?? "Unknown host")}
                            {session.target_port ? `:${session.target_port}` : ""}
                            {session.info ? ` · ${session.info}` : ""}
                          </div>
                        </div>
                        <button onClick={onViewSessions} className="text-xs text-accent hover:underline">Interact</button>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
