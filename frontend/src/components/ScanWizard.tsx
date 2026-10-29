import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { suggestForPort } from "../lib/portSuggestions";

type Phase = "idle" | "submitting" | "running" | "completed" | "timeout" | "error";

type DiscoveredService = {
  host: string;
  port: number;
};

const COMMON_PORTS =
  "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017";
const POLL_INTERVAL_MS = 2000;
const SCAN_TIMEOUT_MS = 5 * 60 * 1000;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  return `${minutes}m ${totalSeconds % 60}s`;
}

export function ScanWizard({ onInvestigate }: { onInvestigate: (type: string, query: string) => void }) {
  const [target, setTarget] = useState("");
  const [scanAllPorts, setScanAllPorts] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState("");
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [nowTick, setNowTick] = useState(() => Date.now());
  const [services, setServices] = useState<DiscoveredService[]>([]);
  const mounted = useRef(true);
  const runGeneration = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    if (phase !== "submitting" && phase !== "running") return;
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [phase]);

  const startScan = async () => {
    const trimmedTarget = target.trim();
    if (!trimmedTarget || phase === "submitting" || phase === "running") return;

    const generation = ++runGeneration.current;
    const isCurrentRun = () => mounted.current && runGeneration.current === generation;

    setServices([]);
    setStartedAt(Date.now());
    setPhase("submitting");
    setMessage("Starting the port scan…");

    try {
      const result = await api.modules.execute("auxiliary", "scanner/portscan/tcp", {
        RHOSTS: trimmedTarget,
        PORTS: scanAllPorts ? "1-10000" : COMMON_PORTS,
      });
      if (!isCurrentRun()) return;

      const rawJobId = result?.job_id ?? result?.jobId;
      const jobId = rawJobId === undefined || rawJobId === null ? undefined : String(rawJobId);
      const rawUuid = result?.uuid ?? result?.run_uuid;
      const runUuid = typeof rawUuid === "string" && /^[A-Za-z0-9]{12,64}$/.test(rawUuid) ? rawUuid : undefined;

      setPhase("running");
      setMessage(
        scanAllPorts
          ? "Scanning all 10,000 ports - this can take several minutes…"
          : "Scanning the common ports…"
      );

      const deadline = Date.now() + SCAN_TIMEOUT_MS;
      let jobObserved = false;

      while (isCurrentRun() && Date.now() < deadline) {
        await sleep(POLL_INTERVAL_MS);
        if (!isCurrentRun()) return;

        const [jobsResult, statsResult] = await Promise.allSettled([api.jobs.list(), api.modules.runningStats()]);
        const jobs = jobsResult.status === "fulfilled" ? jobsResult.value ?? {} : {};
        const activeJobIds = Object.keys(jobs).map(String);
        if (jobId && activeJobIds.includes(jobId)) jobObserved = true;

        const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
        const asIds = (value: unknown) => (Array.isArray(value) ? value.map(String) : []);
        const resultIds = asIds(stats?.results);
        const runHasResult = Boolean(runUuid && resultIds.includes(runUuid));

        const jobFinished = jobId ? jobObserved && !activeJobIds.includes(jobId) : false;

        if (runHasResult || jobFinished || (!jobId && !runUuid)) {
          await finishScan(isCurrentRun);
          return;
        }
      }

      if (isCurrentRun()) {
        setPhase("timeout");
        setMessage(
          `This panel stopped watching after ${Math.round(SCAN_TIMEOUT_MS / 60000)} minutes, but the scan may still be running. Check the Jobs tab, or check back here - results found so far are shown below once available.`
        );
        await loadServices();
      }
    } catch (e: unknown) {
      if (isCurrentRun()) {
        setPhase("error");
        setMessage(e instanceof Error ? e.message : String(e));
      }
    }
  };

  const loadServices = async () => {
    try {
      const result = await api.db.services();
      if (!mounted.current) return;
      const rows = Array.isArray(result?.services) ? result.services : [];
      const open: DiscoveredService[] = rows
        .filter((row: any) => row && row.state === "open" && row.port !== undefined && row.port !== null)
        .map((row: any) => ({ host: String(row.host ?? "unknown"), port: Number(row.port) }))
        .filter((row: DiscoveredService) => Number.isFinite(row.port));
      open.sort((a, b) => (a.host === b.host ? a.port - b.port : a.host.localeCompare(b.host)));
      setServices(open);
    } catch {
      // Non-fatal: the scan itself already ran, this just couldn't refresh the table.
    }
  };

  const finishScan = async (isCurrentRun: () => boolean) => {
    await loadServices();
    if (!isCurrentRun()) return;
    setPhase("completed");
    setMessage("Scan finished.");
  };

  const busy = phase === "submitting" || phase === "running";

  return (
    <div className="p-4 md:p-6 max-w-4xl">
      <div className="mb-4">
        <h2 className="text-sm text-gray-200 font-medium">Scan a target</h2>
        <p className="mt-1 text-xs text-gray-500 leading-relaxed">
          Enter an IP, hostname, range (10.0.0.1-10.0.0.254), or CIDR block (10.0.0.0/24) you are authorized to test.
          This runs Metasploit's own TCP port scanner against it and lists what's open, with a plain-language guess at
          what each port is likely running - based only on the port number, not a confirmed scan of the service
          itself. Use the suggestion to jump into the module browser and investigate further.
        </p>
      </div>

      <div className="rounded-lg border border-border bg-bg-secondary/60 p-4 space-y-3">
        <div>
          <label htmlFor="scan-target" className="block text-[11px] text-gray-400 mb-1.5">Target</label>
          <input
            id="scan-target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="e.g. 10.0.0.5 or 10.0.0.0/24"
            disabled={busy}
            className="w-full bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-100 font-mono placeholder:text-gray-600 focus:outline-none focus:border-accent disabled:opacity-50"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={scanAllPorts}
            onChange={(event) => setScanAllPorts(event.target.checked)}
            disabled={busy}
            className="accent-accent"
          />
          Scan all 10,000 ports instead of the ~25 common ones (slower, more thorough)
        </label>
        <button
          onClick={() => void startScan()}
          disabled={busy || !target.trim()}
          className="rounded bg-accent hover:bg-emerald-400 text-gray-950 font-semibold text-xs px-4 py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {busy ? "Scanning…" : "Start scan"}
        </button>
      </div>

      {phase !== "idle" && (
        <div className="mt-4 rounded-lg border border-border bg-bg-secondary/40 p-4">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-semibold uppercase tracking-widest ${
              phase === "completed" ? "text-emerald-400" : phase === "error" ? "text-danger" : phase === "timeout" ? "text-warning" : "text-accent"
            }`}>
              {phase === "submitting" ? "Starting" : phase === "running" ? "Scanning" : phase === "completed" ? "Completed" : phase === "timeout" ? "Still running (in background)" : "Failed"}
            </span>
            {busy && startedAt && (
              <span className="text-[10px] text-gray-500 font-mono">· {formatElapsed(nowTick - startedAt)} elapsed</span>
            )}
          </div>
          <p className="text-xs text-gray-300 mt-1.5">{message}</p>
        </div>
      )}

      {services.length > 0 && (
        <div className="mt-4">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 mb-2">
            {services.length} open port{services.length === 1 ? "" : "s"} found
          </h3>
          <div className="space-y-2">
            {services.map((service) => {
              const suggestion = suggestForPort(service.port);
              return (
                <div key={`${service.host}:${service.port}`} className="rounded border border-border bg-bg-secondary/50 p-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-accent">{service.host}:{service.port}</span>
                      <span className="rounded border border-border px-2 py-0.5 text-[10px] text-gray-300">{suggestion.label}</span>
                      <span className="text-[10px] text-gray-600">(guessed from port number, not confirmed)</span>
                    </div>
                    <p className="text-[11px] text-gray-500 mt-1 leading-relaxed">{suggestion.note}</p>
                  </div>
                  <button
                    onClick={() => onInvestigate("auxiliary", suggestion.keyword)}
                    className="shrink-0 rounded border border-accent/30 bg-accent/5 px-3 py-1.5 text-[11px] text-accent hover:bg-accent/10"
                  >
                    Investigate in Modules
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {phase === "completed" && services.length === 0 && (
        <div className="mt-4 rounded border border-border bg-bg-secondary/50 p-4 text-xs text-gray-500">
          No open ports found among the ones checked. Try "Scan all 10,000 ports" if the service might be on an
          uncommon port, or double-check the target is reachable from this machine.
        </div>
      )}
    </div>
  );
}
