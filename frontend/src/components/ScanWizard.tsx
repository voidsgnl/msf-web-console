import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { SuggestedModule } from "../lib/api";
import { suggestForPort } from "../lib/portSuggestions";
import { detectionModuleForPort } from "../lib/versionDetection";

type Phase = "idle" | "submitting" | "running" | "completed" | "timeout" | "error";
type ConfirmPhase = "idle" | "running" | "done";
type SuggestionStatus = "idle" | "loading" | "done" | "error";
type VerifyStatus = "idle" | "running" | "done" | "error";

type DiscoveredService = {
  host: string;
  port: number;
  info: string;
};

type SuggestionState = {
  status: SuggestionStatus;
  query: string | null;
  candidates: SuggestedModule[];
  note?: string;
  error?: string;
};

type VerifyState = {
  status: VerifyStatus;
  verdict?: "vulnerable" | "not_vulnerable" | "unknown";
  rawOutput?: string;
  error?: string;
};

const COMMON_PORTS =
  "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017";
const POLL_INTERVAL_MS = 2000;
const SCAN_TIMEOUT_MS = 5 * 60 * 1000;
const CONFIRM_TIMEOUT_MS = 2 * 60 * 1000;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const serviceKey = (service: DiscoveredService) => `${service.host}:${service.port}`;
const candidateKey = (service: DiscoveredService, candidate: SuggestedModule) =>
  `${serviceKey(service)}:${candidate.type}/${candidate.name}`;

function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  return `${minutes}m ${totalSeconds % 60}s`;
}

function rankBadgeStyle(rankWeight: number): string {
  if (rankWeight >= 500) return "border-emerald-500/30 bg-emerald-500/5 text-emerald-400";
  if (rankWeight >= 300) return "border-accent/30 bg-accent/5 text-accent";
  if (rankWeight < 0) return "border-border text-gray-500";
  return "border-warning/30 bg-warning/5 text-warning";
}

function verdictBadge(state: VerifyState | undefined): { label: string; style: string } | null {
  if (!state || state.status === "idle") return null;
  if (state.status === "running") return { label: "Checking…", style: "border-border text-gray-400" };
  if (state.status === "error") return { label: "Check failed", style: "border-danger/30 bg-danger/5 text-danger" };
  if (state.verdict === "vulnerable") return { label: "Appears vulnerable", style: "border-danger/30 bg-danger/5 text-danger" };
  if (state.verdict === "not_vulnerable") return { label: "Not vulnerable", style: "border-emerald-500/30 bg-emerald-500/5 text-emerald-400" };
  return { label: "Unknown / unconfirmed", style: "border-warning/30 bg-warning/5 text-warning" };
}

export function ScanWizard({ onInvestigate }: { onInvestigate: (type: string, query: string, targetContext?: ScanTargetContext) => void }) {
  const [target, setTarget] = useState("");
  const [scanAllPorts, setScanAllPorts] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState("");
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [nowTick, setNowTick] = useState(() => Date.now());
  const [services, setServices] = useState<DiscoveredService[]>([]);
  const [confirmPhase, setConfirmPhase] = useState<ConfirmPhase>("idle");
  const [confirmMessage, setConfirmMessage] = useState("");
  const [suggestions, setSuggestions] = useState<Record<string, SuggestionState>>({});
  const [verifications, setVerifications] = useState<Record<string, VerifyState>>({});
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
    setSuggestions({});
    setVerifications({});
    setConfirmPhase("idle");
    setConfirmMessage("");
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
        .map((row: any) => ({
          host: String(row.host ?? "unknown"),
          port: Number(row.port),
          info: typeof row.info === "string" ? row.info.trim() : "",
        }))
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

  const confirmServiceVersions = async () => {
    if (confirmPhase === "running") return;

    const targets = services
      .map((service) => ({ service, detection: detectionModuleForPort(service.port) }))
      .filter((entry): entry is { service: DiscoveredService; detection: NonNullable<ReturnType<typeof detectionModuleForPort>> } =>
        Boolean(entry.detection)
      );

    if (targets.length === 0) {
      setConfirmMessage("None of the discovered ports have a known version-detection module yet.");
      return;
    }

    setConfirmPhase("running");
    setConfirmMessage(
      `Confirming ${targets.length} service${targets.length === 1 ? "" : "s"} by actually connecting to ${
        targets.length === 1 ? "it" : "them"
      } and reading the banner/version response…`
    );

    const jobIds: string[] = [];
    for (const { service, detection } of targets) {
      try {
        const result = await api.modules.execute("auxiliary", detection.module, {
          RHOSTS: service.host,
          RPORT: String(service.port),
          ...(detection.options ?? {}),
        });
        const rawJobId = result?.job_id ?? result?.jobId;
        if (rawJobId !== undefined && rawJobId !== null) jobIds.push(String(rawJobId));
      } catch {
        // One module failing to queue (e.g. target unreachable) shouldn't block the rest.
      }
    }

    if (!mounted.current) return;

    if (jobIds.length === 0) {
      setConfirmPhase("done");
      setConfirmMessage("Couldn't start any version checks - the backend may be unreachable.");
      return;
    }

    const deadline = Date.now() + CONFIRM_TIMEOUT_MS;
    while (mounted.current && Date.now() < deadline) {
      await sleep(POLL_INTERVAL_MS);
      if (!mounted.current) return;
      try {
        const jobs = await api.jobs.list();
        const activeIds = Object.keys(jobs ?? {}).map(String);
        if (!jobIds.some((id) => activeIds.includes(id))) break;
      } catch {
        break;
      }
    }

    if (!mounted.current) return;
    await loadServices();
    if (!mounted.current) return;
    setConfirmPhase("done");
    setConfirmMessage("Version checks finished. Confirmed services are labeled below.");
  };

  const loadSuggestions = async (service: DiscoveredService) => {
    const key = serviceKey(service);
    setSuggestions((current) => ({
      ...current,
      [key]: { status: "loading", query: null, candidates: [] },
    }));
    try {
      const result = await api.modules.suggest(service.info, service.port);
      if (!mounted.current) return;
      setSuggestions((current) => ({
        ...current,
        [key]: { status: "done", query: result.query, candidates: result.candidates, note: result.note },
      }));
    } catch (e: unknown) {
      if (!mounted.current) return;
      setSuggestions((current) => ({
        ...current,
        [key]: {
          status: "error",
          query: null,
          candidates: [],
          error: e instanceof Error ? e.message : String(e),
        },
      }));
    }
  };

  const verifyCandidate = async (service: DiscoveredService, candidate: SuggestedModule) => {
    const key = candidateKey(service, candidate);
    setVerifications((current) => ({ ...current, [key]: { status: "running" } }));
    try {
      const result = await api.modules.checkModule(candidate.type, candidate.name, {
        RHOSTS: service.host,
        RPORT: String(service.port),
      });
      if (!mounted.current) return;
      setVerifications((current) => ({
        ...current,
        [key]: { status: "done", verdict: result.verdict, rawOutput: result.raw_output },
      }));
    } catch (e: unknown) {
      if (!mounted.current) return;
      setVerifications((current) => ({
        ...current,
        [key]: { status: "error", error: e instanceof Error ? e.message : String(e) },
      }));
    }
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
          itself. Use the suggestion to jump into the module browser and investigate further, or confirm a subset of
          services automatically below.
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
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <h3 className="text-xs uppercase tracking-widest text-gray-400">
              {services.length} open port{services.length === 1 ? "" : "s"} found
            </h3>
            <button
              onClick={() => void confirmServiceVersions()}
              disabled={confirmPhase === "running"}
              className="shrink-0 rounded border border-accent/30 bg-accent/5 px-3 py-1.5 text-[11px] text-accent hover:bg-accent/10 disabled:cursor-wait disabled:opacity-50"
            >
              {confirmPhase === "running" ? "Confirming…" : "Confirm service versions"}
            </button>
          </div>
          {confirmMessage && <p className="text-[11px] text-gray-500 mb-3">{confirmMessage}</p>}
          <div className="space-y-2">
            {services.map((service) => {
              const suggestion = suggestForPort(service.port);
              const detection = detectionModuleForPort(service.port);
              const confirmed = Boolean(service.info);
              const key = serviceKey(service);
              const suggestionState = suggestions[key];
              return (
                <div key={key} className="rounded border border-border bg-bg-secondary/50 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs text-accent">{service.host}:{service.port}</span>
                        <span className="rounded border border-border px-2 py-0.5 text-[10px] text-gray-300">{suggestion.label}</span>
                        {confirmed ? (
                          <span className="rounded border border-emerald-500/30 bg-emerald-500/5 px-2 py-0.5 text-[10px] text-emerald-400">
                            Confirmed
                          </span>
                        ) : (
                          <span className="text-[10px] text-gray-600">
                            {detection ? "(not yet confirmed)" : "(guessed from port number, not confirmed)"}
                          </span>
                        )}
                      </div>
                      {confirmed ? (
                        <p className="text-[11px] text-gray-300 mt-1 leading-relaxed font-mono break-all">{service.info}</p>
                      ) : (
                        <p className="text-[11px] text-gray-500 mt-1 leading-relaxed">{suggestion.note}</p>
                      )}
                    </div>
                    <div className="shrink-0 flex items-center gap-2">
                      {confirmed && (
                        <button
                          onClick={() => void loadSuggestions(service)}
                          disabled={suggestionState?.status === "loading"}
                          className="rounded border border-accent/30 bg-accent/5 px-3 py-1.5 text-[11px] text-accent hover:bg-accent/10 disabled:cursor-wait disabled:opacity-50"
                        >
                          {suggestionState?.status === "loading" ? "Searching…" : "Find matching exploits"}
                        </button>
                      )}
                      <button
                        onClick={() => onInvestigate("auxiliary", suggestion.keyword, { host: service.host, port: service.port, serviceInfo: service.info, source: "scan" })}
                        className="rounded border border-accent/30 bg-accent/5 px-3 py-1.5 text-[11px] text-accent hover:bg-accent/10"
                      >
                        Investigate in Modules
                      </button>
                    </div>
                  </div>

                  {suggestionState && suggestionState.status !== "idle" && (
                    <div className="mt-3 border-t border-border/60 pt-3">
                      {suggestionState.status === "error" && (
                        <p className="text-[11px] text-danger">Couldn't look up matching modules: {suggestionState.error}</p>
                      )}
                      {suggestionState.status === "done" && suggestionState.candidates.length === 0 && (
                        <p className="text-[11px] text-gray-500">
                          {suggestionState.note ?? `No module names matched this service.`}
                        </p>
                      )}
                      {suggestionState.status === "done" && suggestionState.candidates.length > 0 && (
                        <>
                          <p className="text-[10px] text-gray-500 mb-2 leading-relaxed">
                            Module names matched against <span className="font-mono text-gray-400">{suggestionState.query}</span>, ranked by
                            Metasploit's own reliability Rank. This is a NAME match, not a confirmed vulnerability - use
                            "Verify" to actually run the module's own <span className="font-mono text-gray-400">check</span> against
                            this target before trusting it.
                          </p>
                          <div className="space-y-1.5">
                            {suggestionState.candidates.map((candidate) => {
                              const vKey = candidateKey(service, candidate);
                              const verifyState = verifications[vKey];
                              const badge = verdictBadge(verifyState);
                              return (
                                <div key={vKey} className="rounded border border-border/60 bg-bg-primary/40 p-2.5">
                                  <div className="flex flex-wrap items-start justify-between gap-2">
                                    <div className="min-w-0">
                                      <div className="flex items-center gap-1.5 flex-wrap">
                                        <span className="font-mono text-[11px] text-gray-200 break-all">{candidate.fullname}</span>
                                        <span className={`rounded border px-1.5 py-0.5 text-[9px] uppercase ${rankBadgeStyle(candidate.rank_weight)}`}>
                                          {candidate.rank_label}
                                        </span>
                                        {candidate.disclosure_date && (
                                          <span className="text-[9px] text-gray-600">{candidate.disclosure_date}</span>
                                        )}
                                        {badge && (
                                          <span className={`rounded border px-1.5 py-0.5 text-[9px] uppercase ${badge.style}`}>
                                            {badge.label}
                                          </span>
                                        )}
                                      </div>
                                      {candidate.description_snippet && (
                                        <p className="text-[11px] text-gray-500 mt-1 leading-relaxed">{candidate.description_snippet}</p>
                                      )}
                                      {verifyState?.status === "done" && verifyState.rawOutput && (
                                        <pre className="mt-1.5 max-h-24 overflow-y-auto whitespace-pre-wrap break-words rounded bg-bg-secondary/60 p-1.5 text-[10px] text-gray-400 font-mono">
                                          {verifyState.rawOutput}
                                        </pre>
                                      )}
                                      {verifyState?.status === "error" && (
                                        <p className="text-[10px] text-danger mt-1">{verifyState.error}</p>
                                      )}
                                    </div>
                                    <div className="shrink-0 flex items-center gap-1.5">
                                      <button
                                        onClick={() => void verifyCandidate(service, candidate)}
                                        disabled={verifyState?.status === "running"}
                                        className="rounded border border-border px-2 py-1 text-[10px] text-gray-300 hover:border-accent hover:text-accent disabled:cursor-wait disabled:opacity-50"
                                      >
                                        {verifyState?.status === "running" ? "Checking…" : "Verify"}
                                      </button>
                                      <button
                                        onClick={() => onInvestigate(candidate.type, candidate.name, { host: service.host, port: service.port, serviceInfo: service.info, source: "scan" })}
                                        className="rounded border border-border px-2 py-1 text-[10px] text-gray-300 hover:border-accent hover:text-accent"
                                      >
                                        Open
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </>
                      )}
                    </div>
                  )}
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
