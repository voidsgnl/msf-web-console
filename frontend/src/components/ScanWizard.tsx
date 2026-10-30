import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { SuggestedModule } from "../lib/api";
import { suggestForPort } from "../lib/portSuggestions";
import { detectionModuleForPort } from "../lib/versionDetection";
import type { TargetContext } from "./ModuleBrowser";

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

function validateCustomPorts(raw: string): { value: string; error: string | null } {
  const input = raw.trim();
  if (!input) return { value: "", error: "Enter at least one port or range." };

  const tokens = input.split(",");
  const normalized: string[] = [];
  for (const rawToken of tokens) {
    const token = rawToken.trim();
    if (!token) return { value: "", error: "Remove empty entries between commas." };
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(token);
    if (!match) return { value: "", error: `"${token}" is invalid. Use ports and ranges such as 80,443,8000-8100.` };
    const start = Number(match[1]);
    const end = match[2] ? Number(match[2]) : start;
    if (start < 1 || end > 65535 || start > end) {
      return { value: "", error: `"${token}" must be within 1-65535, with the range start no greater than its end.` };
    }
    normalized.push(start === end ? String(start) : `${start}-${end}`);
  }
  return { value: normalized.join(","), error: null };
}

function ipv4Number(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    result = (result * 256 + octet) >>> 0;
  }
  return result >>> 0;
}

function targetMatchesHost(rawTarget: string, rawHost: string): boolean {
  const host = rawHost.trim().toLowerCase();
  if (!host) return false;
  const targets = rawTarget.split(/[\s,]+/).map((item) => item.trim().toLowerCase()).filter(Boolean);
  return targets.some((target) => {
    if (target === host) return true;
    const hostNumber = ipv4Number(host);
    if (hostNumber === null) return false;
    const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(target);
    if (cidr) {
      const network = ipv4Number(cidr[1]);
      const prefix = Number(cidr[2]);
      if (network === null || prefix < 0 || prefix > 32) return false;
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      return (hostNumber & mask) === (network & mask);
    }
    const range = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/.exec(target);
    if (range) {
      const start = ipv4Number(range[1]);
      const end = ipv4Number(range[2]);
      return start !== null && end !== null && hostNumber >= start && hostNumber <= end;
    }
    return false;
  });
}
const candidateKey = (service: DiscoveredService, candidate: SuggestedModule) =>
  `${serviceKey(service)}:${candidate.type}/${candidate.name}`;

function extractScannerFindings(value: unknown, target: string): DiscoveredService[] {
  const strings: string[] = [];
  const visit = (item: unknown, depth = 0) => {
    if (depth > 8 || item == null) return;
    if (typeof item === "string") { strings.push(item); return; }
    if (typeof item === "number" || typeof item === "boolean") return;
    if (Array.isArray(item)) { item.forEach((entry) => visit(entry, depth + 1)); return; }
    if (typeof item === "object") {
      for (const [key, entry] of Object.entries(item as Record<string, unknown>)) {
        if (/output|result|message|text|data/i.test(key)) visit(entry, depth + 1);
        else if (typeof entry === "object" && entry !== null) visit(entry, depth + 1);
      }
    }
  };
  visit(value);
  const found = new Map<string, DiscoveredService>();
  for (const text of strings) {
    for (const line of text.split(/\r?\n/)) {
      if (!/\bopen\b/i.test(line)) continue;
      const match = /\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b/.exec(line);
      if (!match) continue;
      const host = match[1];
      const port = Number(match[2]);
      if (port < 1 || port > 65535 || !targetMatchesHost(target, host)) continue;
      found.set(`${host}:${port}`, { host, port, info: line.trim().slice(0, 500) });
    }
  }
  return [...found.values()];
}

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

export function ScanWizard({ onInvestigate }: { onInvestigate: (type: string, query: string, targetContext?: TargetContext) => void }) {
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<"common" | "all" | "custom">("common");
  const [customPorts, setCustomPorts] = useState("3306,5173,5433,8000,8081");
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState("");
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [nowTick, setNowTick] = useState(() => Date.now());
  const [services, setServices] = useState<DiscoveredService[]>([]);
  const servicesRef = useRef<DiscoveredService[]>([]);
  const [confirmPhase, setConfirmPhase] = useState<ConfirmPhase>("idle");
  const [confirmMessage, setConfirmMessage] = useState("");
  const [suggestions, setSuggestions] = useState<Record<string, SuggestionState>>({});
  const [verifications, setVerifications] = useState<Record<string, VerifyState>>({});
  const mounted = useRef(true);
  const runGeneration = useRef(0);
  const scanContext = useRef<{ target: string; baselineKeys: Set<string> | null } | null>(null);

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

    const customPortResult = scanMode === "custom" ? validateCustomPorts(customPorts) : null;
    if (customPortResult?.error) {
      setPhase("error");
      setMessage(customPortResult.error);
      return;
    }

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

    let baselineServiceKeys: Set<string> | null = null;
    try {
      const baseline = await api.db.services();
      const rows = Array.isArray(baseline?.services) ? baseline.services : [];
      baselineServiceKeys = new Set(
        rows
          .filter((row: any) => row && row.host != null && row.port != null)
          .map((row: any) => `${String(row.host).trim().toLowerCase()}:${Number(row.port)}`)
      );
    } catch {
      // Without a baseline we cannot safely distinguish this scan's findings from stale workspace data.
    }

    scanContext.current = { target: trimmedTarget, baselineKeys: baselineServiceKeys };

    try {
      const result = await api.modules.execute("auxiliary", "scanner/portscan/tcp", {
        RHOSTS: trimmedTarget,
        PORTS: scanMode === "all" ? "1-10000" : scanMode === "custom" ? customPortResult!.value : COMMON_PORTS,
      });
      if (!isCurrentRun()) return;

      const rawJobId = result?.job_id ?? result?.jobId;
      const jobId = rawJobId === undefined || rawJobId === null ? undefined : String(rawJobId);
      const rawUuid = result?.uuid ?? result?.run_uuid;
      const runUuid = typeof rawUuid === "string" && /^[A-Za-z0-9]{12,64}$/.test(rawUuid) ? rawUuid : undefined;

      setPhase("running");
      setMessage(
        scanMode === "all"
          ? "Scanning all 10,000 ports - this can take several minutes…"
          : scanMode === "custom"
            ? `Scanning custom ports: ${customPortResult!.value}…`
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
          await finishScan(isCurrentRun, runUuid);
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
    const context = scanContext.current;
    if (!context) return false;
    const { target: scanTarget, baselineKeys } = context;
    try {
      const result = await api.db.services();
      if (!mounted.current) return;
      const rows = Array.isArray(result?.services) ? result.services : [];
      // Metasploit's db.services is workspace-wide. Only include hosts inside this
      // scan's target, and only records absent from the pre-scan snapshot.
      const open: DiscoveredService[] = baselineKeys === null ? [] : rows
        .filter((row: any) => row && row.state === "open" && row.host != null && row.port !== undefined && row.port !== null)
        .map((row: any) => ({
          host: String(row.host).trim(),
          port: Number(row.port),
          info: typeof row.info === "string" ? row.info.trim() : "",
        }))
        .filter((row: DiscoveredService) =>
          Number.isFinite(row.port) &&
          targetMatchesHost(scanTarget, row.host) &&
          !baselineKeys.has(serviceKey(row).toLowerCase())
        );
      open.sort((a, b) => (a.host === b.host ? a.port - b.port : a.host.localeCompare(b.host)));
      servicesRef.current = open;
      setServices(open);
      return baselineKeys !== null;
    } catch {
      // Non-fatal: the scan itself already ran, but results cannot be verified.
      setServices([]);
      return false;
    }
  };

  const finishScan = async (isCurrentRun: () => boolean, runUuid?: string) => {
    let scannerFindings: DiscoveredService[] = [];
    let resultWarning = "";
    if (runUuid) {
      try {
        const outcome = await api.modules.results(runUuid);
        if (!isCurrentRun()) return;
        const status = String(outcome?.status ?? "").toLowerCase();
        if (["errored", "error", "failed"].includes(status)) {
          resultWarning = String(outcome?.error || "Metasploit reported that the scan run failed.");
        } else {
          scannerFindings = extractScannerFindings(outcome?.result, scanContext.current?.target ?? "");
        }
      } catch (error: unknown) {
        resultWarning = error instanceof Error ? error.message : String(error);
      }
    }

    const resultsVerified = await loadServices();
    if (!isCurrentRun()) return;

    // Run-specific scanner output is authoritative for this execution. Merge it
    // with newly recorded DB services; the DB remains a fallback, not the only source.
    const merged = new Map<string, DiscoveredService>();
    for (const service of scannerFindings) merged.set(serviceKey(service).toLowerCase(), service);
    for (const service of servicesRef.current) merged.set(serviceKey(service).toLowerCase(), service);
    const findings = [...merged.values()].sort((a, b) =>
      a.host === b.host ? a.port - b.port : a.host.localeCompare(b.host)
    );
    setServices(findings);
    setPhase("completed");
    setMessage(
      findings.length
        ? `Scan finished. Found ${findings.length} open port${findings.length === 1 ? "" : "s"} for the requested target.${resultWarning && !scannerFindings.length ? " Scanner output was unavailable; showing verified new database records only." : ""}`
        : resultWarning
          ? `Scan finished, but Metasploit's run output could not be retrieved and no new matching database records were found. Result lookup: ${resultWarning}`
          : resultsVerified
            ? "Scan finished. No new open ports were recorded for the requested target."
            : "Scan finished, but results could not be safely verified. No ports are displayed."
    );
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
        <div>
          <label htmlFor="scan-mode" className="block text-[11px] text-gray-400 mb-1.5">Port selection</label>
          <select
            id="scan-mode"
            value={scanMode}
            onChange={(event) => setScanMode(event.target.value as "common" | "all" | "custom")}
            disabled={busy}
            className="w-full bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-100 focus:outline-none focus:border-accent disabled:opacity-50"
          >
            <option value="common">Common ports (recommended)</option>
            <option value="all">All ports 1-10,000</option>
            <option value="custom">Custom ports and ranges</option>
          </select>
        </div>
        {scanMode === "custom" && (
          <div>
            <label htmlFor="scan-custom-ports" className="block text-[11px] text-gray-400 mb-1.5">Custom ports</label>
            <input
              id="scan-custom-ports"
              value={customPorts}
              onChange={(event) => setCustomPorts(event.target.value)}
              placeholder="e.g. 3306,5173,5433,8000-8100,55553"
              disabled={busy}
              aria-describedby="scan-custom-ports-help"
              className="w-full bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-100 font-mono placeholder:text-gray-600 focus:outline-none focus:border-accent disabled:opacity-50"
            />
            <p id="scan-custom-ports-help" className="mt-1 text-[10px] text-gray-500">
              Comma-separated ports or ranges, from 1 to 65535. Example: 3306,5173,5433,8000-8100,55553,33060.
            </p>
          </div>
        )}
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
          No open ports found among the selected ports. Try a custom port list if the service uses an uncommon port,
          or double-check the target is reachable from this machine.
        </div>
      )}
    </div>
  );
}
