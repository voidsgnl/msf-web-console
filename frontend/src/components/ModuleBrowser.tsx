import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../lib/api";

type ModuleRef = { type: string; name: string };
type SessionSummary = { id: string; session: Record<string, any> };
type ExecutionProgress = {
  phase: "submitting" | "running" | "completed" | "timeout" | "error";
  message: string;
  jobId?: string;
  sessions: SessionSummary[];
};
type ModuleTab = "overview" | "options" | "targets" | "payloads" | "references" | "advanced" | "raw";

const POLL_INTERVAL_MS = 2000;
const EXECUTION_TIMEOUT_MS = 90000;
const CORE_INFO_KEYS = new Set([
  "name", "fullname", "description", "rank", "platform", "arch", "privileged",
  "license", "disclosure_date", "author", "authors", "references", "targets",
  "default_target", "payload", "payloads", "compatible_payloads", "actions",
  "notes", "options", "default_options",
]);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function textValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) return value.map(textValue).filter(Boolean).join(", ");
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function prettyValue(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function listEntries(value: unknown): [string, unknown][] {
  if (Array.isArray(value)) return value.map((entry, index) => [String(index), entry]);
  if (value && typeof value === "object") return Object.entries(value as Record<string, unknown>);
  if (value === null || value === undefined || value === "") return [];
  return [["0", value]];
}

function targetNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

function MetaCard({ label, value }: { label: string; value: unknown }) {
  const text = textValue(value);
  if (!text) return null;
  return (
    <div className="rounded border border-border bg-bg-secondary px-3 py-2 min-w-0">
      <div className="text-[10px] uppercase tracking-widest text-gray-500">{label}</div>
      <div className="mt-1 text-xs text-gray-200 break-words">{text}</div>
    </div>
  );
}

function DetailSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border bg-bg-secondary/60 overflow-hidden">
      <div className="px-4 py-3 border-b border-border">
        <h3 className="text-xs uppercase tracking-widest text-gray-300 font-semibold">{title}</h3>
        {description && <p className="text-xs text-gray-500 mt-1">{description}</p>}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function ModuleBrowser({ onViewSessions }: { onViewSessions: () => void }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState<string>("exploit");
  const [results, setResults] = useState<ModuleRef[]>([]);
  const [selected, setSelected] = useState<ModuleRef | null>(null);
  const [info, setInfo] = useState<{ info: any; options: any } | null>(null);
  const [compatiblePayloads, setCompatiblePayloads] = useState<string[]>([]);
  const [payloadError, setPayloadError] = useState<string | null>(null);
  const [payloadsLoading, setPayloadsLoading] = useState(false);
  const [payloadSearch, setPayloadSearch] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedPayload, setSelectedPayload] = useState("");
  const [payloadOptions, setPayloadOptions] = useState<Record<string, any>>({});
  const [payloadOptionValues, setPayloadOptionValues] = useState<Record<string, string>>({});
  const [payloadOptionsLoading, setPayloadOptionsLoading] = useState(false);
  const [payloadOptionsError, setPayloadOptionsError] = useState<string | null>(null);
  const [optionValues, setOptionValues] = useState<Record<string, string>>({});
  const [optionSearch, setOptionSearch] = useState("");
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState<ModuleTab>("overview");
  const [executing, setExecuting] = useState(false);
  const [progress, setProgress] = useState<ExecutionProgress | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const mounted = useRef(true);
  const selectionGeneration = useRef(0);
  const payloadRequestGeneration = useRef(0);

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

  const loadCompatiblePayloads = async (moduleName: string, target?: number) => {
    const requestGeneration = ++payloadRequestGeneration.current;
    setPayloadsLoading(true);
    setPayloadError(null);
    try {
      const result = await api.modules.compatiblePayloads(moduleName, target);
      if (mounted.current && requestGeneration === payloadRequestGeneration.current) {
        setCompatiblePayloads(result.payloads ?? []);
      }
    } catch (e: unknown) {
      if (mounted.current && requestGeneration === payloadRequestGeneration.current) {
        setPayloadError(e instanceof Error ? e.message : String(e));
        setCompatiblePayloads([]);
      }
    } finally {
      if (mounted.current && requestGeneration === payloadRequestGeneration.current) {
        setPayloadsLoading(false);
      }
    }
  };

  const select = async (mod: ModuleRef) => {
    const generation = ++selectionGeneration.current;
    payloadRequestGeneration.current += 1;
    setSelected(mod);
    setActiveTab("overview");
    setProgress(null);
    setInfo(null);
    setCompatiblePayloads([]);
    setPayloadError(null);
    setPayloadsLoading(mod.type === "exploit");
    setPayloadSearch("");
    setSelectedTargetId("");
    setSelectedPayload("");
    setPayloadOptions({});
    setPayloadOptionValues({});
    setPayloadOptionsLoading(false);
    setPayloadOptionsError(null);
    setInfoError(null);
    setValidationErrors({});
    setOptionSearch("");
    setShowAdvancedOptions(false);
    setLoadingInfo(true);
    try {
      const data = await api.modules.info(mod.type, mod.name);
      if (!mounted.current || generation !== selectionGeneration.current) return;
      setInfo(data);
      const defaults: Record<string, string> = {};
      for (const [key, opt] of Object.entries<any>(data.options || {})) {
        if (opt.default !== undefined && opt.default !== null) defaults[key] = String(opt.default);
      }

      const defaultTarget = targetNumber(data.info?.default_target);
      if (defaultTarget !== undefined) {
        defaults.TARGET = String(defaultTarget);
        setSelectedTargetId(String(defaultTarget));
      }
      setOptionValues(defaults);

      if (mod.type === "exploit") {
        void loadCompatiblePayloads(mod.name, defaultTarget);
      } else {
        setPayloadsLoading(false);
      }
    } catch (e: unknown) {
      console.error("module info failed:", e);
      if (mounted.current && generation === selectionGeneration.current) {
        setInfoError(e instanceof Error ? e.message : String(e));
        setPayloadsLoading(false);
      }
    } finally {
      if (mounted.current && generation === selectionGeneration.current) setLoadingInfo(false);
    }
  };

  const chooseTarget = async (targetId: string) => {
    if (!selected || selected.type !== "exploit" || !targetId || targetId === selectedTargetId) return;

    setSelectedTargetId(targetId);
    setOptionValues((current) => {
      const next = { ...current, TARGET: targetId };
      delete next.PAYLOAD;
      return next;
    });
    setSelectedPayload("");
    setPayloadOptions({});
    setPayloadOptionValues({});
    setPayloadOptionsError(null);
    setValidationErrors({});
    setPayloadError(null);
    setCompatiblePayloads([]);
    void loadCompatiblePayloads(selected.name, targetNumber(targetId));
  };

  const choosePayload = async (payloadName: string) => {
    if (!selected || selected.type !== "exploit" || !payloadName || payloadOptionsLoading) return;
    const generation = selectionGeneration.current;

    setPayloadOptionsLoading(true);
    setPayloadOptionsError(null);
    try {
      const payloadInfo = await api.modules.info("payload", payloadName);
      if (!mounted.current || generation !== selectionGeneration.current) return;

      const defaults: Record<string, string> = {};
      for (const [key, option] of Object.entries<any>(payloadInfo.options || {})) {
        if (option.default !== undefined && option.default !== null) {
          defaults[key] = String(option.default);
        }
      }
      setSelectedPayload(payloadName);
      setPayloadOptions(payloadInfo.options || {});
      setPayloadOptionValues(defaults);
      setOptionValues((current) => ({ ...current, PAYLOAD: payloadName }));
      setActiveTab("options");
    } catch (e: unknown) {
      if (mounted.current && generation === selectionGeneration.current) {
        setPayloadOptionsError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (mounted.current && generation === selectionGeneration.current) setPayloadOptionsLoading(false);
    }
  };

  const clearPayload = () => {
    setSelectedPayload("");
    setPayloadOptions({});
    setPayloadOptionValues({});
    setPayloadOptionsError(null);
    setValidationErrors((current) => Object.fromEntries(
      Object.entries(current).filter(([key]) => !key.startsWith("PAYLOAD."))
    ));
    setOptionValues((current) => {
      const next = { ...current };
      delete next.PAYLOAD;
      return next;
    });
  };

  const execute = async () => {
    if (!selected || executing || payloadOptionsLoading) return;
    const options = info?.options ?? {};
    const missing: Record<string, string> = {};
    for (const [key, option] of Object.entries<any>(options)) {
      if (option.required && !String(optionValues[key] ?? "").trim()) {
        missing[key] = "This option is required.";
      }
    }
    if (selectedPayload) {
      for (const [key, option] of Object.entries<any>(payloadOptions)) {
        if (option.required && !String(payloadOptionValues[key] ?? "").trim()) {
          missing[`PAYLOAD.${key}`] = "This payload option is required.";
        }
      }
    }
    if (Object.keys(missing).length) {
      setValidationErrors(missing);
      setActiveTab("options");
      setProgress({
        phase: "error",
        message: `Complete the ${Object.keys(missing).length} required option(s) before executing this module.`,
        sessions: [],
      });
      return;
    }

    setValidationErrors({});
    setExecuting(true);
    setProgress({
      phase: "submitting",
      message: "Submitting module to Metasploit…",
      sessions: [],
    });

    try {
      const before = await api.sessions.list();
      const previousSessionIds = new Set(Object.keys(before ?? {}));
      const runOptions: Record<string, unknown> = { ...optionValues };
      if (selectedPayload) {
        runOptions.PAYLOAD = selectedPayload;
        Object.assign(runOptions, payloadOptionValues);
      }
      const result = await api.modules.execute(selected.type, selected.name, runOptions);
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
            message: `${newSessions.length} new session${newSessions.length === 1 ? "" : "s"} detected. Open Sessions to interact with ${newSessions.length === 1 ? "it" : "them"}.`,
            jobId,
            sessions: newSessions,
          });
        }

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

  const moduleInfo: Record<string, any> =
    info?.info && typeof info.info === "object" ? info.info : {};
  const moduleOptions: Record<string, any> =
    info?.options && typeof info.options === "object" ? info.options : {};
  const optionEntries = Object.entries<any>(moduleOptions).filter(([key, option]) => {
    const term = optionSearch.toLowerCase().trim();
    if (term && !key.toLowerCase().includes(term) &&
      !String(option.desc ?? option.description ?? "").toLowerCase().includes(term)) return false;
    return showAdvancedOptions || !(option.advanced || option.evasion);
  });
  const requiredCount = Object.values<any>(moduleOptions).filter((option) => option.required).length;
  const references = listEntries(moduleInfo.references ?? moduleInfo.refs);
  const targets = listEntries(moduleInfo.targets);
  // Lists are target-specific when a numeric target has been selected.
  // Without a target, Metasploit returns module-wide compatibility, which
  // can include many candidates across different target configurations.
  const payloads = selected?.type === "exploit"
    ? listEntries(compatiblePayloads)
    : listEntries(moduleInfo.compatible_payloads ?? moduleInfo.payloads ?? moduleInfo.payload);
  const filteredPayloads = payloads.filter(([, payload]) =>
    textValue(payload).toLowerCase().includes(payloadSearch.toLowerCase().trim())
  );
  const advancedEntries = Object.entries(moduleInfo).filter(([key, value]) =>
    !CORE_INFO_KEYS.has(key) && value !== null && value !== undefined && value !== ""
  );
  const tabs: { id: ModuleTab; label: string; count?: number }[] = [
    { id: "overview", label: "Overview" },
    { id: "options", label: "Options", count: Object.keys(moduleOptions).length },
    { id: "targets", label: "Targets", count: targets.length },
    { id: "payloads", label: selected?.type === "exploit" ? "Compatible payloads" : "Payloads", count: payloads.length },
    { id: "references", label: "References", count: references.length },
    { id: "advanced", label: "Advanced", count: advancedEntries.length },
    { id: "raw", label: "Raw metadata" },
  ];

  const renderOption = (
    key: string,
    option: any,
    scope: "module" | "payload" = "module"
  ) => {
    const value = scope === "payload"
      ? payloadOptionValues[key] ?? ""
      : optionValues[key] ?? "";
    const validationKey = scope === "payload" ? `PAYLOAD.${key}` : key;
    const description = option.desc ?? option.description;
    const choices = option.enums ?? option.enum ?? option.values;
    const isBoolean = /^(bool|boolean)$/i.test(String(option.type ?? ""));
    const isNumber = /^(int|integer|float|number|port)$/i.test(String(option.type ?? ""));
    const isSecret = /(password|passwd|token|secret)$/i.test(key);
    const hasChoices = Array.isArray(choices) && choices.length > 0;
    const updateValue = (nextValue: string) => {
      if (scope === "payload") {
        setPayloadOptionValues((current) => ({ ...current, [key]: nextValue }));
      } else {
        setOptionValues((current) => ({ ...current, [key]: nextValue }));
      }
      setValidationErrors((current) => {
        const next = { ...current };
        delete next[validationKey];
        return next;
      });
    };

    return (
      <div key={`${scope}:${key}`} className="grid grid-cols-1 md:grid-cols-[minmax(130px,180px)_minmax(180px,1fr)] gap-2 md:gap-4 py-3 border-b border-border/60 last:border-b-0">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="font-mono text-xs text-gray-200 break-all">{key}</span>
            {option.required && <span className="text-[10px] text-danger uppercase">Required</span>}
            {(option.advanced || option.evasion) && <span className="text-[10px] text-gray-500 uppercase">Advanced</span>}
          </div>
          <p className="text-[10px] text-gray-500 mt-1">
            {option.type ? String(option.type) : "Option"}
            {option.default !== undefined && option.default !== null ? ` · default: ${String(option.default)}` : ""}
          </p>
        </div>
        <div className="min-w-0 space-y-1.5">
          {isBoolean ? (
            <label className="flex items-center gap-2 text-xs text-gray-300 min-h-8">
              <input
                type="checkbox"
                checked={value.toLowerCase() === "true"}
                onChange={(event) => updateValue(String(event.target.checked))}
                className="accent-accent"
              />
              {value.toLowerCase() === "true" ? "Enabled" : "Disabled"}
            </label>
          ) : hasChoices ? (
            <select
              value={value}
              onChange={(event) => updateValue(event.target.value)}
              className="w-full min-w-0 bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-100"
            >
              <option value="">Choose a value…</option>
              {choices.map((choice: unknown) => (
                <option key={String(choice)} value={String(choice)}>{String(choice)}</option>
              ))}
            </select>
          ) : (
            <input
              type={isSecret ? "password" : isNumber ? "number" : "text"}
              value={value}
              onChange={(event) => updateValue(event.target.value)}
              aria-invalid={Boolean(validationErrors[validationKey])}
              className={`w-full min-w-0 bg-bg-tertiary border rounded px-2.5 py-2 text-xs text-gray-100 font-mono focus:outline-none focus:border-accent ${validationErrors[validationKey] ? "border-danger" : "border-border"}`}
            />
          )}
          {description && <p className="text-[11px] leading-relaxed text-gray-500">{String(description)}</p>}
          {validationErrors[validationKey] && <p className="text-[11px] text-danger">{validationErrors[validationKey]}</p>}
        </div>
      </div>
    );
  };

  return (
    <div className="flex h-full min-w-0">
      <aside className="w-64 md:w-72 shrink-0 border-r border-border flex flex-col bg-bg-secondary">
        <div className="p-3 border-b border-border space-y-2.5">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] uppercase tracking-widest text-gray-400 font-semibold">Module explorer</h2>
            <span className="text-[10px] text-gray-600">{results.length} results</span>
          </div>
          <select
            value={type}
            onChange={(event) => {
              const nextType = event.target.value;
              setType(nextType);
              if (query) void search(query, nextType);
            }}
            className="w-full bg-bg-tertiary border border-border rounded px-2 py-2 text-xs text-gray-200"
            aria-label="Module type"
          >
            {["exploit", "auxiliary", "post", "payload", "encoder", "nop"].map((moduleType) => (
              <option key={moduleType} value={moduleType}>{moduleType}</option>
            ))}
          </select>
          <input
            value={query}
            onChange={(event) => void search(event.target.value)}
            placeholder="Search module names…"
            aria-label="Search modules"
            className="w-full bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600 focus:outline-none focus:border-accent"
          />
          <p className="text-[10px] text-gray-600">Enter at least two characters to search.</p>
        </div>
        <div className="flex-1 overflow-y-auto">
          {results.map((module) => (
            <button
              key={`${module.type}/${module.name}`}
              onClick={() => void select(module)}
              className={`w-full text-left px-3 py-2.5 border-b border-border/50 transition-colors ${
                selected?.type === module.type && selected?.name === module.name
                  ? "bg-bg-tertiary border-l-2 border-l-accent"
                  : "border-l-2 border-l-transparent hover:bg-bg-tertiary/70"
              }`}
            >
              <span className="block text-[10px] text-gray-600 uppercase mb-1">{module.type}</span>
              <span className={`block text-xs font-mono break-all leading-relaxed ${
                selected?.type === module.type && selected?.name === module.name ? "text-accent" : "text-gray-300"
              }`}>{module.name}</span>
            </button>
          ))}
          {searchError && <div className="p-3 text-xs text-danger">Search failed: {searchError}</div>}
          {!searchError && query.length >= 2 && results.length === 0 && (
            <div className="p-4 text-xs text-gray-600">No modules matched this search.</div>
          )}
          {query.length < 2 && !results.length && (
            <div className="p-4 text-xs text-gray-600">Search by module name to explore available modules.</div>
          )}
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col bg-bg-primary">
        {!selected && (
          <div className="flex-1 flex items-center justify-center p-8">
            <div className="max-w-md text-center">
              <div className="mx-auto mb-4 w-12 h-12 rounded-xl border border-border bg-bg-secondary flex items-center justify-center text-xl text-accent">▦</div>
              <h2 className="text-base text-gray-200 font-medium">Module inspector</h2>
              <p className="text-sm text-gray-500 mt-2 leading-relaxed">
                Select a module to explore its purpose, configuration, targets, references and technical metadata.
              </p>
            </div>
          </div>
        )}

        {selected && (
          <>
            <div className="px-4 md:px-6 py-4 border-b border-border bg-bg-secondary/70">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className="rounded border border-accent/30 bg-accent/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-accent">{selected.type}</span>
                    {moduleInfo.rank !== undefined && moduleInfo.rank !== null && (
                      <span className="rounded border border-border px-2 py-0.5 text-[10px] text-gray-400">Rank {textValue(moduleInfo.rank)}</span>
                    )}
                    {moduleInfo.privileged !== undefined && (
                      <span className="rounded border border-border px-2 py-0.5 text-[10px] text-gray-400">{moduleInfo.privileged ? "Privileged" : "Unprivileged"}</span>
                    )}
                  </div>
                  <h1 className="text-sm md:text-base font-mono text-gray-100 break-all">{textValue(moduleInfo.fullname) || `${selected.type}/${selected.name}`}</h1>
                  <p className="text-xs text-gray-500 mt-1">Metasploit module inspector</p>
                </div>
                <button
                  onClick={() => void execute()}
                  disabled={executing || loadingInfo || payloadOptionsLoading || !info}
                  className="shrink-0 rounded bg-accent hover:bg-emerald-400 text-gray-950 font-semibold text-xs px-4 py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {executing ? "Executing…" : "Execute module"}
                </button>
              </div>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 mt-4">
                <MetaCard label="Platform" value={moduleInfo.platform} />
                <MetaCard label="Architecture" value={moduleInfo.arch} />
                <MetaCard label="License" value={moduleInfo.license} />
                <MetaCard label="Disclosure date" value={moduleInfo.disclosure_date} />
              </div>
            </div>

            {loadingInfo && (
              <div className="flex-1 p-6 text-sm text-gray-500">Loading module metadata…</div>
            )}
            {infoError && (
              <div className="m-5 rounded border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
                <p className="font-medium">Failed to load module details</p>
                <p className="text-xs mt-1">{infoError}</p>
                <button onClick={() => void select(selected)} className="text-xs underline mt-3">Try again</button>
              </div>
            )}

            {info && !loadingInfo && !infoError && (
              <>
                <div className="flex gap-1 overflow-x-auto px-3 md:px-5 border-b border-border bg-bg-secondary/30">
                  {tabs.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`shrink-0 px-3 py-3 border-b-2 text-xs transition-colors ${
                        activeTab === tab.id
                          ? "border-accent text-accent"
                          : "border-transparent text-gray-500 hover:text-gray-200"
                      }`}
                    >
                      {tab.label}
                      {tab.count !== undefined && (
                        <span className={`ml-1.5 text-[10px] ${activeTab === tab.id ? "text-accent" : "text-gray-600"}`}>{tab.count}</span>
                      )}
                    </button>
                  ))}
                </div>

                <div className="flex-1 min-h-0 overflow-y-auto p-4 md:p-6">
                  <div className="max-w-5xl space-y-4">
                    {activeTab === "overview" && (
                      <>
                        <DetailSection title="Description">
                          {moduleInfo.description ? (
                            <p className="text-sm text-gray-300 leading-7 whitespace-pre-wrap break-words">{String(moduleInfo.description)}</p>
                          ) : (
                            <p className="text-xs text-gray-600">No description was provided by this module.</p>
                          )}
                        </DetailSection>

                        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                          <DetailSection title="Authors">
                            {listEntries(moduleInfo.author ?? moduleInfo.authors).length ? (
                              <div className="flex flex-wrap gap-2">
                                {listEntries(moduleInfo.author ?? moduleInfo.authors).map(([key, author]) => (
                                  <span key={key} className="rounded border border-border bg-bg-tertiary px-2.5 py-1.5 text-xs text-gray-300 break-words">{textValue(author)}</span>
                                ))}
                              </div>
                            ) : <p className="text-xs text-gray-600">No author metadata available.</p>}
                          </DetailSection>
                          <DetailSection title="Module properties">
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <MetaCard label="Full name" value={moduleInfo.fullname} />
                              <MetaCard label="Default target" value={moduleInfo.default_target} />
                              <MetaCard label="Actions" value={moduleInfo.actions} />
                              <MetaCard label="File" value={moduleInfo.file ?? moduleInfo.path} />
                            </div>
                            {moduleInfo.notes && (
                              <div className="mt-3">
                                <p className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5">Notes</p>
                                <pre className="text-xs text-gray-400 whitespace-pre-wrap break-words font-mono">{prettyValue(moduleInfo.notes)}</pre>
                              </div>
                            )}
                          </DetailSection>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <button onClick={() => setActiveTab("options")} className="rounded border border-border px-3 py-2 text-xs text-gray-300 hover:bg-bg-tertiary">
                            Configure options <span className="text-gray-500">({Object.keys(moduleOptions).length})</span>
                          </button>
                          {targets.length > 0 && <button onClick={() => setActiveTab("targets")} className="rounded border border-border px-3 py-2 text-xs text-gray-300 hover:bg-bg-tertiary">Inspect targets</button>}
                          {references.length > 0 && <button onClick={() => setActiveTab("references")} className="rounded border border-border px-3 py-2 text-xs text-gray-300 hover:bg-bg-tertiary">View references</button>}
                        </div>
                      </>
                    )}

                    {activeTab === "options" && (
                      <>
                        <DetailSection
                          title="Module configuration"
                          description={`${Object.keys(moduleOptions).length} module options · ${requiredCount} required. Values here are sent to Metasploit when you execute the module.`}
                        >
                          <div className="flex flex-col sm:flex-row gap-2 sm:items-center justify-between mb-2">
                            <input
                              value={optionSearch}
                              onChange={(event) => setOptionSearch(event.target.value)}
                              placeholder="Filter options by name or description…"
                              className="w-full sm:max-w-sm bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-200 placeholder:text-gray-600 focus:outline-none focus:border-accent"
                            />
                            <button
                              onClick={() => setShowAdvancedOptions((show) => !show)}
                              className="shrink-0 text-xs text-accent hover:underline text-left"
                            >
                              {showAdvancedOptions ? "Hide advanced options" : "Show advanced options"}
                            </button>
                          </div>
                          {optionEntries.length ? (
                            optionEntries.map(([key, option]) => renderOption(key, option, "module"))
                          ) : (
                            <p className="py-5 text-xs text-gray-600">No options match this filter.</p>
                          )}
                          {Object.keys(validationErrors).length > 0 && (
                            <p className="mt-3 text-xs text-danger">Complete all required options before executing.</p>
                          )}
                        </DetailSection>

                        {selected.type === "exploit" && (
                          <DetailSection
                            title="Payload configuration"
                            description="Choose a compatible payload if you need to override Metasploit's default. The selected payload and its options are passed with the exploit when you execute it."
                          >
                            {selectedPayload ? (
                              <div className="rounded border border-accent/30 bg-accent/5 p-3">
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <p className="text-[10px] uppercase tracking-widest text-accent">Selected payload</p>
                                    <p className="mt-1 font-mono text-xs text-gray-100 break-all">{selectedPayload}</p>
                                    <p className="text-[10px] text-gray-500 mt-1">Sent as PAYLOAD with the configured datastore options.</p>
                                  </div>
                                  <button type="button" onClick={clearPayload} className="shrink-0 text-xs text-gray-400 hover:text-danger underline">Clear</button>
                                </div>
                              </div>
                            ) : (
                              <div className="rounded border border-border bg-bg-secondary p-3">
                                <p className="text-xs text-gray-300">No explicit payload selected.</p>
                                <p className="text-xs text-gray-500 mt-1">Metasploit may choose a default payload if the exploit supports one. Use the Compatible payloads tab to select a specific payload.</p>
                                {selectedTargetId && <p className="text-[10px] text-gray-500 mt-2">Target ID: {selectedTargetId}</p>}
                              </div>
                            )}

                            {payloadOptionsLoading && <p className="text-xs text-gray-500">Loading payload options…</p>}
                            {payloadOptionsError && (
                              <div className="rounded border border-danger/30 bg-danger/5 p-3 text-xs text-danger">
                                Could not load payload options: {payloadOptionsError}
                              </div>
                            )}
                            {selectedPayload && !payloadOptionsLoading && Object.keys(payloadOptions).length > 0 && (
                              <div className="mt-3">
                                <h4 className="text-[10px] uppercase tracking-widest text-gray-500 mb-1">Payload-specific options</h4>
                                {Object.entries<any>(payloadOptions).map(([key, option]) => renderOption(key, option, "payload"))}
                              </div>
                            )}
                            {selectedPayload && !payloadOptionsLoading && Object.keys(payloadOptions).length === 0 && !payloadOptionsError && (
                              <p className="text-xs text-gray-500 mt-2">This payload exposes no additional datastore options.</p>
                            )}
                            <button type="button" onClick={() => setActiveTab("payloads")} className="mt-3 text-xs text-accent hover:underline">
                              Browse compatible payloads ({payloads.length})
                            </button>
                          </DetailSection>
                        )}
                      </>
                    )}

                    {activeTab === "targets" && (
                      <DetailSection
                        title="Supported targets"
                        description={selected.type === "exploit"
                          ? "Selecting a target narrows the compatible payload list to that target where Metasploit supports it."
                          : "Target names and identifiers returned by Metasploit."}
                      >
                        {targets.length ? (
                          <div className="space-y-2">
                            {targets.map(([id, target]) => {
                              const canSelectTarget = selected.type === "exploit" && targetNumber(id) !== undefined;
                              const active = selectedTargetId === id;
                              return (
                                <div key={id} className={`rounded border px-3 py-3 flex items-start gap-3 ${active ? "border-accent/40 bg-accent/5" : "border-border bg-bg-secondary"}`}>
                                  <span className="shrink-0 font-mono text-xs text-accent rounded bg-accent/10 px-2 py-1">{id}</span>
                                  <div className="min-w-0 flex-1">
                                    <p className="text-xs text-gray-200 break-words">{textValue(target)}</p>
                                    {String(moduleInfo.default_target) === id && <span className="inline-block mt-1 text-[10px] text-gray-500">Metasploit default target</span>}
                                    {active && <span className="inline-block mt-1 ml-2 text-[10px] text-accent">Selected</span>}
                                  </div>
                                  {canSelectTarget && (
                                    <button
                                      type="button"
                                      onClick={() => void chooseTarget(id)}
                                      disabled={active || payloadsLoading}
                                      className="shrink-0 rounded border border-border px-2.5 py-1.5 text-[10px] text-gray-300 hover:border-accent hover:text-accent disabled:opacity-50"
                                    >
                                      {active ? "Selected" : "Use target"}
                                    </button>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        ) : <p className="text-xs text-gray-600">This module did not expose a targets list.</p>}
                      </DetailSection>
                    )}

                    {activeTab === "payloads" && (
                      <DetailSection
                        title={selected.type === "exploit" ? "Compatible payloads" : "Payload information"}
                        description={selected.type === "exploit"
                          ? "Pick a payload to configure the exploit. Use target selection first when the module has multiple targets; compatibility can differ by target."
                          : "Payload compatibility lookup is for exploit modules. Payload modules themselves are browsed through the module explorer."}
                      >
                        {selected.type !== "exploit" ? (
                          <p className="text-xs text-gray-500">
                            This is a {selected.type} module. Payload selection is part of exploit configuration, not this module type.
                          </p>
                        ) : (
                          <>
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                              <div className="text-xs text-gray-300">
                                {payloadsLoading ? "Checking compatibility…" : `${payloads.length} compatible payloads`}
                                {selectedTargetId ? ` · target ${selectedTargetId}` : targets.length ? " · all module targets" : ""}
                              </div>
                              {selectedPayload && (
                                <span className="text-[10px] rounded border border-accent/30 bg-accent/10 px-2 py-1 text-accent">
                                  Selected: {selectedPayload}
                                </span>
                              )}
                            </div>

                            {targets.length > 0 && !selectedTargetId && (
                              <div className="rounded border border-warning/30 bg-warning/5 px-3 py-2.5 mb-3">
                                <p className="text-xs text-warning">Showing payloads compatible across the module, not one specific target.</p>
                                <p className="text-xs text-gray-500 mt-1">Open Targets and choose a target to narrow this list.</p>
                              </div>
                            )}

                            <input
                              value={payloadSearch}
                              onChange={(event) => setPayloadSearch(event.target.value)}
                              placeholder="Filter payloads by name (e.g. meterpreter, reverse_tcp)…"
                              aria-label="Filter compatible payloads"
                              className="w-full bg-bg-tertiary border border-border rounded px-2.5 py-2 text-xs text-gray-200 font-mono placeholder:text-gray-600 focus:outline-none focus:border-accent mb-3"
                            />

                            {payloadError ? (
                              <div className="rounded border border-warning/30 bg-warning/5 p-3">
                                <p className="text-xs text-warning">Could not retrieve compatible payloads from Metasploit.</p>
                                <p className="text-xs text-gray-400 mt-1 break-words">{payloadError}</p>
                                <button
                                  type="button"
                                  onClick={() => {
                                    if (selected) {
                                      void loadCompatiblePayloads(
                                        selected.name,
                                        targetNumber(selectedTargetId || moduleInfo.default_target)
                                      );
                                    }
                                  }}
                                  className="mt-2 text-xs text-accent hover:underline"
                                >
                                  Retry compatibility lookup
                                </button>
                              </div>
                            ) : payloadsLoading ? (
                              <p className="py-5 text-xs text-gray-500">Loading compatible payloads from Metasploit…</p>
                            ) : filteredPayloads.length ? (
                              <>
                                <p className="text-[10px] text-gray-500 mb-2">Showing {filteredPayloads.length} of {payloads.length}. Selecting a payload opens its options in the Options tab; it will not execute until you press Execute module.</p>
                                <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
                                  {filteredPayloads.map(([id, payload]) => {
                                    const name = textValue(payload);
                                    const active = selectedPayload === name;
                                    return (
                                      <div key={`${id}:${name}`} className={`flex items-center justify-between gap-3 rounded border px-3 py-2.5 ${active ? "border-accent/40 bg-accent/5" : "border-border bg-bg-secondary"}`}>
                                        <span className={`min-w-0 font-mono text-xs break-all ${active ? "text-accent" : "text-gray-300"}`}>{name}</span>
                                        <button
                                          type="button"
                                          onClick={() => void choosePayload(name)}
                                          disabled={active || payloadOptionsLoading}
                                          className="shrink-0 rounded border border-border px-2.5 py-1.5 text-[10px] text-gray-300 hover:border-accent hover:text-accent disabled:opacity-50"
                                        >
                                          {active ? "Selected" : "Use payload"}
                                        </button>
                                      </div>
                                    );
                                  })}
                                </div>
                              </>
                            ) : (
                              <p className="text-xs text-gray-500 py-4">
                                {payloads.length === 0
                                  ? "Metasploit returned no compatible payloads for this target. This is a genuine empty result, not a lookup error."
                                  : "No payloads match this filter. Try a broader search."}
                              </p>
                            )}
                          </>
                        )}
                      </DetailSection>
                    )}

                    {activeTab === "references" && (
                      <DetailSection title="References" description="Identifiers and reference links returned by the module metadata.">
                        {references.length ? (
                          <div className="space-y-2">
                            {references.map(([id, reference]) => {
                              const values = Array.isArray(reference) ? reference : [reference];
                              const label = values.map(textValue).filter(Boolean).join(" · ") || id;
                              const url = values.find((value) => typeof value === "string" && /^https?:\/\//i.test(value));
                              return (
                                <div key={id} className="rounded border border-border bg-bg-secondary px-3 py-2.5 flex items-start justify-between gap-3">
                                  <p className="text-xs text-gray-300 break-words">{label}</p>
                                  {typeof url === "string" && (
                                    <a href={url} target="_blank" rel="noreferrer" className="shrink-0 text-xs text-accent hover:underline">Open ↗</a>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        ) : <p className="text-xs text-gray-600">No references were returned for this module.</p>}
                      </DetailSection>
                    )}

                    {activeTab === "advanced" && (
                      <DetailSection title="Advanced metadata" description="Additional properties returned by Metasploit that do not fit the common overview fields.">
                        {advancedEntries.length ? (
                          <div className="divide-y divide-border/60">
                            {advancedEntries.map(([key, value]) => (
                              <div key={key} className="grid grid-cols-1 md:grid-cols-[180px_minmax(0,1fr)] gap-2 py-3 first:pt-0 last:pb-0">
                                <span className="text-xs text-gray-400 font-mono break-all">{key}</span>
                                <pre className="text-xs text-gray-300 whitespace-pre-wrap break-words font-mono">{prettyValue(value)}</pre>
                              </div>
                            ))}
                          </div>
                        ) : <p className="text-xs text-gray-600">No additional metadata was returned.</p>}
                      </DetailSection>
                    )}

                    {activeTab === "raw" && (
                      <DetailSection title="Raw metadata" description="Unmodified JSON from the module information and options RPC responses. Useful for debugging and inspecting fields that the UI does not yet interpret.">
                        <pre className="text-[11px] leading-5 text-gray-300 whitespace-pre-wrap break-words font-mono">{prettyValue({
                          info: info.info,
                          options: info.options,
                          target: selectedTargetId || null,
                          selected_payload: selectedPayload || null,
                          compatible_payloads: compatiblePayloads,
                          payloads_error: payloadError,
                          payload_options: payloadOptions,
                          payload_option_values: payloadOptionValues,
                        })}</pre>
                      </DetailSection>
                    )}
                  </div>
                </div>
              </>
            )}

            {progress && (
              <div className="border-t border-border bg-bg-secondary px-4 md:px-6 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className={`text-[10px] font-semibold uppercase tracking-widest ${statusStyle(progress.phase)}`}>
                      {progress.phase === "submitting" ? "Submitting" :
                        progress.phase === "running" ? "In progress" :
                        progress.phase === "completed" ? "Completed" :
                        progress.phase === "timeout" ? "Needs attention" : "Failed"}
                    </div>
                    <p className="text-xs text-gray-300 mt-1">{progress.message}</p>
                    {progress.jobId && <p className="text-[10px] text-gray-500 mt-1 font-mono">Job ID: {progress.jobId}</p>}
                  </div>
                  {progress.sessions.length > 0 && (
                    <button onClick={onViewSessions} className="shrink-0 rounded bg-accent-dim hover:bg-accent text-black text-xs font-medium px-3 py-2">
                      Open Sessions ({progress.sessions.length})
                    </button>
                  )}
                </div>
                {progress.sessions.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-3">
                    {progress.sessions.map(({ id, session }) => (
                      <button
                        key={id}
                        onClick={onViewSessions}
                        className="text-left rounded border border-accent/30 bg-accent/5 px-2.5 py-2 hover:bg-accent/10"
                        title="Open the Sessions view to interact with this session"
                      >
                        <span className="block text-[10px] text-accent font-mono">Session {id} · {textValue(session.type) || "session"}</span>
                        <span className="block mt-1 text-[10px] text-gray-400">{textValue(session.target_host ?? session.session_host ?? session.info) || "Target details unavailable"}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
