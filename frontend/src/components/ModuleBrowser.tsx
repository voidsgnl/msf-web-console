import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../lib/api";
import { glossaryFor } from "../lib/glossary";
import { ConfirmDialog } from "./ConfirmDialog";

type ModuleRef = { type: string; name: string };
type SessionSummary = { id: string; session: Record<string, any> };
type ExecutionProgress = {
  phase: "submitting" | "running" | "completed" | "timeout" | "unknown" | "error";
  message: string;
  jobId?: string;
  runUuid?: string;
  resultText?: string;
  artifact?: { filename: string; size: number; payloadBase64: string; format: string };
  sessions: SessionSummary[];
};
type ModuleTab = "overview" | "options" | "targets" | "payloads" | "references" | "advanced" | "raw";

const POLL_INTERVAL_MS = 2000;
// How long this panel actively tracks a run before it stops polling and tells
// you to check the Jobs/Sessions views instead. Metasploit itself keeps the
// job running past this point if it's a long scan or a waiting handler - this
// is only about how long the module browser watches it, not a hard deadline.
const EXECUTION_TIMEOUT_MS = 10 * 60 * 1000;
const CORE_INFO_KEYS = new Set([
  "name", "fullname", "description", "rank", "platform", "arch", "privileged",
  "license", "disclosure_date", "author", "authors", "references", "targets",
  "default_target", "payload", "payloads", "compatible_payloads", "actions",
  "notes", "options", "default_options",
]);
// Metasploit's RPC API has no "most used" / popularity metric, so this is a
// hand-picked, clearly-labeled set of well-known modules shown by default
// for each type - not telemetry-derived usage data. It exists purely so the
// Module explorer shows *something* useful before the user types a search
// term; the full catalog is always one search away.
const POPULAR_MODULES: Record<string, string[]> = {
  exploit: [
    "windows/smb/ms17_010_eternalblue",
    "windows/smb/psexec",
    "multi/handler",
    "unix/ftp/vsftpd_234_backdoor",
    "multi/http/apache_struts2_content_type_ognl",
    "windows/smb/ms08_067_netapi",
    "linux/http/apache_mod_cgi_bash_env_exec",
    "multi/http/php_cgi_arg_injection",
    "windows/rdp/cve_2019_0708_bluekeep_rce",
    "multi/misc/java_rmi_server",
  ],
  auxiliary: [
    "scanner/portscan/tcp",
    "scanner/http/http_version",
    "scanner/ssh/ssh_login",
    "scanner/smb/smb_version",
    "scanner/discovery/udp_sweep",
    "scanner/ftp/ftp_version",
    "scanner/mysql/mysql_login",
    "scanner/rdp/rdp_scanner",
  ],
  post: [
    "windows/gather/hashdump",
    "multi/gather/env",
    "windows/gather/credentials/credential_collector",
    "linux/gather/hashdump",
    "multi/recon/local_exploit_suggester",
  ],
  payload: [
    "windows/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_tcp",
    "linux/x64/meterpreter/reverse_tcp",
    "cmd/unix/reverse_bash",
    "python/meterpreter/reverse_tcp",
    "osx/x64/meterpreter/reverse_tcp",
  ],
  encoder: [
    "x86/shikata_ga_nai",
    "x64/xor_dynamic",
    "cmd/powershell_base64",
  ],
  nop: [
    "x86/opty2",
    "x86/single_byte",
  ],
};
// Generic, always-true-for-the-type context ("what is an exploit module,
// generally"), shown next to each module's own description. Deliberately
// NOT a per-module summary - fabricating what a specific exploit does would
// be guessing at a security tool's behavior, which is worse than not
// explaining it. This only explains the category; the module's own
// (official) description below it covers the specifics.
const MODULE_TYPE_EXPLAINERS: Record<string, string> = {
  exploit: "An exploit module tries to actively break into a target by abusing a specific vulnerability. Running one against a real system without authorization can be illegal and can disrupt the target.",
  auxiliary: "An auxiliary module scans, probes, or tests a target without trying to gain access - things like port scanning, version detection, or login testing. Lower risk than an exploit, but still touches the target.",
  post: "A post-exploitation module runs commands on a target you already have a session on, to gather information or expand access. Requires an existing session, selected on the Options tab.",
  payload: "A payload is the code delivered once an exploit succeeds (e.g. a reverse shell). Generating one here produces a standalone file - it doesn't exploit anything on its own.",
  encoder: "An encoder transforms input bytes to avoid characters a target might mangle or filter. It doesn't exploit or contact any target by itself.",
  nop: "A NOP generator produces \"do nothing\" filler bytes (a NOP sled), used to pad payloads so they land reliably. It doesn't exploit or contact any target by itself.",
};
// Metasploit ranks modules by how reliable/safe they are to run (does it
// crash the service, does it need exact tuning to work, etc.). Translating
// that into a visual tone - rather than just printing the word - makes the
// risk legible without already knowing Metasploit's rank scale.
function rankTone(rank: unknown): "good" | "neutral" | "caution" {
  const normalized = String(rank ?? "").toLowerCase();
  if (["excellent", "great"].includes(normalized)) return "good";
  if (["good", "normal"].includes(normalized)) return "neutral";
  if (["average", "low", "manual"].includes(normalized)) return "caution";
  return "neutral";
}
const RANK_TONE_CLASS: Record<string, string> = {
  good: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  neutral: "border-border text-gray-400",
  caution: "border-warning/30 bg-warning/10 text-warning",
};
// Plain-language translations for Metasploit's SideEffects notes (set on
// modules via the 'Notes' => { 'SideEffects' => [...] } metadata). Codes
// not in this list still render, just with their raw name formatted.
const SIDE_EFFECT_LABELS: Record<string, string> = {
  ARTIFACTS_ON_DISK: "Leaves files behind on the target",
  IOC_IN_LOGS: "May leave traces in the target's logs",
  CONFIG_CHANGES: "Changes configuration on the target",
  ACCOUNT_LOCKOUTS: "May lock out an account on the target",
  ACCOUNT_CHANGES: "Changes an account on the target",
  SCREEN_EFFECTS: "May cause visible effects on the target's screen",
  AUDIO_EFFECTS: "May cause audible effects on the target",
  PHYSICAL_EFFECTS: "May cause a physical effect, e.g. a reboot",
  PERMANENT_DENIAL_OF_SERVICE: "Can permanently disable the target service or device",
};
function formatSideEffectCode(code: string): string {
  return SIDE_EFFECT_LABELS[code] ?? code.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}
// SideEffects codes that justify an extra confirmation step before running
// the module, since they can change or damage the target rather than just
// leaving a forensic trace (IOC_IN_LOGS) or a cosmetic effect (SCREEN/AUDIO).
// Matches Phase 3's "Privileged or destructive SideEffects" roadmap item.
const DESTRUCTIVE_SIDE_EFFECT_CODES = new Set([
  "ARTIFACTS_ON_DISK",
  "CONFIG_CHANGES",
  "ACCOUNT_LOCKOUTS",
  "ACCOUNT_CHANGES",
  "PHYSICAL_EFFECTS",
  "PERMANENT_DENIAL_OF_SERVICE",
]);
// A short, prominent lead-in pulled from the module's OWN description (never
// invented) - its first sentence, cleaned of the line-wrapping/indentation
// Metasploit descriptions are typically written with.
function firstSentence(description: unknown): string {
  const text = String(description ?? "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  const match = text.match(/^.{0,220}?[.!?](?=\s|$)/);
  const sentence = match ? match[0] : text.slice(0, 200) + (text.length > 200 ? "…" : "");
  return sentence.trim();
}
// Well-known "you'd type this in msfconsole" datastore options. These are
// surfaced first in the Options list (ahead of less familiar framework
// options) regardless of whether Metasploit's RPC happens to flag them as
// advanced, so the fields people actually expect - RHOSTS/RPORT/LHOST/LPORT
// and friends - aren't buried in a long, unfamiliar list.
const ESSENTIAL_OPTION_KEYS = new Set([
  "RHOSTS", "RHOST", "RPORT", "LHOST", "LPORT",
  "SRVHOST", "SRVPORT", "TARGETURI", "TARGETURL",
  "USERNAME", "PASSWORD", "SMBUSER", "SMBPASS",
  "SSL", "VHOST", "TARGET",
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

function runResultText(value: unknown): string {
  if (value === null || value === undefined || value === "") {
    return "Metasploit marked the run complete but returned no additional result payload.";
  }
  const rendered = prettyValue(value);
  return rendered.length > 12000
    ? rendered.slice(0, 12000) + "\n… output truncated in the UI …"
    : rendered;
}

function formatArtifactSize(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "size unavailable";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB"];
  let size = value / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size < 10 ? 1 : 0)} ${units[index]}`;
}

function downloadGeneratedPayload(artifact: NonNullable<ExecutionProgress["artifact"]>) {
  const binary = window.atob(artifact.payloadBase64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = artifact.filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
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

// Required options first, then the well-known "you'd type this in
// msfconsole" fields, then everything else alphabetically. Purely a display
// order - it never hides anything the advanced toggle wasn't already hiding.
function sortOptionEntries(entries: [string, any][]): [string, any][] {
  const rank = (key: string, option: any) => {
    if (option?.required) return 0;
    if (ESSENTIAL_OPTION_KEYS.has(key.toUpperCase())) return 1;
    return 2;
  };
  return [...entries].sort(([keyA, optionA], [keyB, optionB]) => {
    const diff = rank(keyA, optionA) - rank(keyB, optionB);
    return diff !== 0 ? diff : keyA.localeCompare(keyB);
  });
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

export type TargetContext = { host: string; port?: number; serviceInfo?: string; source: "scan" };
export type ModuleSearchRequest = { type: string; query: string; nonce: number; targetContext?: TargetContext };

export function ModuleBrowser({
  onViewSessions,
  onViewJobs,
  externalSearchRequest,
}: {
  onViewSessions: () => void;
  onViewJobs: () => void;
  externalSearchRequest?: ModuleSearchRequest | null;
}) {
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
  const [selectedPayloadDescription, setSelectedPayloadDescription] = useState("");
  const [payloadOptions, setPayloadOptions] = useState<Record<string, any>>({});
  const [payloadOptionValues, setPayloadOptionValues] = useState<Record<string, string>>({});
  const [payloadOptionsLoading, setPayloadOptionsLoading] = useState(false);
  const [payloadOptionsError, setPayloadOptionsError] = useState<string | null>(null);
  const [payloadAutoSelected, setPayloadAutoSelected] = useState(false);
  const [optionValues, setOptionValues] = useState<Record<string, string>>({});
  const [autoOptionSources, setAutoOptionSources] = useState<Record<string, string>>({});
  const [activeTargetContext, setActiveTargetContext] = useState<TargetContext | null>(null);
  const [optionSearch, setOptionSearch] = useState("");
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState<ModuleTab>("overview");
  const [executing, setExecuting] = useState(false);
  const [confirmExecuteOpen, setConfirmExecuteOpen] = useState(false);
  const [checkState, setCheckState] = useState<{ status: "idle" | "running" | "done" | "error"; verdict?: string; output?: string; error?: string }>({ status: "idle" });
  const [progress, setProgress] = useState<ExecutionProgress | null>(null);
  const [runStartedAt, setRunStartedAt] = useState<number | null>(null);
  const [nowTick, setNowTick] = useState(() => Date.now());
  const [encoderInput, setEncoderInput] = useState("");
  const [encoderInputFormat, setEncoderInputFormat] = useState<"text" | "hex" | "base64">("text");
  const [encoderBadChars, setEncoderBadChars] = useState("");
  const [encoderPlatform, setEncoderPlatform] = useState("");
  const [encoderArch, setEncoderArch] = useState("");
  const [encoderIterations, setEncoderIterations] = useState(1);
  const [nopLength, setNopLength] = useState("256");
  const [nopBadChars, setNopBadChars] = useState("");
  const [nopSaveRegisters, setNopSaveRegisters] = useState("");
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const mounted = useRef(true);
  const selectionGeneration = useRef(0);
  const payloadRequestGeneration = useRef(0);
  const executionGeneration = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Live "running for Xs" display. Only ticks while a run is actually in
  // flight, so it doesn't redraw the whole panel once a result is in.
  useEffect(() => {
    if (!runStartedAt || (progress?.phase !== "submitting" && progress?.phase !== "running")) return;
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [runStartedAt, progress?.phase]);

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

  // Lets another view (the scan wizard's "Investigate in Modules" button)
  // drive this search from outside, without this component needing to know
  // anything about where the request came from. Keyed on `nonce` so the
  // same {type, query} pair fired twice in a row (e.g. clicking the same
  // suggestion again) still re-triggers the search.
  const lastAppliedSearchNonce = useRef<number | null>(null);
  useEffect(() => {
    if (!externalSearchRequest || externalSearchRequest.nonce === lastAppliedSearchNonce.current) return;
    lastAppliedSearchNonce.current = externalSearchRequest.nonce;
    setType(externalSearchRequest.type);
    setActiveTargetContext(externalSearchRequest.targetContext ?? null);
    void search(externalSearchRequest.query, externalSearchRequest.type);
  }, [externalSearchRequest]);

  const loadCompatiblePayloads = async (
    moduleName: string,
    target?: number,
    options: { autoSelect?: boolean } = {}
  ) => {
    const { autoSelect = false } = options;
    const requestGeneration = ++payloadRequestGeneration.current;
    setPayloadsLoading(true);
    setPayloadError(null);
    try {
      const result = await api.modules.compatiblePayloads(moduleName, target);
      if (mounted.current && requestGeneration === payloadRequestGeneration.current) {
        const payloadNames: string[] = result.payloads ?? [];
        setCompatiblePayloads(payloadNames);
        // Mirror msfconsole: `use <exploit>` picks a default payload right
        // away, so LHOST/LPORT show up alongside RHOSTS/RPORT immediately.
        // Here we approximate that by auto-selecting the first compatible
        // payload Metasploit reports, without forcing a tab switch - the
        // user can still pick a different one from the Payloads tab.
        if (autoSelect && payloadNames.length > 0) {
          setPayloadAutoSelected(true);
          void choosePayload(payloadNames[0], { switchTab: false });
        }
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
    executionGeneration.current += 1;
    setExecuting(false);
    payloadRequestGeneration.current += 1;
    setSelected(mod);
    setAutoOptionSources({});
    setActiveTab("overview");
    setProgress(null);
    setRunStartedAt(null);
    setEncoderInput("");
    setEncoderInputFormat("text");
    setEncoderBadChars("");
    setEncoderPlatform("");
    setEncoderArch("");
    setEncoderIterations(1);
    setNopLength("256");
    setNopBadChars("");
    setNopSaveRegisters("");
    setInfo(null);
    setCompatiblePayloads([]);
    setPayloadError(null);
    setPayloadsLoading(mod.type === "exploit");
    setPayloadSearch("");
    setSelectedTargetId("");
    setSelectedPayload("");
    setSelectedPayloadDescription("");
    setPayloadOptions({});
    setPayloadOptionValues({});
    setPayloadOptionsLoading(false);
    setPayloadOptionsError(null);
    setPayloadAutoSelected(false);
    setInfoError(null);
    setValidationErrors({});
    setOptionSearch("");
    setShowAdvancedOptions(false);
    setConfirmExecuteOpen(false);
    setCheckState({ status: "idle" });
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

      // A scan-selected host/service becomes the initial configuration context.
      // Only options declared by this module are populated; the user can edit
      // every value before Check or Execute.
      const autoSources: Record<string, string> = {};
      const declaredOptions = data.options ?? {};
      const context = activeTargetContext;
      if (context?.host) {
        if (declaredOptions.RHOSTS) {
          defaults.RHOSTS = context.host;
          autoSources.RHOSTS = "Scan";
        } else if (declaredOptions.RHOST) {
          defaults.RHOST = context.host;
          autoSources.RHOST = "Scan";
        }
        if (context.port && declaredOptions.RPORT) {
          defaults.RPORT = String(context.port);
          autoSources.RPORT = "Scan";
        }
        if (Object.prototype.hasOwnProperty.call(declaredOptions, "LHOST")) {
          try {
            const network = await api.system.networkContext(context.host);
            if (network.local_ip) {
              defaults.LHOST = network.local_ip;
              autoSources.LHOST = "Network";
            }
          } catch {
            // LHOST remains at the module default if route detection is unavailable.
          }
        }
      }
      if (!mounted.current || generation !== selectionGeneration.current) return;
      setAutoOptionSources(autoSources);
      setOptionValues(defaults);

      if (mod.type === "exploit") {
        void loadCompatiblePayloads(mod.name, defaultTarget, { autoSelect: true });
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
      const next: Record<string, string> = { ...current, TARGET: targetId };
      delete next.PAYLOAD;
      return next;
    });
    setSelectedPayload("");
    setSelectedPayloadDescription("");
    setPayloadOptions({});
    setPayloadOptionValues({});
    setPayloadOptionsError(null);
    setPayloadAutoSelected(false);
    setValidationErrors({});
    setPayloadError(null);
    setCompatiblePayloads([]);
    void loadCompatiblePayloads(selected.name, targetNumber(targetId), { autoSelect: true });
  };

  const choosePayload = async (
    payloadName: string,
    options: { switchTab?: boolean } = {}
  ) => {
    const { switchTab = true } = options;
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
      if (activeTargetContext?.host && Object.prototype.hasOwnProperty.call(payloadInfo.options ?? {}, "LHOST")) {
        try {
          const network = await api.system.networkContext(activeTargetContext.host);
          if (network.local_ip) {
            defaults.LHOST = network.local_ip;
            setAutoOptionSources((current) => ({ ...current, "PAYLOAD.LHOST": "Network" }));
          }
        } catch {
          // Keep the payload's own LHOST default when route detection fails.
        }
      }
      setSelectedPayload(payloadName);
      if (!switchTab) setPayloadAutoSelected(true);
      setSelectedPayloadDescription(String(payloadInfo.info?.description ?? ""));
      setPayloadOptions(payloadInfo.options || {});
      setPayloadOptionValues(defaults);
      setOptionValues((current) => ({ ...current, PAYLOAD: payloadName }));
      if (switchTab) setActiveTab("options");
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
    setSelectedPayloadDescription("");
    setPayloadOptions({});
    setPayloadOptionValues({});
    setPayloadOptionsError(null);
    setPayloadAutoSelected(false);
    setValidationErrors((current) => Object.fromEntries(
      Object.entries(current).filter(([key]) => !key.startsWith("PAYLOAD."))
    ));
    setOptionValues((current) => {
      const next = { ...current };
      delete next.PAYLOAD;
      return next;
    });
  };

  const executeDedicatedArtifact = async () => {
    if (!selected || executing || (selected.type !== "encoder" && selected.type !== "nop")) return;

    if (selected.type === "encoder") {
      if (encoderInput.length === 0) {
        setProgress({ phase: "error", message: "Enter the input bytes to encode first.", sessions: [] });
        return;
      }
      const missing: Record<string, string> = {};
      for (const [key, option] of Object.entries<any>(info?.options ?? {})) {
        if (option.required && !String(optionValues[key] ?? "").trim()) {
          missing[key] = "This option is required.";
        }
      }
      if (Object.keys(missing).length) {
        setValidationErrors(missing);
        setActiveTab("options");
        setProgress({
          phase: "error",
          message: `Complete the ${Object.keys(missing).length} required encoder option(s) in the Options tab.`,
          sessions: [],
        });
        return;
      }
    } else {
      const length = Number(nopLength);
      if (!Number.isSafeInteger(length) || length < 1 || length > 16384) {
        setProgress({
          phase: "error",
          message: "NOP length must be a whole number between 1 and 16,384 bytes.",
          sessions: [],
        });
        return;
      }
    }

    const runGeneration = ++executionGeneration.current;
    const isCurrentRun = () => mounted.current && executionGeneration.current === runGeneration;
    setExecuting(true);
    setRunStartedAt(Date.now());
    setProgress({
      phase: "submitting",
      message: selected.type === "encoder"
        ? "Encoding input with the selected Metasploit encoder…"
        : "Generating a NOP sled with the selected Metasploit module…",
      sessions: [],
    });

    try {
      const result = selected.type === "encoder"
        ? await api.modules.encode({
            name: selected.name,
            data: encoderInput,
            data_format: encoderInputFormat,
            badchars: encoderBadChars,
            platform: encoderPlatform,
            arch: encoderArch,
            iterations: encoderIterations,
            module_options: optionValues,
          })
        : await api.modules.generateNops({
            name: selected.name,
            length: Number(nopLength),
            badchars: nopBadChars,
            save_registers: nopSaveRegisters.split(",").map((value) => value.trim()).filter(Boolean),
          });

      if (!isCurrentRun()) return;
      const payloadBase64 = typeof result?.payload_base64 === "string" ? result.payload_base64 : "";
      if (!payloadBase64 || !result.filename) {
        throw new Error("Metasploit did not return a generated binary artifact.");
      }
      const rawSize = Number(result.size);
      const artifact = {
        filename: String(result.filename || `generated-${selected.type}.bin`),
        size: Number.isFinite(rawSize) && rawSize >= 0 ? rawSize : 0,
        payloadBase64,
        format: String(result.format || "raw"),
      };
      setProgress({
        phase: "completed",
        message: `${selected.type === "encoder" ? "Encoding" : "NOP generation"} completed successfully (${formatArtifactSize(artifact.size)}).`,
        resultText: `Module: ${selected.type}/${selected.name}\nFile: ${artifact.filename}\nFormat: raw binary\nSize: ${artifact.size} bytes`,
        artifact,
        sessions: [],
      });
    } catch (e: unknown) {
      if (isCurrentRun()) {
        setProgress({
          phase: "error",
          message: e instanceof Error ? e.message : String(e),
          sessions: [],
        });
      }
    } finally {
      if (isCurrentRun()) setExecuting(false);
    }
  };

  const checkSelectedModule = async () => {
    if (!selected || !["exploit", "auxiliary"].includes(selected.type) || checkState.status === "running") return;
    const required = Object.entries<any>(info?.options ?? {}).filter(
      ([key, option]) => option.required && !String(optionValues[key] ?? "").trim()
    );
    if (required.length) {
      setValidationErrors(Object.fromEntries(required.map(([key]) => [key, "This option is required for the check."])));
      setActiveTab("options");
      setCheckState({ status: "error", error: "Complete the required target and module options before running Check." });
      return;
    }
    setCheckState({ status: "running" });
    try {
      const result = await api.modules.checkModule(selected.type, selected.name, optionValues);
      setCheckState({ status: "done", verdict: result.verdict, output: result.raw_output });
    } catch (error: unknown) {
      setCheckState({ status: "error", error: error instanceof Error ? error.message : String(error) });
    }
  };

  const execute = async () => {
    if (!selected || executing || payloadOptionsLoading) return;
    if (selected.type === "encoder" || selected.type === "nop") {
      await executeDedicatedArtifact();
      return;
    }
    const executableTypes = new Set(["exploit", "auxiliary", "post", "payload"]);
    if (!executableTypes.has(selected.type)) return;

    const runGeneration = ++executionGeneration.current;
    const isCurrentRun = () => mounted.current && executionGeneration.current === runGeneration;
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
    setRunStartedAt(Date.now());
    setProgress({
      phase: "submitting",
      message: "Submitting module to Metasploit…",
      sessions: [],
    });

    try {
      // Session inventory helps identify new sessions, but a temporary
      // failure to list sessions must not prevent a module from executing.
      let previousSessionIds = new Set<string>();
      try {
        const before = await api.sessions.list();
        previousSessionIds = new Set(Object.keys(before ?? {}).map(String));
      } catch {
        previousSessionIds = new Set<string>();
      }
      if (!isCurrentRun()) return;

      const runOptions: Record<string, unknown> = { ...optionValues };
      if (selectedPayload) {
        runOptions.PAYLOAD = selectedPayload;
        Object.assign(runOptions, payloadOptionValues);
      }
      const result = await api.modules.execute(selected.type, selected.name, runOptions);
      if (!isCurrentRun()) return;

      // Payload generation is synchronous and returns the artifact itself,
      // rather than a background job.
      if (selected.type === "payload") {
        const payloadBase64 = typeof result?.payload_base64 === "string" ? result.payload_base64 : "";
        if (result?.kind !== "payload" || !payloadBase64) {
          throw new Error("Metasploit did not return a generated payload artifact.");
        }
        const rawSize = Number(result.size);
        const artifact = {
          filename: String(result.filename || "generated-payload.bin"),
          size: Number.isFinite(rawSize) && rawSize >= 0 ? rawSize : 0,
          payloadBase64,
          format: String(result.format || "raw"),
        };
        setProgress({
          phase: "completed",
          message: `Payload generated successfully (${formatArtifactSize(artifact.size)}).`,
          resultText: `File: ${artifact.filename}\nFormat: ${artifact.format}\nSize: ${artifact.size} bytes`,
          artifact,
          sessions: [],
        });
        return;
      }

      const rawJobId = result?.job_id ?? result?.jobId;
      const jobId = rawJobId === undefined || rawJobId === null ? undefined : String(rawJobId);
      const rawUuid = result?.uuid ?? result?.run_uuid;
      const runUuid = typeof rawUuid === "string" && /^[A-Za-z0-9]{12,64}$/.test(rawUuid)
        ? rawUuid
        : undefined;

      setProgress({
        phase: "running",
        message: runUuid
          ? "Module accepted. Tracking Metasploit run status and results…"
          : jobId
            ? "Module accepted. Waiting for the background job to finish or open a session…"
            : "Module submitted. Watching for new sessions…",
        jobId,
        runUuid,
        sessions: [],
      });

      const startedAt = Date.now();
      let jobObserved = false;
      let latestSessions: SessionSummary[] = [];
      let resultLookupFailures = 0;
      let lastResultLookupError = "";

      while (isCurrentRun() && Date.now() - startedAt < EXECUTION_TIMEOUT_MS) {
        await sleep(POLL_INTERVAL_MS);
        if (!isCurrentRun()) return;

        const [jobsResult, sessionsResult, statsResult] = await Promise.allSettled([
          api.jobs.list(),
          api.sessions.list(),
          api.modules.runningStats(),
        ]);
        const jobs = jobsResult.status === "fulfilled" ? jobsResult.value ?? {} : {};
        const sessions = sessionsResult.status === "fulfilled" ? sessionsResult.value ?? {} : {};
        const activeJobIds = Object.keys(jobs).map(String);
        if (jobId && activeJobIds.includes(jobId)) jobObserved = true;

        latestSessions = Object.entries(sessions)
          .filter(([id]) => !previousSessionIds.has(String(id)))
          .map(([id, session]) => ({ id: String(id), session: session as Record<string, any> }));

        const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
        const asIds = (value: unknown) => Array.isArray(value) ? value.map(String) : [];
        const waitingIds = asIds(stats?.waiting);
        const runningIds = asIds(stats?.running);
        const resultIds = asIds(stats?.results);
        const runIsWaiting = Boolean(runUuid && waitingIds.includes(runUuid));
        const runIsActive = Boolean(runUuid && runningIds.includes(runUuid));
        const runHasResult = Boolean(runUuid && resultIds.includes(runUuid));

        if (runUuid && runHasResult) {
          try {
            const outcome = await api.modules.results(runUuid);
            if (!isCurrentRun()) return;
            resultLookupFailures = 0;
            lastResultLookupError = "";
            const outcomeStatus = String(outcome.status ?? "").toLowerCase();
            if (["completed", "complete", "success"].includes(outcomeStatus)) {
              setProgress({
                phase: "completed",
                message: latestSessions.length
                  ? "Module run completed and new session(s) were detected."
                  : "Metasploit reports that the module run completed.",
                jobId,
                runUuid,
                resultText: runResultText(outcome.result),
                sessions: latestSessions,
              });
              return;
            }
            if (["errored", "error", "failed"].includes(outcomeStatus)) {
              setProgress({
                phase: "error",
                message: String(outcome.error || "Metasploit reports that the module run failed."),
                jobId,
                runUuid,
                resultText: runResultText(outcome.result ?? outcome.error),
                sessions: latestSessions,
              });
              return;
            }
          } catch (e: unknown) {
            // The UUID is already listed in "results", so a repeated result
            // lookup failure is actionable. Retry briefly for transient RPC
            // errors, then surface the actual backend detail instead of letting
            // the UI time out with a misleading generic warning.
            resultLookupFailures += 1;
            lastResultLookupError = e instanceof Error ? e.message : String(e);
            if (resultLookupFailures >= 3) {
              setProgress({
                phase: "unknown",
                message: `Metasploit lists this run as having a result, but it could not be retrieved after ${resultLookupFailures} attempts: ${lastResultLookupError}. This may be an RPC compatibility or result-retention issue; the run is not being reported as failed.`,
                jobId,
                runUuid,
                sessions: latestSessions,
              });
              return;
            }
          }
        }

        if (runUuid && (runIsWaiting || runIsActive)) {
          setProgress({
            phase: "running",
            message: runIsWaiting
              ? "Module run is queued in Metasploit…"
              : "Module run is still executing in Metasploit…",
            jobId,
            runUuid,
            sessions: latestSessions,
          });
        } else if (latestSessions.length > 0) {
          setProgress({
            phase: "running",
            message: `${latestSessions.length} new session${latestSessions.length === 1 ? "" : "s"} detected. The module result is still being checked.`,
            jobId,
            runUuid,
            sessions: latestSessions,
          });
        }

        if (jobId && jobObserved && !activeJobIds.includes(jobId) && !runIsWaiting && !runIsActive && !runHasResult) {
          setProgress({
            phase: "unknown",
            message: latestSessions.length
              ? "The background job is no longer listed and new session(s) were detected. The session is confirmed, but the final module outcome is unavailable."
              : "The background job is no longer listed, but no final result was retrieved. The job may have completed, failed, or been removed; check the Metasploit console or Jobs history.",
            jobId,
            runUuid,
            sessions: latestSessions,
          });
          return;
        }

        if (!jobId && !runUuid && latestSessions.length > 0) {
          setProgress({
            phase: "completed",
            message: "A new session was detected. The Framework did not return a job or run UUID for result tracking.",
            sessions: latestSessions,
          });
          return;
        }
      }

      if (isCurrentRun()) {
        const minutes = Math.round(EXECUTION_TIMEOUT_MS / 60000);
        setProgress((current) => current ? {
          ...current,
          phase: "timeout",
          message: current.sessions.length
            ? "Tracking stopped after the time limit. New session(s) are available below - open Sessions to use them; the module may still be active."
            : `Tracking stopped after ${minutes} minutes. This does not stop or cancel the Metasploit module: it may still be running, or it may have finished without a retrievable result. Check Jobs and the Metasploit console for its current state.`,
        } : null);
      }
    } catch (e: unknown) {
      if (isCurrentRun()) {
        setProgress({
          phase: "error",
          message: e instanceof Error ? e.message : String(e),
          sessions: [],
        });
      }
    } finally {
      if (isCurrentRun()) setExecuting(false);
    }
  };

  const statusStyle = (phase: ExecutionProgress["phase"]) => {
    if (phase === "completed") return "text-emerald-400";
    if (phase === "error") return "text-danger";
    if (phase === "timeout" || phase === "unknown") return "text-warning";
    return "text-accent";
  };

  function formatElapsed(ms: number): string {
    const totalSeconds = Math.max(0, Math.floor(ms / 1000));
    if (totalSeconds < 60) return `${totalSeconds}s`;
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes < 60) return `${minutes}m ${seconds}s`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  }

  // Translates the raw completed/error outcome into a plain-English verdict,
  // so "Completed" + a wall of returned data doesn't leave someone who
  // doesn't already know Metasploit guessing whether anything actually
  // happened. Only covers the two terminal states with a clear meaning;
  // "running"/"submitting"/"timeout" already have their own wording above.
  function interpretOutcome(current: ExecutionProgress, moduleType: string): string | null {
    if (current.phase === "completed") {
      if (current.sessions.length > 0) {
        return "Success — this opened a new session, meaning you now have remote access to the target. Open Sessions to use it.";
      }
      if (current.artifact) {
        return "Done — a file was generated below. Nothing was sent to a target by this step.";
      }
      if (moduleType === "exploit") {
        return "The exploit finished without opening a session. That usually means the target wasn't vulnerable, was unreachable, or the payload couldn't connect back (double-check LHOST/LPORT) — see the result below for details.";
      }
      if (moduleType === "auxiliary") {
        return "The scan/check finished. This module type doesn't open sessions by itself — see the result below for what it found.";
      }
      return "The module finished running. See the result below for what it did.";
    }
    if (current.phase === "unknown") {
      return "Outcome unverified — the available Metasploit RPC data was not enough to confirm success or failure. Check Jobs, Sessions, and the Metasploit console before drawing a conclusion.";
    }
    if (current.phase === "error") {
      return "Metasploit reported an execution or submission error. See the message below for the specific reason.";
    }
    return null;
  }

  const moduleInfo: Record<string, any> =
    info?.info && typeof info.info === "object" ? info.info : {};
  const moduleOptions: Record<string, any> =
    info?.options && typeof info.options === "object" ? info.options : {};
  // SideEffects codes this module declares (computed once here so both the
  // header badges and the pre-execution confirmation dialog agree on the
  // same list), split into destructive ones that warrant a confirmation
  // step versus purely informational/cosmetic ones that don't.
  const sideEffectCodes = listEntries(moduleInfo.notes?.SideEffects).map(([, value]) => String(value));
  const destructiveSideEffects = sideEffectCodes.filter((code) => DESTRUCTIVE_SIDE_EFFECT_CODES.has(code));
  const isPrivilegedModule = Boolean(moduleInfo.privileged);
  const needsExecuteConfirmation =
    Boolean(selected) &&
    selected?.type !== "encoder" &&
    selected?.type !== "nop" &&
    (isPrivilegedModule || destructiveSideEffects.length > 0);
  const confirmExecuteDescription = selected
    ? [
        `This ${selected.type} module is flagged as higher-impact:`,
        "",
        ...(isPrivilegedModule ? ["• Can grant elevated (SYSTEM/root-level) access if it succeeds."] : []),
        ...destructiveSideEffects.map((code) => `• ${formatSideEffectCode(code)}.`),
        "",
        "Only run this against a target you are authorized to test.",
      ].join("\n")
    : "";
  const optionEntries = sortOptionEntries(
    Object.entries<any>(moduleOptions).filter(([key, option]) => {
      const term = optionSearch.toLowerCase().trim();
      if (term && !key.toLowerCase().includes(term) &&
        !String(option.desc ?? option.description ?? "").toLowerCase().includes(term)) return false;
      return showAdvancedOptions || !(option.advanced || option.evasion);
    })
  );
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
    const plainLanguageHint = glossaryFor(key);
    const choices = option.enums ?? option.enum ?? option.values;
    const isBoolean = /^(bool|boolean)$/i.test(String(option.type ?? ""));
    const isNumber = /^(int|integer|float|number|port)$/i.test(String(option.type ?? ""));
    const isSecret = /(password|passwd|token|secret)$/i.test(key);
    const hasChoices = Array.isArray(choices) && choices.length > 0;
    const isEssential = !option.required && ESSENTIAL_OPTION_KEYS.has(key.toUpperCase());
    const updateValue = (nextValue: string) => {
      if (scope === "payload") {
        setPayloadOptionValues((current) => ({ ...current, [key]: nextValue }));
      } else {
        setOptionValues((current) => ({ ...current, [key]: nextValue }));
      }
      const sourceKey = scope === "payload" ? `PAYLOAD.${key}` : key;
      setAutoOptionSources((current) => {
        if (!(sourceKey in current)) return current;
        const next = { ...current };
        delete next[sourceKey];
        return next;
      });
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
            {autoOptionSources[scope === "payload" ? `PAYLOAD.${key}` : key] && (
              <span className="text-[10px] text-emerald-400 uppercase">Auto · {autoOptionSources[scope === "payload" ? `PAYLOAD.${key}` : key]}</span>
            )}
            {isEssential && <span className="text-[10px] text-accent uppercase">Common</span>}
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
          {plainLanguageHint && (
            <p className="text-[11px] leading-relaxed text-gray-300 bg-accent/5 border border-accent/20 rounded px-2 py-1.5">
              {plainLanguageHint}
            </p>
          )}
          {description && <p className="text-[11px] leading-relaxed text-gray-500">{String(description)}</p>}
          {validationErrors[validationKey] && <p className="text-[11px] text-danger">{validationErrors[validationKey]}</p>}
        </div>
      </div>
    );
  };

  const popularRefs: ModuleRef[] = (POPULAR_MODULES[type] ?? []).map((name) => ({ type, name }));
  const showingPopular = query.trim().length < 2;
  const visibleModules = showingPopular ? popularRefs : results;

  return (
    <>
    <div className="flex h-full min-w-0">
      <aside className="w-64 md:w-72 shrink-0 border-r border-border flex flex-col bg-bg-secondary">
        <div className="p-3 border-b border-border space-y-2.5">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] uppercase tracking-widest text-gray-400 font-semibold">Module explorer</h2>
            <span className="text-[10px] text-gray-600">{visibleModules.length} {showingPopular ? "shown" : "results"}</span>
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
          <p className="text-[10px] text-gray-600">
            {showingPopular ? "Showing a few well-known modules. Type to search the full catalog." : "Enter at least two characters to search."}
          </p>
        </div>
        <div className="flex-1 overflow-y-auto">
          {showingPopular && visibleModules.length > 0 && (
            <div className="px-3 pt-3 pb-1 text-[10px] uppercase tracking-widest text-gray-600">
              Popular {type} modules
            </div>
          )}
          {visibleModules.map((module) => (
            <button
              key={`${module.type}/${module.name}`}
              data-context-kind="module"
              data-context-label={`${module.type}/${module.name}`}
              data-context-value={`${module.type}/${module.name}`}
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
          {!showingPopular && !searchError && results.length === 0 && (
            <div className="p-4 text-xs text-gray-600">No modules matched this search.</div>
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
                      <span
                        title="Metasploit's own reliability rating - lower ranks (Average/Low/Manual) may need exact tuning or be more likely to crash the target service."
                        className={`rounded border px-2 py-0.5 text-[10px] ${RANK_TONE_CLASS[rankTone(moduleInfo.rank)]}`}
                      >
                        Rank {textValue(moduleInfo.rank)}
                      </span>
                    )}
                    {moduleInfo.privileged !== undefined && moduleInfo.privileged && (
                      <span
                        title="This module can grant elevated (SYSTEM/root-level) access if it succeeds."
                        className="rounded border border-warning/30 bg-warning/10 px-2 py-0.5 text-[10px] text-warning"
                      >
                        ⚠ Privileged
                      </span>
                    )}
                  </div>
                  <h1 className="text-sm md:text-base font-mono text-gray-100 break-all">{textValue(moduleInfo.fullname) || `${selected.type}/${selected.name}`}</h1>
                  <p className="text-xs text-gray-500 mt-1">Metasploit module inspector</p>
                  {activeTargetContext && <p className="mt-1 text-[11px] text-emerald-400">Scan context · {activeTargetContext.host}{activeTargetContext.port ? `:${activeTargetContext.port}` : ""} · values are prefilled for review</p>}
                  {sideEffectCodes.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {sideEffectCodes.map((code) => (
                        <span
                          key={code}
                          className={`rounded border px-2 py-0.5 text-[10px] ${
                            DESTRUCTIVE_SIDE_EFFECT_CODES.has(code)
                              ? "border-danger/30 bg-danger/5 text-danger"
                              : "border-warning/20 bg-warning/5 text-warning/90"
                          }`}
                          title={code}
                        >
                          {formatSideEffectCode(code)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {(selected.type === "exploit" || selected.type === "auxiliary") && (
                  <button
                    type="button"
                    onClick={() => void checkSelectedModule()}
                    disabled={executing || loadingInfo || checkState.status === "running" || !info}
                    className="shrink-0 rounded border border-accent/40 bg-accent/5 px-3 py-2.5 text-xs font-medium text-accent hover:bg-accent/10 disabled:opacity-50"
                    title="Run Metasploit's non-exploit check action when this module supports it. This still sends a probe to the configured target."
                  >
                    {checkState.status === "running" ? "Checking…" : "Check first"}
                  </button>
                )}
                <button
                  onClick={() => {
                    if (needsExecuteConfirmation) {
                      setConfirmExecuteOpen(true);
                    } else {
                      void execute();
                    }
                  }}
                  disabled={executing || loadingInfo || payloadOptionsLoading || !info}
                  title={selected.type === "encoder"
                    ? "Encode input data with this Metasploit encoder."
                    : selected.type === "nop"
                      ? "Generate a NOP sled with this Metasploit module."
                      : undefined}
                  className="shrink-0 rounded bg-accent hover:bg-emerald-400 text-gray-950 font-semibold text-xs px-4 py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {executing
                    ? selected.type === "encoder" ? "Encoding…" : selected.type === "nop" ? "Generating…" : "Executing…"
                    : selected.type === "payload" ? "Generate payload"
                      : selected.type === "encoder" ? "Encode input"
                        : selected.type === "nop" ? "Generate NOP sled" : "Execute module"}
                </button>
              </div>
              {(selected.type === "exploit" || selected.type === "auxiliary") && (
                <div className="mt-3 rounded border border-border bg-bg-primary px-3 py-2.5">
                  <p className="text-xs font-medium text-gray-200">Check before running</p>
                  <p className="mt-1 text-[11px] leading-relaxed text-gray-400">
                    Check asks the module whether the configured target appears vulnerable, without attempting the exploit. Not every module supports it, and a check still contacts the target. An inconclusive result is not proof of safety.
                  </p>
                  {checkState.status === "error" && <p role="alert" className="mt-2 text-xs text-danger">{checkState.error}</p>}
                  {checkState.status === "done" && (
                    <div className="mt-2">
                      <p className={`text-xs font-semibold ${checkState.verdict === "vulnerable" ? "text-danger" : checkState.verdict === "not_vulnerable" ? "text-emerald-400" : "text-warning"}`}>
                        {checkState.verdict === "vulnerable" ? "Check: appears vulnerable" : checkState.verdict === "not_vulnerable" ? "Check: not reported vulnerable" : "Check: inconclusive or unsupported"}
                      </p>
                      {checkState.output && <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-words text-[11px] text-gray-500">{checkState.output}</pre>}
                    </div>
                  )}
                </div>
              )}
              {(selected.type === "exploit" || selected.type === "auxiliary" || selected.type === "post") && (
                <div className="mt-3 rounded border border-warning/30 bg-warning/5 px-3 py-2.5">
                  <p className="text-xs font-semibold text-warning">Authorized targets only</p>
                  <p className="mt-1 text-[11px] leading-relaxed text-gray-400">
                    Running this module sends actions or requests to the configured target. Continue only if you own the system or have explicit authorization to assess it. Review the target and options before proceeding.
                  </p>
                </div>
              )}
              {selected.type === "encoder" && (
                <p role="status" className="mt-3 rounded border border-accent/20 bg-accent/5 px-3 py-2 text-xs text-gray-400">
                  Provide input as text, hexadecimal bytes, or Base64. Output is saved as a raw binary artifact; encoder options from the Options tab are included when supported.
                </p>
              )}
              {selected.type === "nop" && (
                <p role="status" className="mt-3 rounded border border-accent/20 bg-accent/5 px-3 py-2 text-xs text-gray-400">
                  Generate an architecture-aware NOP sled with this selected module. Choose a byte length and optional bad characters or registers to preserve.
                </p>
              )}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 mt-4">
                <MetaCard label="Platform" value={moduleInfo.platform} />
                <MetaCard label="Architecture" value={moduleInfo.arch} />
                <MetaCard label="License" value={moduleInfo.license} />
                <MetaCard label="Disclosure date" value={moduleInfo.disclosure_date} />
              </div>
            </div>

            {selected.type === "encoder" && info && !loadingInfo && !infoError && (
              <section className="border-b border-border bg-bg-primary px-4 py-4 md:px-6">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-200">Encoder input</h2>
                    <p className="mt-1 text-[11px] text-gray-500">Enter the bytes to encode. No exploit or target is contacted by this workflow.</p>
                  </div>
                  <span className="rounded border border-border px-2 py-1 font-mono text-[10px] text-gray-500">module.encode · raw</span>
                </div>
                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                  <div className="space-y-1.5">
                    <label htmlFor="encoder-input-data" className="block text-[11px] text-gray-400">Input data</label>
                    <textarea
                      id="encoder-input-data"
                      value={encoderInput}
                      onChange={(event) => setEncoderInput(event.target.value)}
                      rows={5}
                      spellCheck={false}
                      placeholder={encoderInputFormat === "text" ? "Paste input data…" : encoderInputFormat === "hex" ? "e.g. 41424390ff" : "Paste Base64 data…"}
                      className="w-full resize-y rounded border border-border bg-bg-tertiary px-3 py-2 font-mono text-xs text-gray-100 placeholder:text-gray-600 focus:border-accent focus:outline-none"
                    />
                  </div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <label htmlFor="encoder-input-format" className="block text-[11px] text-gray-400">Input format</label>
                      <select
                        id="encoder-input-format"
                        value={encoderInputFormat}
                        onChange={(event) => setEncoderInputFormat(event.target.value as "text" | "hex" | "base64")}
                        className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 text-xs text-gray-100"
                      >
                        <option value="text">Text (UTF-8)</option>
                        <option value="hex">Hexadecimal bytes</option>
                        <option value="base64">Base64</option>
                      </select>
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor="encoder-iterations" className="block text-[11px] text-gray-400">Encoding iterations</label>
                      <input
                        id="encoder-iterations"
                        type="number"
                        min={1}
                        max={5}
                        step={1}
                        value={encoderIterations}
                        onChange={(event) => setEncoderIterations(Number(event.target.value))}
                        className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 text-xs text-gray-100"
                      />
                    </div>
                    <div className="space-y-1.5 sm:col-span-2">
                      <label htmlFor="encoder-badchars" className="block text-[11px] text-gray-400">Bad characters (optional hex bytes)</label>
                      <input
                        id="encoder-badchars"
                        value={encoderBadChars}
                        onChange={(event) => setEncoderBadChars(event.target.value)}
                        placeholder="e.g. 00 0a 0d"
                        className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 font-mono text-xs text-gray-100 placeholder:text-gray-600"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor="encoder-platform" className="block text-[11px] text-gray-400">Platform (optional)</label>
                      <input
                        id="encoder-platform"
                        value={encoderPlatform}
                        onChange={(event) => setEncoderPlatform(event.target.value)}
                        placeholder="e.g. windows"
                        className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 font-mono text-xs text-gray-100 placeholder:text-gray-600"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor="encoder-arch" className="block text-[11px] text-gray-400">Architecture (optional)</label>
                      <input
                        id="encoder-arch"
                        value={encoderArch}
                        onChange={(event) => setEncoderArch(event.target.value)}
                        placeholder="e.g. x86"
                        className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 font-mono text-xs text-gray-100 placeholder:text-gray-600"
                      />
                    </div>
                  </div>
                </div>
                <p className="mt-2 text-[10px] leading-4 text-gray-600">
                  Hex input and bad characters accept spaces, commas, colons, and optional 0x or \x prefixes. Iterations are limited to 1–5.
                </p>
              </section>
            )}

            {selected.type === "nop" && info && !loadingInfo && !infoError && (
              <section className="border-b border-border bg-bg-primary px-4 py-4 md:px-6">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-200">NOP generation</h2>
                    <p className="mt-1 text-[11px] text-gray-500">The selected NOP module determines the architecture-specific instructions.</p>
                  </div>
                  <span className="rounded border border-border px-2 py-1 font-mono text-[10px] text-gray-500">generate · raw</span>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <div className="space-y-1.5">
                    <label htmlFor="nop-length" className="block text-[11px] text-gray-400">Sled length (bytes)</label>
                    <input
                      id="nop-length"
                      type="number"
                      min={1}
                      max={16384}
                      step={1}
                      value={nopLength}
                      onChange={(event) => setNopLength(event.target.value)}
                      className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 font-mono text-xs text-gray-100"
                    />
                    <p className="text-[10px] text-gray-600">1 to 16,384 bytes</p>
                  </div>
                  <div className="space-y-1.5">
                    <label htmlFor="nop-badchars" className="block text-[11px] text-gray-400">Bad characters (optional hex bytes)</label>
                    <input
                      id="nop-badchars"
                      value={nopBadChars}
                      onChange={(event) => setNopBadChars(event.target.value)}
                      placeholder="e.g. 00 0a"
                      className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 font-mono text-xs text-gray-100 placeholder:text-gray-600"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label htmlFor="nop-save-registers" className="block text-[11px] text-gray-400">Registers to preserve (optional)</label>
                    <input
                      id="nop-save-registers"
                      value={nopSaveRegisters}
                      onChange={(event) => setNopSaveRegisters(event.target.value)}
                      placeholder="e.g. esp, ebp"
                      className="w-full rounded border border-border bg-bg-tertiary px-2.5 py-2 font-mono text-xs text-gray-100 placeholder:text-gray-600"
                    />
                    <p className="text-[10px] text-gray-600">Comma-separated register names</p>
                  </div>
                </div>
              </section>
            )}

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
                        {(MODULE_TYPE_EXPLAINERS[selected.type] || firstSentence(moduleInfo.description)) && (
                          <div className="rounded-lg border border-accent/20 bg-accent/5 p-4">
                            <p className="text-[10px] uppercase tracking-widest text-accent mb-2">Quick summary</p>
                            {MODULE_TYPE_EXPLAINERS[selected.type] && (
                              <p className="text-xs text-gray-300 leading-relaxed">{MODULE_TYPE_EXPLAINERS[selected.type]}</p>
                            )}
                            {firstSentence(moduleInfo.description) && (
                              <p className="text-xs text-gray-400 leading-relaxed mt-2">
                                <span className="text-gray-500">This specific module, in Metasploit's own words: </span>
                                {firstSentence(moduleInfo.description)}
                              </p>
                            )}
                          </div>
                        )}
                        <DetailSection title="Full description">
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
                                    <p className="text-[10px] uppercase tracking-widest text-accent">
                                      {payloadAutoSelected ? "Auto-selected payload" : "Selected payload"}
                                    </p>
                                    <p className="mt-1 font-mono text-xs text-gray-100 break-all">{selectedPayload}</p>
                                    {selectedPayloadDescription && <p className="text-xs text-gray-400 mt-2 leading-relaxed whitespace-pre-wrap">{selectedPayloadDescription}</p>}
                                    <p className="text-[10px] text-gray-500 mt-1">
                                      {payloadAutoSelected
                                        ? "Metasploit's first compatible payload was pre-selected, mirroring msfconsole's default behavior. Change it below if you need a different one."
                                        : "Sent as PAYLOAD with the configured datastore options."}
                                    </p>
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
                                {sortOptionEntries(Object.entries<any>(payloadOptions)).map(([key, option]) => renderOption(key, option, "payload"))}
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
                                      disabled={active || payloadsLoading || payloadOptionsLoading}
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
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-semibold uppercase tracking-widest ${statusStyle(progress.phase)}`}>
                        {progress.phase === "submitting" ? "Submitting" :
                          progress.phase === "running" ? "Running" :
                          progress.phase === "completed" ? "Completed" :
                          progress.phase === "timeout" ? "Tracking paused" : progress.phase === "unknown" ? "Outcome unverified" : "Failed"}
                      </span>
                      {(progress.phase === "submitting" || progress.phase === "running") && runStartedAt && (
                        <span className="text-[10px] text-gray-500 font-mono">· {formatElapsed(nowTick - runStartedAt)} elapsed</span>
                      )}
                      {(progress.phase === "completed" || progress.phase === "error" || progress.phase === "timeout" || progress.phase === "unknown") && runStartedAt && (
                        <span className="text-[10px] text-gray-500 font-mono">· took {formatElapsed((nowTick - runStartedAt))}</span>
                      )}
                    </div>
                    {selected && interpretOutcome(progress, selected.type) && (
                      <p className={`mt-2 rounded border px-2.5 py-2 text-xs leading-relaxed ${
                        progress.phase === "error"
                          ? "border-danger/30 bg-danger/5 text-gray-200"
                          : progress.phase === "unknown" || progress.phase === "timeout"
                            ? "border-warning/30 bg-warning/5 text-gray-200"
                            : "border-emerald-500/30 bg-emerald-500/5 text-gray-200"
                      }`}>
                        {interpretOutcome(progress, selected.type)}
                      </p>
                    )}
                    <p className="text-xs text-gray-300 mt-1">{progress.message}</p>
                    {progress.jobId && <p className="text-[10px] text-gray-500 mt-1 font-mono">Job ID: {progress.jobId}</p>}
                    {progress.runUuid && <p className="text-[10px] text-gray-500 mt-1 font-mono">Run UUID: {progress.runUuid}</p>}
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-2">
                    {progress.artifact && (
                      <button
                        onClick={() => downloadGeneratedPayload(progress.artifact!)}
                        className="rounded bg-accent-dim hover:bg-accent px-3 py-2 text-xs font-medium text-black"
                      >
                        Download {progress.artifact.filename}
                      </button>
                    )}
                    {progress.sessions.length > 0 && (
                      <button onClick={onViewSessions} className="rounded bg-accent-dim hover:bg-accent px-3 py-2 text-xs font-medium text-black">
                        Open Sessions ({progress.sessions.length})
                      </button>
                    )}
                    {(progress.phase === "running" || progress.phase === "timeout") && progress.jobId && (
                      <button onClick={onViewJobs} className="rounded border border-border px-3 py-2 text-xs text-gray-300 hover:bg-bg-tertiary">
                        Watch in Jobs
                      </button>
                    )}
                  </div>
                </div>
                {progress.resultText && (
                  <div className="mt-3 rounded border border-border bg-bg-primary p-3">
                    <div className="mb-2 text-[10px] uppercase tracking-widest text-gray-500">Run result</div>
                    <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words text-xs text-gray-300">{progress.resultText}</pre>
                  </div>
                )}
                {progress.sessions.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {progress.sessions.map(({ id, session }) => (
                      <button
                        key={id}
                        onClick={onViewSessions}
                        className="rounded border border-accent/30 bg-accent/5 px-2.5 py-2 text-left hover:bg-accent/10"
                        title="Open the Sessions view to interact with this session"
                      >
                        <span className="block font-mono text-[10px] text-accent">Session {id} · {textValue(session.type) || "session"}</span>
                        <span className="mt-1 block text-[10px] text-gray-400">{textValue(session.target_host ?? session.session_host ?? session.info) || "Target details unavailable"}</span>
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
    <ConfirmDialog
      open={confirmExecuteOpen}
      title="Confirm execution"
      description={confirmExecuteDescription}
      confirmLabel="Execute anyway"
      onConfirm={async () => {
        setConfirmExecuteOpen(false);
        await execute();
      }}
      onCancel={() => setConfirmExecuteOpen(false)}
    />
    </>
  );
}
