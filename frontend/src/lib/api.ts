const BASE = "/api";

export type AssessmentTarget = { id: number; url: string; hostname: string; created_at: string };
export type AssessmentSummary = {
  id: number; name: string; description: string; status: "active" | "completed" | "archived";
  created_at: string; updated_at: string; target_count?: number;
};
export type AssessmentDetail = AssessmentSummary & { targets: AssessmentTarget[] };
export type AssessmentAsset = { id: number; assessment_id: number; asset_type: "url" | "host"; value: string; hostname: string; scope_state: "in_scope" | "out_of_scope"; source_tool: string; first_seen: string; last_seen: string };
export type AssessmentAssetInventory = { assets: AssessmentAsset[]; counts: { total: number; in_scope: number; out_of_scope: number } };
export type AssessmentExecutionDetail = AssessmentExecution & { records: Record<string, unknown>[]; stderr: string };
export type AssessmentExecution = {
  id: number; assessment_id: number; target_id: number; tool_id: string;
  target_url: string; started_at: string; finished_at: string;
  exit_code: number; output_truncated: number | boolean;
};

export type Workspace = {
  id: number;
  name: string;
  created_at?: number;
  updated_at?: number;
};

export type CurrentWorkspace = {
  workspace: string;
  workspace_id: number;
};

export type CveCvss = {
  version?: string | null;
  vector?: string | null;
  base_score?: number | null;
  base_severity?: string | null;
  source_metric?: string | null;
};

export type CveEnrichment = {
  cve_id: string;
  published?: string | null;
  last_modified?: string | null;
  vuln_status?: string | null;
  description?: string | null;
  cvss?: CveCvss | null;
  references?: string[];
};

export type WorkspaceCveEnrichment = {
  total_cves_found: number;
  enriched: Record<string, CveEnrichment | null>;
  errors: Record<string, string>;
  matched_records: Record<string, { host?: string; name?: string }[]>;
  remaining_cves: string[];
};

export type SuggestedModule = {
  type: string;
  name: string;
  fullname: string;
  rank_weight: number;
  rank_label: string;
  disclosure_date?: string | null;
  description_snippet: string;
  match_basis: string;
  // CVE IDs referenced by both this module's metadata and NVD keyword
  // search results for the detected product query. This is corroborating
  // reference evidence, not affected-version validation or a vuln verdict.
  cve_matches: string[];
  cve_version_assessments: {
    cve_id: string;
    status: "affected" | "not_affected" | "indeterminate";
  }[];
};

export type ServiceAssessment = {
  protocol: "http" | null;
  edge_provider: "cloudflare" | null;
  http_status: number | null;
  access_state: "forbidden" | "http_error" | "responding" | "unknown";
  origin_visibility: "edge_proxy" | "not_assessed";
  summary: string;
};

export type ModuleSuggestions = {
  query: string | null;
  candidates: SuggestedModule[];
  note?: string;
  service_assessment?: ServiceAssessment;
};

export type ModuleCheckResult = {
  module: string;
  verdict: "vulnerable" | "not_vulnerable" | "unknown" | "unsupported";
  failure_kind?: "tls_failure" | "connection_failure" | "http_error" | null;
  failure_message?: string | null;
  raw_output: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text();
    if (res.status === 401 && !path.startsWith("/auth/")) {
      window.dispatchEvent(new CustomEvent("msf-auth-required"));
    }
    let message = text;
    try {
      const payload = JSON.parse(text);
      if (typeof payload.detail === "string") message = payload.detail;
    } catch {
      // Keep non-JSON responses readable.
    }
    throw new Error(`${res.status}: ${message}`);
  }
  return res.json();
}

export const api = {
  webRecon: {
    tools: () => request<{ tools: {
      id: string; name: string; category: string; purpose: string;
      installed: boolean; path?: string | null;
    }[]; built_in: { name: string; available: boolean; description: string }[] }>("/web-recon/tools"),
    probe: (assessmentId: number, url: string, authorized: boolean) =>
      request<{
        execution_id: number; target: string; status_code: number; reason?: string; final_url: string;
        redirect_location?: string | null; title?: string | null;
        headers: Record<string, string>; technologies: string[];
        content_type?: string | null; body_truncated: boolean;
        bytes_inspected: number; assessment: string;
      }>("/web-recon/probe", {
        method: "POST",
        body: JSON.stringify({ assessment_id: assessmentId, url, authorized }),
      }),
    runTool: (assessmentId: number, toolId: "httpx" | "whatweb" | "subfinder" | "katana", url: string, authorized: boolean) =>
      request<{
        execution_id: number; assessment_id: number; tool_id: string; tool: string; target: string; exit_code: number;
        timed_out: boolean; output_truncated: boolean;
        records: { url?: string; target?: string; status_code?: number; http_status?: number;
          title?: string | null; webserver?: string; content_type?: string;
          technologies?: string[]; host?: string; sources?: string[]; method?: string; source?: string;
          tag?: string; attribute?: string; raw?: string | null }[];
        stderr: string; assessment: string;
      }>("/web-recon/run", {
        method: "POST",
        body: JSON.stringify({ assessment_id: assessmentId, tool_id: toolId, url, authorized }),
      }),
  },
  assessments: {
    list: () => request<{ assessments: AssessmentSummary[] }>("/assessments"),
    create: (name: string) => request<AssessmentSummary>("/assessments", {
      method: "POST", body: JSON.stringify({ name }),
    }),
    get: (id: number) => request<AssessmentDetail>(`/assessments/${id}`),
    addTarget: (id: number, url: string, authorized: boolean) =>
      request<AssessmentTarget>(`/assessments/${id}/targets`, {
        method: "POST", body: JSON.stringify({ url, authorized }),
      }),
    assets: (id: number) => request<AssessmentAssetInventory>(`/assessments/${id}/assets`),
    executions: (id: number) =>
      request<{ executions: AssessmentExecution[] }>(`/assessments/${id}/executions`),
    execution: (id: number, executionId: number) =>
      request<AssessmentExecutionDetail>(`/assessments/${id}/executions/${executionId}`),
  },
  auth: {
    session: () => request<{ configured: boolean; authenticated: boolean; username?: string | null }>("/auth/session"),
    login: (username: string, password: string) =>
      request<{ authenticated: boolean; username: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }),
    logout: () => request<{ authenticated: boolean }>("/auth/logout", { method: "POST" }),
  },

  status: () => request<{ connected: boolean; version?: unknown; error?: string }>("/system/status"),
  system: {
    networkContext: (target: string) => request<{ target: string; resolved_target?: string | null; local_ip?: string | null; method?: string; error?: string | null }>(`/system/network-context?target=${encodeURIComponent(target)}`),
  },

  modules: {
    list: (type: string) => request<{ type: string; modules: string[] }>(`/modules?type=${type}`),
    search: (q: string, type?: string) =>
      request<{ results: { type: string; name: string }[] }>(
        `/modules/search?q=${encodeURIComponent(q)}${type ? `&type=${type}` : ""}`
      ),
    info: (type: string, name: string) =>
      request<{ info: Record<string, unknown>; options: Record<string, any> }>(
        `/modules/${type}/${encodeURIComponent(name)}/info`
      ),
    compatiblePayloads: (name: string, target?: number) => {
      const params = new URLSearchParams({ name });
      if (target !== undefined) params.set("target", String(target));
      return request<{ module: string; target: number | null; payloads: string[] }>(
        `/modules/compatible-payloads?${params.toString()}`
      );
    },
    execute: (type: string, name: string, options: Record<string, unknown>) =>
      request<Record<string, unknown>>("/modules/execute", {
        method: "POST",
        body: JSON.stringify({ type, name, options }),
      }),
    encode: (requestBody: {
      name: string;
      data: string;
      data_format: "text" | "hex" | "base64";
      badchars: string;
      platform: string;
      arch: string;
      iterations: number;
      module_options: Record<string, unknown>;
    }) =>
      request<{
        kind: "encoder";
        filename: string;
        size: number;
        payload_base64: string;
        format: "raw";
        module: string;
        input_size: number;
        iterations: number;
      }>("/modules/encode", {
        method: "POST",
        body: JSON.stringify(requestBody),
      }),
    generateNops: (requestBody: {
      name: string;
      length: number;
      badchars: string;
      save_registers: string[];
    }) =>
      request<{
        kind: "nop";
        filename: string;
        size: number;
        payload_base64: string;
        format: "raw";
        module: string;
        requested_size: number;
        badchars: string;
        save_registers: string[];
      }>("/modules/generate-nops", {
        method: "POST",
        body: JSON.stringify(requestBody),
      }),
    runningStats: () =>
      request<{ waiting?: string[]; running?: string[]; results?: string[] }>("/modules/running-stats"),
    results: (runUuid: string) =>
      request<{ status?: string; result?: unknown; error?: string }>("/modules/results/" + encodeURIComponent(runUuid)),
    // Match module names against a confirmed banner, or use a labelled
    // common-port service-family hint when the scan has no banner. Also
    // cross-references each candidate against NVD's own CVE data for the
    // confirmed product/version (see SuggestedModule.cve_matches) - still
    // not a vulnerability confirmation by itself; see checkModule below.
    suggest: (serviceInfo: string, port?: number) => {
      const params = new URLSearchParams({ service_info: serviceInfo });
      if (port !== undefined) params.set("port", String(port));
      return request<ModuleSuggestions>(`/modules/suggest?${params.toString()}`);
    },
    // Actually runs Metasploit's own `check` action for one module against
    // a target - the same mechanism local_exploit_suggester uses - rather
    // than trusting the name/description match from suggest() above.
    checkModule: (type: string, name: string, options: Record<string, unknown>) =>
      request<ModuleCheckResult>(`/modules/${type}/${encodeURIComponent(name)}/check`, {
        method: "POST",
        body: JSON.stringify({ options }),
      }),
  },

  sessions: {
    list: () => request<Record<string, any>>("/sessions"),
    stop: (id: number) => request(`/sessions/${id}/stop`, { method: "POST" }),
  },

  db: {
    hosts: () => request<{ hosts: any[] }>("/db/hosts"),
    services: () => request<{ services: any[] }>("/db/services"),
    vulns: () => request<{ vulns: any[] }>("/db/vulns"),
    loot: () => request<{ loot: any[] }>("/db/loot"),
    downloadLoot: async (downloadId: string): Promise<{ blob: Blob; filename: string }> => {
      const response = await fetch(`${BASE}/db/loot/${encodeURIComponent(downloadId)}/download`, { credentials: "same-origin" });
      if (!response.ok) {
        const message = await response.text();
        if (response.status === 401) window.dispatchEvent(new CustomEvent("msf-auth-required"));
        throw new Error(`${response.status}: ${message}`);
      }
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const match = /filename="([^"]+)"/i.exec(disposition);
      return {
        blob: await response.blob(),
        filename: match?.[1] ?? "loot-artifact.bin",
      };
    },
    downloadReport: async (): Promise<{ blob: Blob; filename: string }> => {
      const response = await fetch(`${BASE}/db/report`, { credentials: "same-origin" });
      if (!response.ok) {
        const message = await response.text();
        if (response.status === 401) window.dispatchEvent(new CustomEvent("msf-auth-required"));
        throw new Error(`${response.status}: ${message}`);
      }
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const match = /filename="([^"]+)"/i.exec(disposition);
      return {
        blob: await response.blob(),
        filename: match?.[1] ?? "msf-assessment.html",
      };
    },
    downloadReportPdf: async (): Promise<{ blob: Blob; filename: string }> => {
      const response = await fetch(`${BASE}/db/report.pdf`, { credentials: "same-origin" });
      if (!response.ok) {
        const message = await response.text();
        if (response.status === 401) window.dispatchEvent(new CustomEvent("msf-auth-required"));
        throw new Error(`${response.status}: ${message}`);
      }
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const match = /filename="([^"]+)"/i.exec(disposition);
      return {
        blob: await response.blob(),
        filename: match?.[1] ?? "msf-assessment.pdf",
      };
    },
    creds: () => request<{ creds: any[] }>("/db/creds"),
    workspaces: () => request<{ workspaces: Workspace[] }>("/db/workspaces"),
    currentWorkspace: () => request<CurrentWorkspace>("/db/workspace"),
    setWorkspace: (name: string) =>
      request<CurrentWorkspace>("/db/workspace", {
        method: "POST",
        body: JSON.stringify({ name }),
      }),
    createWorkspace: (name: string) =>
      request<CurrentWorkspace>("/db/workspaces", {
        method: "POST",
        body: JSON.stringify({ name }),
      }),
    renameWorkspace: (oldName: string, newName: string) =>
      request<{
        renamed_workspace: { old_name: string; new_name: string };
        current_workspace: CurrentWorkspace;
        workspaces: Workspace[];
      }>("/db/workspaces/rename", {
        method: "POST",
        body: JSON.stringify({ old_name: oldName, new_name: newName }),
      }),
    deleteWorkspace: (name: string) =>
      request<{ deleted_workspace: string; current_workspace: CurrentWorkspace; workspaces: Workspace[] }>(
        `/db/workspaces/${encodeURIComponent(name)}`,
        { method: "DELETE" }
      ),
  },

  cve: {
    lookup: (cveId: string) => request<CveEnrichment>(`/cve/${encodeURIComponent(cveId)}`),
    workspaceEnrichment: (limit = 25) =>
      request<WorkspaceCveEnrichment>(`/cve/workspace-enrichment?limit=${limit}`),
  },

  jobs: {
    list: () => request<Record<string, any>>("/jobs"),
    info: (id: string) => request<Record<string, any>>(`/jobs/${encodeURIComponent(id)}/info`),
    stop: (id: string) => request(`/jobs/${encodeURIComponent(id)}/stop`, { method: "POST" }),
  },
};

function wsBase(): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}`;
}

export function consoleSocketUrl(): string {
  return `${wsBase()}/api/console/ws`;
}

export function sessionSocketUrl(sessionId: number): string {
  return `${wsBase()}/api/sessions/ws/${sessionId}`;
}
