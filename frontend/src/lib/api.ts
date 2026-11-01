const BASE = "/api";

export type AssessmentTarget = { id: number; url: string; hostname: string; created_at: string };
export type AssessmentSummary = {
  id: number; name: string; description: string; status: "active" | "completed" | "archived";
  created_at: string; updated_at: string; target_count?: number;
};
export type AssessmentDetail = AssessmentSummary & { targets: AssessmentTarget[] };
export type AssessmentAsset = { id: number; assessment_id: number; asset_type: "url" | "host"; value: string; hostname: string; scope_state: "in_scope" | "out_of_scope"; source_tool: string; first_seen: string; last_seen: string };
export type AssessmentAssetInventory = { assets: AssessmentAsset[]; counts: { total: number; in_scope: number; out_of_scope: number } };
export type AssessmentExecutionRecord = Record<string, unknown> & {
  record_id: string; review_state: "active" | "dismissed"; reviewed_at: string | null; notes: string; record_type: "evidence" | "finding";
};
export type AssessmentExecutionDetail = AssessmentExecution & { records: AssessmentExecutionRecord[]; stderr: string };
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
      installed: boolean; execution_enabled: boolean;
      status: "ready" | "not_installed" | "not_integrated";
      path?: string | null;
    }[]; built_in: { name: string; available: boolean; description: string }[] }>("/web-recon/tools"),
    wordlists: () => request<{ wordlists: { id: string; name: string; size_bytes: number }[] }>("/web-recon/wordlists"),
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
    checkManualPaths: (assessmentId: number, url: string, paths: string[], authorized: boolean) =>
      request<{
        execution_id: number; assessment_id: number; tool_id: "manual-path-check"; target: string;
        records: { url: string; status_code?: number; reason?: string; response_title?: string | null;
          response_content_type?: string | null; response_preview?: string; content_length?: number; bytes_inspected?: number;
          body_truncated?: boolean; redirect_location?: string | null; fetch_state?: string;
          response_features?: { form_count: number; input_count: number; password_input_count: number;
            email_input_count: number; link_count: number; script_count: number; button_count: number };
          response_classification?: "likely_soft_404" | "needs_verification" | "distinct_response" | "baseline_unavailable"; body_similarity?: number | null;
          response_fingerprint?: string; soft_404_markers?: string[]; shared_not_found_markers?: string[];
          shared_not_found_marker_count?: number; baseline_samples_compared?: number;
          baseline_sample_count?: number; classification_reason: string }[];
        baseline: { status: "available" | "partial" | "unavailable"; attempted: number; successful: number; failed: number; failures: { fetch_state: string; reason: string }[]; comparison: string };
        assessment: string;
      }>("/web-recon/directories/check", {
        method: "POST",
        body: JSON.stringify({ assessment_id: assessmentId, url, paths, authorized }),
      }),
    runTool: (assessmentId: number, toolId: "httpx" | "whatweb" | "subfinder" | "katana" | "gobuster", url: string, authorized: boolean, options?: { wordlist_id?: string; extensions?: string }) =>
      request<{
        execution_id: number; assessment_id: number; tool_id: string; tool: string; target: string; exit_code: number;
        timed_out: boolean; output_truncated: boolean;
        records: { url?: string; target?: string; status_code?: number; http_status?: number;
          title?: string | null; webserver?: string; content_type?: string; content_length?: number | null;
          discovery_type?: "directory" | "path"; path?: string;
          technologies?: string[]; host?: string; sources?: string[]; method?: string; source?: string;
          tag?: string; attribute?: string; redirect_location?: string | null;
          kind?: string; redirects?: { from: string; to?: string; status_code: number; followed: boolean; reason?: string }[];
          raw?: string | null; resource_type?: "page" | "api_candidate" | "static_asset" | "redirect" | "framework_redirect" | "malformed"; classification_reason?: string; response_classification?: "suspected_wildcard" | "likely_soft_404" | "needs_verification" | "distinct_response" | "unverified"; body_similarity?: number; response_title?: string | null; response_content_type?: string | null; response_group_id?: string; soft_404_markers?: string[]; canonical_url?: string; endpoint_group?: string; fetch_state?: "fetched" | "discovered_unverified"; display_default?: boolean; observations?: number }[];
        wildcard_summary?: { baseline_status_codes: number[]; baseline_length_range: [number, number]; reference_length: number; length_tolerance: number; body_similarity_threshold: number; review_similarity_threshold: number; body_fingerprint_checks: number; body_fingerprint_check_limit: number; suspected_wildcard: number; likely_soft_404: number; needs_verification: number; distinct_response: number; unverified: number; total: number } | null;
        redirect_chain?: { from: string; to?: string; status_code: number; followed: boolean; reason?: string }[];
        stderr: string; assessment: string;
      }>("/web-recon/run", {
        method: "POST",
        body: JSON.stringify({ assessment_id: assessmentId, tool_id: toolId, url, authorized, ...options }),
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
    updateExecutionRecord: (id: number, executionId: number, recordId: string, changes: {
      review_state?: "active" | "dismissed"; reviewed?: boolean; notes?: string; record_type?: "evidence" | "finding";
    }) => request<{ record_id: string; review_state: "active" | "dismissed"; reviewed_at: string | null; notes: string; record_type: "evidence" | "finding" }>(
      `/assessments/${id}/executions/${executionId}/records/${encodeURIComponent(recordId)}`,
      { method: "PATCH", body: JSON.stringify(changes) },
    ),
    deleteExecutionRecord: (id: number, executionId: number, recordId: string) =>
      request<{ deleted: boolean; record_id: string }>(
        `/assessments/${id}/executions/${executionId}/records/${encodeURIComponent(recordId)}`,
        { method: "DELETE" },
      ),
    records: (id: number, filters?: { q?: string; tool_id?: string; record_type?: string; review_state?: string; reviewed?: string; sort_by?: string }) => {
      const params = new URLSearchParams();
      Object.entries(filters ?? {}).forEach(([key, value]) => { if (value) params.set(key, value); });
      return request<{ records: (AssessmentExecutionRecord & { execution_id: number; tool_id: string; target_url: string; started_at: string; finished_at: string; exit_code: number })[]; total: number }>(
        `/assessments/${id}/records?${params.toString()}`
      );
    },
    bulkUpdateRecords: (id: number, record_ids: string[], changes: { review_state?: "active" | "dismissed"; reviewed?: boolean; record_type?: "evidence" | "finding" }) =>
      request<{ updated: number }>(`/assessments/${id}/records/bulk`, { method: "PATCH", body: JSON.stringify({ record_ids, ...changes }) }),
    bulkDeleteRecords: (id: number, record_ids: string[]) =>
      request<{ deleted: number }>(`/assessments/${id}/records/bulk`, { method: "DELETE", body: JSON.stringify({ record_ids }) }),
    history: (id: number) => request<{ assessment_id: number; total_runs: number; total_records: number; findings: number; evidence: number; reviewed: number; dismissed: number; by_tool: { tool_id: string; runs: number; first_run: string; last_run: string; successful_runs: number }[] }>(`/assessments/${id}/history`),
    compareRuns: (id: number, baseline_id: number, comparison_id: number) =>
      request<{ baseline: { id: number; tool_id: string; target_url: string }; comparison: { id: number; tool_id: string; target_url: string }; added: Record<string, unknown>[]; removed: Record<string, unknown>[]; unchanged: Record<string, unknown>[] }>(
        `/assessments/${id}/compare?${new URLSearchParams({ baseline_id: String(baseline_id), comparison_id: String(comparison_id) })}`
      ),
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
