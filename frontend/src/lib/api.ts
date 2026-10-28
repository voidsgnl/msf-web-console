const BASE = "/api";

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
    runningStats: () =>
      request<{ waiting?: string[]; running?: string[]; results?: string[] }>("/modules/running-stats"),
    results: (runUuid: string) =>
      request<{ status?: string; result?: unknown; error?: string }>("/modules/results/" + encodeURIComponent(runUuid)),
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
