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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}

export const api = {
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
      const response = await fetch(`${BASE}/db/loot/${encodeURIComponent(downloadId)}/download`);
      if (!response.ok) {
        const message = await response.text();
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
      const response = await fetch(`${BASE}/db/report`);
      if (!response.ok) {
        const message = await response.text();
        throw new Error(`${response.status}: ${message}`);
      }
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const match = /filename="([^"]+)"/i.exec(disposition);
      return {
        blob: await response.blob(),
        filename: match?.[1] ?? "msf-assessment.html",
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
  },

  jobs: {
    list: () => request<Record<string, any>>("/jobs"),
    stop: (id: string) => request(`/jobs/${id}/stop`, { method: "POST" }),
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
