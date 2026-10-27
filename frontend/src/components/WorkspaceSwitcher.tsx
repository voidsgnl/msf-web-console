import { FormEvent, useEffect, useState } from "react";
import { api, Workspace } from "../lib/api";

export function WorkspaceSwitcher({
  onWorkspaceChanged,
}: {
  onWorkspaceChanged: (workspace: string) => void;
}) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [currentWorkspace, setCurrentWorkspace] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    Promise.all([api.db.workspaces(), api.db.currentWorkspace()])
      .then(([workspaceResult, currentResult]) => {
        if (!active) return;
        setWorkspaces(workspaceResult.workspaces ?? []);
        setCurrentWorkspace(currentResult.workspace ?? "");
        setError(null);
      })
      .catch((e: unknown) => {
        if (active) {
          setError(e instanceof Error ? e.message : String(e));
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const switchWorkspace = async (name: string) => {
    if (!name || name === currentWorkspace || busy) return;

    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const current = await api.db.setWorkspace(name);
      setCurrentWorkspace(current.workspace);
      setMessage(`Switched to ${current.workspace}`);
      onWorkspaceChanged(current.workspace);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const createWorkspace = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const name = newName.trim();
    if (!name || busy) return;

    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const current = await api.db.createWorkspace(name);
      setCurrentWorkspace(current.workspace);
      setWorkspaces((existing) => {
        const withoutDuplicate = existing.filter((workspace) => workspace.name !== current.workspace);
        return [...withoutDuplicate, { id: current.workspace_id, name: current.workspace }]
          .sort((a, b) => a.name.localeCompare(b.name));
      });
      setNewName("");
      setCreateOpen(false);
      setMessage(`Created and switched to ${current.workspace}`);
      onWorkspaceChanged(current.workspace);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex items-center gap-2">
      <span className="text-[10px] uppercase tracking-widest text-gray-500">Workspace</span>
      <select
        aria-label="Active database workspace"
        value={currentWorkspace}
        onChange={(event) => void switchWorkspace(event.target.value)}
        disabled={loading || busy}
        className="max-w-56 bg-bg-tertiary border border-border rounded px-2 py-1.5 text-xs text-gray-200 disabled:opacity-60"
      >
        {!currentWorkspace && (
          <option value="">{loading ? "Loading…" : "Unavailable"}</option>
        )}
        {currentWorkspace && !workspaces.some((workspace) => workspace.name === currentWorkspace) && (
          <option value={currentWorkspace}>{currentWorkspace}</option>
        )}
        {workspaces.map((workspace) => (
          <option key={workspace.id ?? workspace.name} value={workspace.name}>
            {workspace.name}
          </option>
        ))}
      </select>

      <button
        type="button"
        onClick={() => {
          setCreateOpen((open) => !open);
          setError(null);
          setMessage(null);
        }}
        disabled={busy}
        className="rounded border border-border px-2 py-1.5 text-xs text-gray-400 hover:text-gray-100 hover:bg-bg-tertiary disabled:opacity-50"
      >
        + New
      </button>

      {createOpen && (
        <form
          onSubmit={(event) => void createWorkspace(event)}
          className="absolute right-0 top-full z-30 mt-2 w-72 rounded border border-border bg-bg-secondary p-3 shadow-xl space-y-2"
        >
          <label htmlFor="new-workspace-name" className="block text-xs text-gray-300">
            Create a database workspace
          </label>
          <input
            id="new-workspace-name"
            autoFocus
            maxLength={100}
            value={newName}
            onChange={(event) => setNewName(event.target.value)}
            placeholder="e.g. client_assessment"
            className="w-full bg-bg-tertiary border border-border rounded px-2 py-1.5 text-xs text-gray-100 font-mono placeholder:text-gray-600"
          />
          <p className="text-[10px] text-gray-500">
            Creates the workspace and switches to it. Existing workspace data is kept separate.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setCreateOpen(false);
                setNewName("");
              }}
              className="px-2 py-1 text-xs text-gray-500 hover:text-gray-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !newName.trim()}
              className="rounded bg-accent-dim px-2 py-1 text-xs font-medium text-black hover:bg-accent disabled:opacity-50"
            >
              {busy ? "Working…" : "Create & switch"}
            </button>
          </div>
        </form>
      )}

      <span className="sr-only" aria-live="polite">
        {message ?? error ?? ""}
      </span>
      {error && <span className="max-w-48 truncate text-xs text-danger" title={error}>{error}</span>}
      {message && !error && <span className="max-w-48 truncate text-xs text-gray-500">{message}</span>}
    </div>
  );
}
