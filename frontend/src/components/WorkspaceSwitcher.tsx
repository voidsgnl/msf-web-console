import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../lib/api";
import type { Workspace } from "../lib/api";

export function WorkspaceSwitcher({
  onWorkspaceChanged,
}: {
  onWorkspaceChanged: (workspace: string) => void;
}) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [currentWorkspace, setCurrentWorkspace] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const knownWorkspace = useRef<string | null>(null);
  const onWorkspaceChangedRef = useRef(onWorkspaceChanged);
  onWorkspaceChangedRef.current = onWorkspaceChanged;

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);

    Promise.all([api.db.workspaces(), api.db.currentWorkspace()])
      .then(([workspaceResult, currentResult]) => {
        if (!active) return;
        const nextWorkspace = currentResult.workspace ?? "";
        if (knownWorkspace.current !== null && knownWorkspace.current !== nextWorkspace) {
          onWorkspaceChangedRef.current(nextWorkspace);
        }
        knownWorkspace.current = nextWorkspace;
        setWorkspaces(workspaceResult.workspaces ?? []);
        setCurrentWorkspace(nextWorkspace);
      })
      .catch((e: unknown) => {
        if (active) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [reloadKey]);

  const switchWorkspace = async (name: string) => {
    if (!name || name === currentWorkspace || busy) return;

    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const current = await api.db.setWorkspace(name);
      knownWorkspace.current = current.workspace;
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
      knownWorkspace.current = current.workspace;
      setCurrentWorkspace(current.workspace);
      setWorkspaces((existing) => {
        const withoutDuplicate = existing.filter((workspace) => workspace.name !== current.workspace);
        return [...withoutDuplicate, { id: current.workspace_id, name: current.workspace }]
          .sort((a, b) => a.name.localeCompare(b.name));
      });
      setNewName("");
      setCreateOpen(false);
      setManageOpen(false);
      setMessage(`Created and switched to ${current.workspace}`);
      onWorkspaceChanged(current.workspace);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const renameWorkspace = async (workspace: Workspace) => {
    if (busy || workspace.name.toLowerCase() === "default") return;
    const entered = window.prompt(
      `Rename workspace "${workspace.name}" to:`,
      workspace.name
    );
    if (entered === null) return;
    const newName = entered.trim();
    if (!newName) {
      setError("Workspace name must not be blank.");
      return;
    }
    if (newName === workspace.name) {
      setMessage("Workspace name unchanged.");
      return;
    }

    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await api.db.renameWorkspace(workspace.name, newName);
      const nextWorkspace = result.current_workspace?.workspace ?? currentWorkspace;
      setWorkspaces(result.workspaces ?? []);
      setCurrentWorkspace(nextWorkspace);
      knownWorkspace.current = nextWorkspace;
      setManageOpen(false);
      setMessage(`Renamed ${workspace.name} to ${result.renamed_workspace?.new_name ?? newName}`);
      if (nextWorkspace !== currentWorkspace) onWorkspaceChanged(nextWorkspace);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const deleteWorkspace = async (workspace: Workspace) => {
    if (busy || workspace.name.toLowerCase() === "default") return;
    const entered = window.prompt(
      `This permanently deletes the "${workspace.name}" workspace and its stored assessment records. Type the workspace name exactly to confirm:`
    );
    if (entered !== workspace.name) {
      if (entered !== null) setMessage("Workspace deletion cancelled because the name did not match.");
      return;
    }

    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await api.db.deleteWorkspace(workspace.name);
      const nextWorkspace = result.current_workspace?.workspace ?? "default";
      setWorkspaces(result.workspaces ?? []);
      setCurrentWorkspace(nextWorkspace);
      knownWorkspace.current = nextWorkspace;
      setManageOpen(false);
      const switched = nextWorkspace !== currentWorkspace;
      setMessage(
        switched
          ? `Deleted ${workspace.name} and switched to ${nextWorkspace}`
          : `Deleted workspace ${workspace.name}`
      );
      if (switched) onWorkspaceChanged(nextWorkspace);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const toggleCreate = () => {
    setCreateOpen((open) => !open);
    setManageOpen(false);
    setError(null);
    setMessage(null);
  };

  const toggleManage = () => {
    setManageOpen((open) => !open);
    setCreateOpen(false);
    setError(null);
    setMessage(null);
  };

  return (
    <div className="relative flex items-center gap-2">
      <span className="text-[10px] uppercase tracking-widest text-gray-500">Workspace</span>
      <select
        aria-label="Active database workspace"
        value={currentWorkspace}
        onChange={(event) => void switchWorkspace(event.target.value)}
        disabled={loading || busy}
        className="max-w-56 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-gray-200 disabled:opacity-60"
      >
        {!currentWorkspace && <option value="">{loading ? "Loading…" : "Unavailable"}</option>}
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
        onClick={toggleCreate}
        disabled={busy}
        className="rounded border border-border px-2 py-1.5 text-xs text-gray-400 hover:bg-bg-tertiary hover:text-gray-100 disabled:opacity-50"
      >
        + New
      </button>
      <button
        type="button"
        onClick={toggleManage}
        disabled={busy || loading}
        aria-expanded={manageOpen}
        className="rounded border border-border px-2 py-1.5 text-xs text-gray-400 hover:bg-bg-tertiary hover:text-gray-100 disabled:opacity-50"
      >
        Manage
      </button>
      <button
        type="button"
        aria-label="Refresh workspaces"
        title={error ? "Retry workspace connection" : "Refresh workspace list"}
        onClick={() => {
          setMessage(null);
          setReloadKey((key) => key + 1);
        }}
        disabled={loading || busy}
        className="rounded border border-border px-2 py-1.5 text-xs text-gray-400 hover:bg-bg-tertiary hover:text-gray-100 disabled:opacity-50"
      >
        {loading ? "…" : error ? "Retry" : "↻"}
      </button>

      {createOpen && (
        <form
          onSubmit={(event) => void createWorkspace(event)}
          className="absolute right-0 top-full z-30 mt-2 w-72 space-y-2 rounded border border-border bg-bg-secondary p-3 shadow-xl"
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
            className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 font-mono text-xs text-gray-100 placeholder:text-gray-600"
          />
          <p className="text-[10px] text-gray-500">
            Creates the workspace and switches to it. Existing workspace data is kept separate.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => { setCreateOpen(false); setNewName(""); }}
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

      {manageOpen && (
        <div className="absolute right-0 top-full z-30 mt-2 w-80 max-w-[90vw] rounded border border-border bg-bg-secondary p-3 shadow-xl">
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold text-gray-200">Manage workspaces</h3>
            <button onClick={() => setManageOpen(false)} className="text-xs text-gray-500 hover:text-gray-200">
              Close
            </button>
          </div>
          <p className="mb-3 text-[10px] leading-4 text-gray-500">
            Rename a workspace without moving or deleting its records. Deleting a workspace permanently removes its stored assessment data. The default workspace is protected.
          </p>
          <div className="max-h-64 space-y-1 overflow-auto">
            {workspaces.map((workspace) => (
              <div key={workspace.id ?? workspace.name} className="flex items-center justify-between gap-3 rounded border border-border/60 px-2 py-2">
                <div className="min-w-0">
                  <p className="truncate text-xs text-gray-200" title={workspace.name}>{workspace.name}</p>
                  <p className="mt-0.5 text-[10px] text-gray-600">
                    {workspace.name === currentWorkspace ? "Active workspace" : "Not active"}
                    {workspace.name.toLowerCase() === "default" ? " · protected" : ""}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <button
                    type="button"
                    onClick={() => void renameWorkspace(workspace)}
                    disabled={busy || workspace.name.toLowerCase() === "default"}
                    title={workspace.name.toLowerCase() === "default" ? "The default workspace is protected" : "Rename this workspace"}
                    className="rounded border border-border px-2 py-1 text-[10px] text-gray-300 hover:bg-bg-tertiary disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Rename
                  </button>
                  <button
                    type="button"
                    onClick={() => void deleteWorkspace(workspace)}
                    disabled={busy || workspace.name.toLowerCase() === "default"}
                    className="rounded border border-danger/30 px-2 py-1 text-[10px] text-danger hover:bg-danger/5 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {busy ? "working…" : "Delete"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <span className="sr-only" aria-live="polite">{message ?? error ?? ""}</span>
      {error && <span className="max-w-48 truncate text-xs text-danger" title={error}>{error}</span>}
      {message && !error && <span className="max-w-48 truncate text-xs text-gray-500">{message}</span>}
    </div>
  );
}
