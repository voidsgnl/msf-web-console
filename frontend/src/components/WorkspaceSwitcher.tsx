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
  const [workspaceDialog, setWorkspaceDialog] = useState<{ kind: "rename" | "delete"; workspace: Workspace } | null>(null);
  const [dialogValue, setDialogValue] = useState("");
  const [dialogError, setDialogError] = useState<string | null>(null);
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

  useEffect(() => {
    if (!workspaceDialog) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) {
        setWorkspaceDialog(null);
        setDialogError(null);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [workspaceDialog, busy]);

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

  const openRenameDialog = (workspace: Workspace) => {
    if (busy || workspace.name.toLowerCase() === "default") return;
    setWorkspaceDialog({ kind: "rename", workspace });
    setDialogValue(workspace.name);
    setDialogError(null);
    setError(null);
    setMessage(null);
    setCreateOpen(false);
    setManageOpen(false);
  };

  const openDeleteDialog = (workspace: Workspace) => {
    if (busy || workspace.name.toLowerCase() === "default") return;
    setWorkspaceDialog({ kind: "delete", workspace });
    setDialogValue("");
    setDialogError(null);
    setError(null);
    setMessage(null);
    setCreateOpen(false);
    setManageOpen(false);
  };

  const closeWorkspaceDialog = () => {
    if (busy) return;
    setWorkspaceDialog(null);
    setDialogError(null);
  };

  const submitWorkspaceDialog = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!workspaceDialog || busy) return;

    const { kind, workspace } = workspaceDialog;
    const value = dialogValue.trim();

    if (kind === "rename") {
      if (!value) {
        setDialogError("Workspace name must not be blank.");
        return;
      }
      if (value.length > 100 || !/^[A-Za-z0-9_](?:[A-Za-z0-9_. -]{0,98}[A-Za-z0-9_])?$/.test(value)) {
        setDialogError("Use up to 100 letters, numbers, spaces, dots, hyphens, or underscores. The first and last characters must be a letter, number, or underscore.");
        return;
      }
      if (value.toLowerCase() === workspace.name.toLowerCase()) {
        setDialogError("Enter a different name. Workspace names are not case-sensitive.");
        return;
      }

      setBusy(true);
      setDialogError(null);
      setError(null);
      setMessage(null);
      try {
        const result = await api.db.renameWorkspace(workspace.name, value);
        const nextWorkspace = result.current_workspace?.workspace ?? currentWorkspace;
        setWorkspaces(result.workspaces ?? []);
        setCurrentWorkspace(nextWorkspace);
        knownWorkspace.current = nextWorkspace;
        setWorkspaceDialog(null);
        setDialogValue("");
        setManageOpen(false);
        setMessage(`Renamed ${workspace.name} to ${result.renamed_workspace?.new_name ?? value}`);
        if (nextWorkspace !== currentWorkspace) onWorkspaceChanged(nextWorkspace);
      } catch (e: unknown) {
        setDialogError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
      return;
    }

    if (value !== workspace.name) {
      setDialogError("The name does not match. Type the exact workspace name to confirm deletion.");
      return;
    }

    setBusy(true);
    setDialogError(null);
    setError(null);
    setMessage(null);
    try {
      const result = await api.db.deleteWorkspace(workspace.name);
      const nextWorkspace = result.current_workspace?.workspace ?? "default";
      setWorkspaces(result.workspaces ?? []);
      setCurrentWorkspace(nextWorkspace);
      knownWorkspace.current = nextWorkspace;
      setWorkspaceDialog(null);
      setDialogValue("");
      setManageOpen(false);
      const switched = nextWorkspace !== currentWorkspace;
      setMessage(
        switched
          ? `Deleted ${workspace.name} and switched to ${nextWorkspace}`
          : `Deleted workspace ${workspace.name}`
      );
      if (switched) onWorkspaceChanged(nextWorkspace);
    } catch (e: unknown) {
      setDialogError(e instanceof Error ? e.message : String(e));
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
                    onClick={() => openRenameDialog(workspace)}
                    disabled={busy || workspace.name.toLowerCase() === "default"}
                    title={workspace.name.toLowerCase() === "default" ? "The default workspace is protected" : "Rename this workspace"}
                    className="rounded border border-border px-2 py-1 text-[10px] text-gray-300 hover:bg-bg-tertiary disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Rename
                  </button>
                  <button
                    type="button"
                    onClick={() => openDeleteDialog(workspace)}
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

      {workspaceDialog && (
        <div
          className="fixed inset-0 z-[80] flex items-center justify-center bg-black/75 p-4 backdrop-blur-[2px]"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) closeWorkspaceDialog();
          }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="workspace-dialog-title"
            aria-describedby="workspace-dialog-description"
            className="w-full max-w-md overflow-hidden rounded-lg border border-border bg-bg-primary shadow-2xl"
          >
            <div className="flex items-start gap-3 border-b border-border p-5">
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-md border ${workspaceDialog.kind === "delete" ? "border-danger/30 bg-danger/10 text-danger" : "border-accent/30 bg-accent-dim text-accent"}`}>
                <span aria-hidden="true" className="text-lg font-semibold">
                  {workspaceDialog.kind === "delete" ? "!" : "↗"}
                </span>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-gray-500">
                  Workspace manager
                </p>
                <h2 id="workspace-dialog-title" className="mt-1 text-base font-semibold text-gray-100">
                  {workspaceDialog.kind === "rename" ? "Rename workspace" : "Delete workspace"}
                </h2>
                <p id="workspace-dialog-description" className="mt-1 text-xs leading-5 text-gray-500">
                  {workspaceDialog.kind === "rename"
                    ? "Change the workspace name without moving or deleting its assessment records."
                    : "This permanently deletes the workspace and its stored assessment records. This action cannot be undone."}
                </p>
              </div>
              <button
                type="button"
                aria-label="Close dialog"
                onClick={closeWorkspaceDialog}
                disabled={busy}
                className="rounded p-1 text-gray-500 hover:bg-bg-tertiary hover:text-gray-200 disabled:opacity-40"
              >
                <span aria-hidden="true">×</span>
              </button>
            </div>

            <form onSubmit={(event) => void submitWorkspaceDialog(event)}>
              <div className="space-y-2 p-5">
                {workspaceDialog.kind === "rename" ? (
                  <>
                    <label htmlFor="workspace-rename-name" className="block text-xs font-medium text-gray-300">
                      New workspace name
                    </label>
                    <input
                      id="workspace-rename-name"
                      autoFocus
                      autoComplete="off"
                      spellCheck={false}
                      maxLength={100}
                      value={dialogValue}
                      onChange={(event) => {
                        setDialogValue(event.target.value);
                        setDialogError(null);
                      }}
                      placeholder="e.g. client_assessment"
                      aria-invalid={Boolean(dialogError)}
                      aria-describedby={dialogError ? "workspace-dialog-error" : "workspace-rename-help"}
                      className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2.5 font-mono text-sm text-gray-100 outline-none transition focus:border-accent focus:ring-2 focus:ring-accent/20"
                    />
                    <p id="workspace-rename-help" className="text-[11px] leading-4 text-gray-500">
                      Letters, numbers, spaces, dots, hyphens, and underscores are supported.
                    </p>
                  </>
                ) : (
                  <>
                    <label htmlFor="workspace-delete-confirmation" className="block text-xs font-medium text-gray-300">
                      Type <span className="rounded bg-bg-tertiary px-1.5 py-0.5 font-mono text-gray-100">{workspaceDialog.workspace.name}</span> to confirm
                    </label>
                    <input
                      id="workspace-delete-confirmation"
                      autoFocus
                      autoComplete="off"
                      spellCheck={false}
                      value={dialogValue}
                      onChange={(event) => {
                        setDialogValue(event.target.value);
                        setDialogError(null);
                      }}
                      placeholder="Enter the workspace name exactly"
                      aria-invalid={Boolean(dialogError)}
                      aria-describedby={dialogError ? "workspace-dialog-error" : "workspace-delete-help"}
                      className="w-full rounded-md border border-danger/30 bg-bg-tertiary px-3 py-2.5 font-mono text-sm text-gray-100 outline-none transition focus:border-danger focus:ring-2 focus:ring-danger/20"
                    />
                    <p id="workspace-delete-help" className="text-[11px] leading-4 text-gray-500">
                      The workspace and its database records will be permanently removed.
                    </p>
                  </>
                )}
                {dialogError && (
                  <p id="workspace-dialog-error" role="alert" className="rounded-md border border-danger/30 bg-danger/5 px-3 py-2 text-xs leading-5 text-danger">
                    {dialogError}
                  </p>
                )}
              </div>

              <div className="flex items-center justify-between gap-3 border-t border-border bg-bg-secondary/70 px-5 py-4">
                <span className="hidden text-[10px] text-gray-600 sm:inline">
                  Press Esc to cancel
                </span>
                <div className="ml-auto flex items-center gap-2">
                  <button
                    type="button"
                    onClick={closeWorkspaceDialog}
                    disabled={busy}
                    className="rounded-md border border-border px-3 py-2 text-xs text-gray-300 hover:bg-bg-tertiary disabled:opacity-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={busy || (workspaceDialog.kind === "rename" ? !dialogValue.trim() : dialogValue !== workspaceDialog.workspace.name)}
                    className={`rounded-md px-3 py-2 text-xs font-semibold disabled:cursor-not-allowed disabled:opacity-40 ${workspaceDialog.kind === "delete" ? "bg-danger text-white hover:bg-danger/90" : "bg-accent-dim text-black hover:bg-accent"}`}
                  >
                    {busy
                      ? workspaceDialog.kind === "rename" ? "Renaming…" : "Deleting…"
                      : workspaceDialog.kind === "rename" ? "Rename workspace" : "Delete workspace"}
                  </button>
                </div>
              </div>
            </form>
          </section>
        </div>
      )}

      <span className="sr-only" aria-live="polite">{message ?? error ?? ""}</span>
      {error && <span className="max-w-48 truncate text-xs text-danger" title={error}>{error}</span>}
      {message && !error && <span className="max-w-48 truncate text-xs text-gray-500">{message}</span>}
    </div>
  );
}
