import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../lib/api";

export function LoginView({
  configured,
  initialError,
  onAuthenticated,
}: {
  configured: boolean | null;
  initialError?: string | null;
  onAuthenticated: (username: string) => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(initialError ?? null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!configured || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.auth.login(username.trim(), password);
      setPassword("");
      onAuthenticated(result.username);
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen w-screen items-center justify-center overflow-auto bg-bg-primary p-4">
      <section className="w-full max-w-md overflow-hidden rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="border-b border-border px-6 py-5">
          <div className="mb-3 flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded bg-accent-dim font-mono text-sm font-bold text-black">M</span>
            <span className="text-[10px] uppercase tracking-[0.25em] text-accent">Local security console</span>
          </div>
          <h1 className="text-xl font-semibold text-gray-100">MSF Web Console</h1>
          <p className="mt-2 text-sm leading-5 text-gray-500">
            Sign in to access your local Metasploit console, sessions, jobs and assessment database.
          </p>
        </div>

        <div className="p-6">
          {configured === false ? (
            <div role="alert" className="rounded border border-warning/30 bg-warning/5 p-4">
              <h2 className="text-sm font-semibold text-warning">Login is not configured</h2>
              <p className="mt-2 text-xs leading-5 text-gray-300">
                Stop the backend and edit <code className="text-accent">backend/.env</code>. Set
                <code className="mx-1 text-accent">MSF_WEB_USERNAME</code> and a unique
                <code className="mx-1 text-accent">MSF_WEB_PASSWORD</code> with at least 12 characters, then restart the backend.
              </p>
              <p className="mt-3 text-[11px] leading-5 text-gray-500">
                Authentication fails closed: the console API remains locked until valid credentials are configured.
              </p>
            </div>
          ) : (
            <form onSubmit={(event) => void submit(event)} className="space-y-4">
              <div>
                <label htmlFor="login-username" className="mb-1.5 block text-xs font-medium text-gray-300">Username</label>
                <input
                  id="login-username"
                  name="username"
                  autoComplete="username"
                  autoFocus
                  required
                  maxLength={100}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  className="h-10 w-full rounded border border-border bg-bg-primary px-3 text-sm text-gray-100 outline-none focus:border-accent"
                  placeholder="Enter username"
                />
              </div>
              <div>
                <label htmlFor="login-password" className="mb-1.5 block text-xs font-medium text-gray-300">Password</label>
                <input
                  id="login-password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="h-10 w-full rounded border border-border bg-bg-primary px-3 text-sm text-gray-100 outline-none focus:border-accent"
                  placeholder="Enter password"
                />
              </div>
              {error && (
                <div role="alert" className="rounded border border-danger/30 bg-danger/5 p-3 text-xs leading-5 text-danger">
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={busy || !username.trim() || !password}
                className="h-10 w-full rounded bg-accent-dim text-sm font-semibold text-black transition-colors hover:bg-accent disabled:cursor-wait disabled:opacity-50"
              >
                {busy ? "Signing in…" : "Sign in"}
              </button>
            </form>
          )}

          {configured === null && (
            <p role="status" className="text-xs leading-5 text-gray-500">
              Checking authentication configuration…
            </p>
          )}
          <div className="mt-5 border-t border-border pt-4 text-[10px] leading-5 text-gray-600">
            This application remains bound to local access. Login does not enable remote deployment.
          </div>
        </div>
      </section>
    </main>
  );
}
