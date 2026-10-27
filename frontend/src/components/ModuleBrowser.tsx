import { useState } from "react";
import { api } from "../lib/api";

type ModuleRef = { type: string; name: string };

export function ModuleBrowser() {
  const [query, setQuery] = useState("");
  const [type, setType] = useState<string>("exploit");
  const [results, setResults] = useState<ModuleRef[]>([]);
  const [selected, setSelected] = useState<ModuleRef | null>(null);
  const [info, setInfo] = useState<{ info: any; options: any } | null>(null);
  const [optionValues, setOptionValues] = useState<Record<string, string>>({});
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState<string | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  const search = async (q: string) => {
    setQuery(q);
    if (q.length < 2) {
      setResults([]);
      setSearchError(null);
      return;
    }
    try {
      setSearchError(null);
      const res = await api.modules.search(q, type);
      setResults(res.results);
    } catch (e: any) {
      console.error("module search failed:", e);
      setSearchError(e.message ?? String(e));
      setResults([]);
    }
  };

  const select = async (mod: ModuleRef) => {
    setSelected(mod);
    setExecResult(null);
    setInfo(null);
    setInfoError(null);
    setLoadingInfo(true);
    try {
      const data = await api.modules.info(mod.type, mod.name);
      setInfo(data);
      const defaults: Record<string, string> = {};
      for (const [key, opt] of Object.entries<any>(data.options || {})) {
        if (opt.default !== undefined && opt.default !== null) defaults[key] = String(opt.default);
      }
      setOptionValues(defaults);
    } catch (e: any) {
      console.error("module info failed:", e);
      setInfoError(e.message ?? String(e));
    } finally {
      setLoadingInfo(false);
    }
  };

  const execute = async () => {
    if (!selected) return;
    setExecuting(true);
    setExecResult(null);
    try {
      const result = await api.modules.execute(selected.type, selected.name, optionValues);
      setExecResult(JSON.stringify(result, null, 2));
    } catch (e: any) {
      setExecResult(`Error: ${e.message}`);
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="flex h-full">
      {/* Search + results column */}
      <div className="w-80 border-r border-border flex flex-col">
        <div className="p-3 border-b border-border space-y-2">
          <select
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              if (query) search(query);
            }}
            className="w-full bg-bg-tertiary border border-border rounded px-2 py-1.5 text-sm text-gray-200"
          >
            {["exploit", "auxiliary", "post", "payload", "encoder", "nop"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <input
            value={query}
            onChange={(e) => search(e.target.value)}
            placeholder="Search modules…"
            className="w-full bg-bg-tertiary border border-border rounded px-2 py-1.5 text-sm text-gray-200 font-mono placeholder:text-gray-600"
          />
        </div>
        <div className="flex-1 overflow-y-auto">
          {results.map((r) => (
            <button
              key={r.name}
              onClick={() => select(r)}
              className={`w-full text-left px-3 py-2 text-xs font-mono border-b border-border/50 hover:bg-bg-tertiary ${
                selected?.name === r.name ? "bg-bg-tertiary text-accent" : "text-gray-300"
              }`}
            >
              {r.name}
            </button>
          ))}
          {searchError && (
            <div className="p-3 text-xs text-danger">Search failed: {searchError}</div>
          )}
          {!searchError && query.length >= 2 && results.length === 0 && (
            <div className="p-3 text-xs text-gray-600">No matches</div>
          )}
        </div>
      </div>

      {/* Detail / options column */}
      <div className="flex-1 overflow-y-auto p-4">
        {!selected && <div className="text-sm text-gray-600">Select a module to view details and options.</div>}

        {selected && loadingInfo && <div className="text-sm text-gray-600">Loading {selected.name}…</div>}

        {selected && infoError && (
          <div className="text-sm text-danger">
            Failed to load module info: {infoError}
          </div>
        )}

        {selected && info && (
          <div className="space-y-4 max-w-2xl">
            <div>
              <h2 className="font-mono text-sm text-gray-100">{selected.name}</h2>
              <p className="text-xs text-gray-500 mt-1">{String(info.info?.description ?? "").slice(0, 400)}</p>
            </div>

            <div>
              <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Options</h3>
              <div className="space-y-1.5">
                {Object.entries<any>(info.options || {}).map(([key, opt]) => (
                  <div key={key} className="grid grid-cols-[120px_1fr_auto] items-center gap-2 text-xs">
                    <label className="font-mono text-gray-400">
                      {key}
                      {opt.required && <span className="text-danger">*</span>}
                    </label>
                    <input
                      value={optionValues[key] ?? ""}
                      onChange={(e) => setOptionValues((v) => ({ ...v, [key]: e.target.value }))}
                      className="bg-bg-tertiary border border-border rounded px-2 py-1 text-gray-200 font-mono"
                    />
                    <span className="text-gray-600">{opt.type}</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={execute}
              disabled={executing}
              className="bg-accent-dim hover:bg-accent text-black font-medium text-sm px-4 py-1.5 rounded disabled:opacity-50"
            >
              {executing ? "Running…" : "Execute"}
            </button>

            {execResult && (
              <pre className="bg-bg-secondary border border-border rounded p-3 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                {execResult}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
