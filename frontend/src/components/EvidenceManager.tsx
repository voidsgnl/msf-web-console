import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { AssessmentExecution, AssessmentExecutionRecord } from "../lib/api";

type RecordItem = AssessmentExecutionRecord & {
  execution_id: number;
  tool_id: string;
  target_url: string;
  started_at: string;
  finished_at: string;
  exit_code: number;
};
type Props = { assessmentId: number; executions: AssessmentExecution[]; onRefresh: () => void };

function downloadFile(name: string, type: string, value: string) {
  const blob = new Blob([value], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function EvidenceManager({ assessmentId, executions, onRefresh }: Props) {
  const [records, setRecords] = useState<RecordItem[]>([]);
  const [query, setQuery] = useState("");
  const [toolFilter, setToolFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [reviewFilter, setReviewFilter] = useState("");
  const [sortBy, setSortBy] = useState("newest");
  const [selected, setSelected] = useState<string[]>([]);
  const [detail, setDetail] = useState<RecordItem | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [history, setHistory] = useState<Awaited<ReturnType<typeof api.assessments.history>> | null>(null);
  const [baselineId, setBaselineId] = useState("");
  const [comparisonId, setComparisonId] = useState("");
  const [comparison, setComparison] = useState<Awaited<ReturnType<typeof api.assessments.compareRuns>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setError(null);
    try {
      const [result, report] = await Promise.all([
        api.assessments.records(assessmentId),
        api.assessments.history(assessmentId),
      ]);
      setRecords(result.records);
      setHistory(report);
      setSelected(current => current.filter(id => result.records.some(record => record.record_id === id)));
      setDetail(current => current ? result.records.find(record => record.record_id === current.record_id) ?? null : null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => { void refresh(); }, [assessmentId]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return records.filter(record => {
      if (needle && !JSON.stringify(record).toLowerCase().includes(needle)) return false;
      if (toolFilter && record.tool_id !== toolFilter) return false;
      if (typeFilter && record.record_type !== typeFilter) return false;
      if (stateFilter && record.review_state !== stateFilter) return false;
      if (reviewFilter === "reviewed" && !record.reviewed_at) return false;
      if (reviewFilter === "unreviewed" && record.reviewed_at) return false;
      return true;
    }).sort((a, b) => {
      if (sortBy === "oldest") return a.started_at.localeCompare(b.started_at);
      if (sortBy === "tool") return a.tool_id.localeCompare(b.tool_id) || b.started_at.localeCompare(a.started_at);
      if (sortBy === "target") return a.target_url.localeCompare(b.target_url) || b.started_at.localeCompare(a.started_at);
      return b.started_at.localeCompare(a.started_at);
    });
  }, [records, query, toolFilter, typeFilter, stateFilter, reviewFilter, sortBy]);

  const tools = useMemo(() => Array.from(new Set(records.map(item => item.tool_id))).sort(), [records]);
  const allVisibleSelected = filtered.length > 0 && filtered.every(item => selected.includes(item.record_id));

  const mutate = async (operation: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await operation();
      await refresh();
      onRefresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const bulkUpdate = (changes: { review_state?: "active" | "dismissed"; reviewed?: boolean; record_type?: "evidence" | "finding" }) => {
    if (!selected.length) return;
    void mutate(() => api.assessments.bulkUpdateRecords(assessmentId, selected, changes));
  };

  const bulkDelete = () => {
    if (!selected.length || !window.confirm("Permanently delete " + selected.length + " selected records? This cannot be undone.")) return;
    void mutate(() => api.assessments.bulkDeleteRecords(assessmentId, selected));
    setSelected([]);
    if (detail && selected.includes(detail.record_id)) setDetail(null);
  };

  const updateOne = (record: RecordItem, changes: { review_state?: "active" | "dismissed"; reviewed?: boolean; notes?: string; record_type?: "evidence" | "finding" }) => {
    void mutate(() => api.assessments.updateExecutionRecord(assessmentId, record.execution_id, record.record_id, changes));
  };

  const copyRecords = async (items: RecordItem[]) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(items, null, 2));
    } catch {
      setError("Clipboard access was blocked by the browser.");
    }
  };

  const exportRecords = (items: RecordItem[], format: "json" | "csv") => {
    if (format === "json") {
      downloadFile("assessment-" + assessmentId + "-records.json", "application/json", JSON.stringify(items, null, 2));
      return;
    }
    const columns = ["record_id", "record_type", "tool_id", "execution_id", "target_url", "started_at", "review_state", "reviewed_at", "notes", "record"];
    const escape = (value: unknown) => '"' + String(value ?? "").replace(/"/g, '""') + '"';
    const rows = items.map(item => columns.map(column => escape(column === "record" ? JSON.stringify(Object.fromEntries(Object.entries(item).filter(([key]) => !["record_id", "record_type", "tool_id", "execution_id", "target_url", "started_at", "review_state", "reviewed_at", "notes"].includes(key)))) : (item as Record<string, unknown>)[column])).join(","));
    downloadFile("assessment-" + assessmentId + "-records.csv", "text/csv;charset=utf-8", [columns.join(","), ...rows].join("\n"));
  };

  const runCompare = async () => {
    if (!baselineId || !comparisonId) return;
    setBusy(true);
    setError(null);
    try {
      setComparison(await api.assessments.compareRuns(assessmentId, Number(baselineId), Number(comparisonId)));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const chooseDetail = (record: RecordItem) => {
    setDetail(record);
    setNoteDraft(record.notes);
  };
  const comparisonGroups: { label: string; items: Record<string, unknown>[] }[] = comparison ? [
    { label: "Added", items: comparison.added },
    { label: "Removed", items: comparison.removed },
    { label: "Unchanged", items: comparison.unchanged },
  ] : [];

  return <section className="card">
    <div className="card-header">
      <div><h2 className="text-sm font-semibold text-gray-100">Findings & evidence</h2><p className="mt-1 text-xs text-gray-500">Assessment-wide triage, search, comparison, and export. Scanner output starts as evidence, not a vulnerability verdict.</p></div>
      <button type="button" className="btn btn-sm" onClick={() => void refresh()} disabled={busy}>Refresh</button>
    </div>
    {history && <div className="grid grid-cols-2 gap-2 border-b border-border p-4 sm:grid-cols-5">
      {[[ "Runs", history.total_runs ],[ "Records", history.total_records ],[ "Findings", history.findings ],[ "Evidence", history.evidence ],[ "Reviewed", history.reviewed ]].map(([label, value]) => <div key={String(label)} className="rounded-md bg-bg-primary p-3"><div className="text-[10px] uppercase tracking-wide text-gray-500">{label}</div><div className="mt-1 text-lg font-semibold text-gray-100">{value}</div></div>)}
    </div>}
    {error && <div role="alert" className="m-4 rounded border border-danger/30 bg-danger/5 p-3 text-xs text-danger">{error}</div>}
    <div className="space-y-3 border-b border-border p-4">
      <input className="input w-full" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search across evidence, URLs, notes, status, and tool output…" />
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        <select className="input" value={toolFilter} onChange={event => setToolFilter(event.target.value)}><option value="">All tools</option>{tools.map(tool => <option key={tool} value={tool}>{tool}</option>)}</select>
        <select className="input" value={typeFilter} onChange={event => setTypeFilter(event.target.value)}><option value="">Findings & evidence</option><option value="finding">Findings</option><option value="evidence">Evidence</option></select>
        <select className="input" value={stateFilter} onChange={event => setStateFilter(event.target.value)}><option value="">All states</option><option value="active">Active</option><option value="dismissed">Dismissed</option></select>
        <select className="input" value={reviewFilter} onChange={event => setReviewFilter(event.target.value)}><option value="">Reviewed & unreviewed</option><option value="reviewed">Reviewed</option><option value="unreviewed">Unreviewed</option></select>
        <select className="input" value={sortBy} onChange={event => setSortBy(event.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="tool">Tool</option><option value="target">Target</option></select>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2 text-xs text-gray-400"><input type="checkbox" checked={allVisibleSelected} onChange={event => setSelected(event.target.checked ? Array.from(new Set([...selected, ...filtered.map(item => item.record_id)])) : selected.filter(id => !filtered.some(item => item.record_id === id))} />Select visible ({filtered.length})</label>
        <span className="text-[11px] text-gray-500">{filtered.length} of {records.length} records · {selected.length} selected</span>
      </div>
      {selected.length > 0 && <div className="flex flex-wrap gap-2 rounded-md bg-bg-primary p-3">
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => bulkUpdate({ reviewed: true })}>Mark reviewed</button>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => bulkUpdate({ review_state: "dismissed" })}>Dismiss</button>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => bulkUpdate({ review_state: "active" })}>Restore</button>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => bulkUpdate({ record_type: "finding" })}>Classify as finding</button>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => bulkUpdate({ record_type: "evidence" })}>Classify as evidence</button>
        <button type="button" className="btn btn-sm" onClick={() => void copyRecords(filtered.filter(item => selected.includes(item.record_id)))}>Copy selected</button>
        <button type="button" className="btn btn-sm" onClick={() => exportRecords(filtered.filter(item => selected.includes(item.record_id)), "json")}>Export JSON</button>
        <button type="button" className="btn btn-sm" onClick={() => exportRecords(filtered.filter(item => selected.includes(item.record_id)), "csv")}>Export CSV</button>
        <button type="button" className="btn btn-sm text-danger" disabled={busy} onClick={bulkDelete}>Delete selected</button>
      </div>}
    </div>
    <div className="grid min-h-[360px] lg:grid-cols-[minmax(0,1fr)_minmax(300px,0.85fr)]">
      <div className="divide-y divide-border">
        {filtered.map(record => <article key={record.record_id} className={"flex gap-3 p-3 " + (detail?.record_id === record.record_id ? "bg-bg-secondary" : "")}>
          <input aria-label={"Select record " + record.record_id} type="checkbox" checked={selected.includes(record.record_id)} onChange={event => setSelected(current => event.target.checked ? [...current, record.record_id] : current.filter(id => id !== record.record_id))} />
          <button type="button" className="min-w-0 flex-1 text-left" onClick={() => chooseDetail(record)}>
            <div className="flex flex-wrap items-center gap-2"><span className="badge">{record.record_type}</span><span className={"badge " + (record.review_state === "dismissed" ? "badge-warning" : "badge-accent")}>{record.review_state}</span>{record.reviewed_at && <span className="badge">Reviewed</span>}<span className="text-[10px] text-gray-500">{record.tool_id} · run #{record.execution_id}</span></div>
            <div className="mt-1 break-all font-mono text-xs text-gray-200">{String(record.url ?? record.target ?? record.host ?? record.path ?? record.raw ?? "Structured record")}</div>
            <div className="mt-1 text-[10px] text-gray-500">{new Date(record.started_at).toLocaleString()} · {record.target_url}</div>
            {record.notes && <p className="mt-1 truncate text-[11px] text-gray-400">Note: {record.notes}</p>}
          </button>
        </article>)}
        {!filtered.length && <p className="p-6 text-xs text-gray-500">No records match these filters.</p>}
      </div>
      <aside className="border-t border-border bg-bg-primary p-4 lg:border-l lg:border-t-0">
        {detail ? <div className="space-y-3">
          <div className="flex items-center justify-between gap-2"><h3 className="text-sm font-semibold text-gray-100">Record detail</h3><button type="button" className="btn btn-sm" onClick={() => setDetail(null)}>Close</button></div>
          <div className="flex flex-wrap gap-2"><span className="badge">{detail.tool_id}</span><span className="badge">Run #{detail.execution_id}</span><span className="badge">{detail.record_type}</span></div>
          <p className="break-all font-mono text-xs text-gray-300">{detail.target_url}</p>
          <div className="grid grid-cols-2 gap-2 text-[10px] text-gray-500"><div>Started<br/>{new Date(detail.started_at).toLocaleString()}</div><div>Finished<br/>{new Date(detail.finished_at).toLocaleString()}</div></div>
          <label className="block text-xs text-gray-400">Classification<select className="input mt-1 w-full" value={detail.record_type} onChange={event => updateOne(detail, { record_type: event.target.value as "finding" | "evidence" })}><option value="evidence">Evidence</option><option value="finding">Finding (analyst classified)</option></select></label>
          <label className="block text-xs text-gray-400">Analyst notes<textarea className="input mt-1 min-h-24 w-full" maxLength={4000} value={noteDraft} onChange={event => setNoteDraft(event.target.value)} /></label>
          <button type="button" className="btn btn-primary w-full" disabled={busy || noteDraft === detail.notes} onClick={() => updateOne(detail, { notes: noteDraft })}>Save notes</button>
          <div className="flex flex-wrap gap-2"><button type="button" className="btn btn-sm" disabled={busy} onClick={() => updateOne(detail, { reviewed: !detail.reviewed_at })}>{detail.reviewed_at ? "Mark unreviewed" : "Mark reviewed"}</button><button type="button" className="btn btn-sm" disabled={busy} onClick={() => updateOne(detail, { review_state: detail.review_state === "dismissed" ? "active" : "dismissed" })}>{detail.review_state === "dismissed" ? "Restore" : "Dismiss"}</button><button type="button" className="btn btn-sm" onClick={() => void copyRecords([detail])}>Copy record</button><button type="button" className="btn btn-sm" onClick={() => exportRecords([detail], "json")}>Export record</button></div>
          <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded bg-bg-secondary p-3 text-[11px] text-gray-300">{JSON.stringify(Object.fromEntries(Object.entries(detail).filter(([key]) => !["record_id", "record_type", "review_state", "reviewed_at", "notes", "execution_id", "tool_id", "target_url", "started_at", "finished_at", "exit_code"].includes(key))), null, 2)}</pre>
        </div> : <p className="text-xs text-gray-500">Select a record to inspect its full structured data, classify it, and update analyst notes.</p>}
      </aside>
    </div>
    <div className="space-y-3 border-t border-border p-4">
      <div><h3 className="text-xs font-semibold text-gray-200">Run comparison</h3><p className="mt-1 text-[11px] text-gray-500">Compare stored output from two executions in this assessment. Results are compared as structured records, not vulnerability verdicts.</p></div>
      <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
        <select className="input" value={baselineId} onChange={event => setBaselineId(event.target.value)}><option value="">Baseline run…</option>{executions.map(run => <option key={run.id} value={run.id}>#{run.id} {run.tool_id} · {new Date(run.started_at).toLocaleString()}</option>)}</select>
        <select className="input" value={comparisonId} onChange={event => setComparisonId(event.target.value)}><option value="">Compare with…</option>{executions.map(run => <option key={run.id} value={run.id}>#{run.id} {run.tool_id} · {new Date(run.started_at).toLocaleString()}</option>)}</select>
        <button type="button" className="btn btn-primary" disabled={busy || !baselineId || !comparisonId || baselineId === comparisonId} onClick={() => void runCompare()}>Compare runs</button>
      </div>
      {comparison && <div className="grid gap-2 sm:grid-cols-3">
        {comparisonGroups.map(group => <div key={group.label} className="rounded-md bg-bg-primary p-3"><div className="text-xs font-semibold text-gray-200">{group.label} ({group.items.length})</div><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all text-[10px] text-gray-500">{JSON.stringify(group.items, null, 2)}</pre></div>)}
      </div>}
      {history && <div className="rounded-md bg-bg-primary p-3"><h3 className="text-xs font-semibold text-gray-200">Historical activity by tool</h3><div className="mt-2 space-y-2">{history.by_tool.map(item => <div key={item.tool_id} className="flex flex-wrap justify-between gap-2 text-[11px] text-gray-400"><span>{item.tool_id}</span><span>{item.runs} runs · {item.successful_runs} successful · last {new Date(item.last_run).toLocaleString()}</span></div>)}</div></div>}
    </div>
  </section>;
}
