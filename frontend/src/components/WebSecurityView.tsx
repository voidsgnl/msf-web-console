import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../lib/api";

type Tool = { id: string; name: string; category: string; purpose: string; installed: boolean; path?: string | null };
type Probe = {
  target: string; status_code: number; reason?: string; final_url: string; redirect_location?: string | null;
  title?: string | null; headers: Record<string, string>; technologies: string[];
  content_type?: string | null; body_truncated: boolean; bytes_inspected: number; assessment: string;
};
const CATEGORIES = ["HTTP probing","Technology fingerprinting","Crawling","Content discovery","Subdomain discovery","Asset discovery","TLS analysis","Network discovery","Vulnerability scanning","Web server checks","CMS assessment"];

export function WebSecurityView() {
  const [tools,setTools]=useState<Tool[]>([]);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState<string|null>(null);
  const [target,setTarget]=useState("");
  const [authorized,setAuthorized]=useState(false);
  const [probing,setProbing]=useState(false);
  const [probe,setProbe]=useState<Probe|null>(null);
  const [probeError,setProbeError]=useState<string|null>(null);
  const loadTools=async()=>{setLoading(true);setError(null);try{setTools((await api.webRecon.tools()).tools);}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setLoading(false);}};
  useEffect(()=>{void loadTools();},[]);
  const groups=useMemo(()=>CATEGORIES.map(category=>({category,items:tools.filter(tool=>tool.category===category)})).filter(group=>group.items.length),[tools]);
  const runProbe=async(event:FormEvent)=>{event.preventDefault();if(!authorized||!target.trim()||probing)return;setProbing(true);setProbe(null);setProbeError(null);try{setProbe(await api.webRecon.probe(target.trim(),true));}catch(e){setProbeError(e instanceof Error?e.message:String(e));}finally{setProbing(false);}};
  return <div className="h-full overflow-y-auto bg-bg-primary p-4 md:p-6"><div className="mx-auto max-w-7xl space-y-5">
    <header><div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">Web assessment</div><div className="mt-1 flex flex-wrap items-end justify-between gap-3"><div><h1 className="text-xl font-semibold text-gray-100">Web Security</h1><p className="mt-1 max-w-3xl text-sm text-gray-400">Discover web services and prepare structured findings for deeper investigation in Metasploit.</p></div><div className="flex gap-2"><span className="badge badge-accent">{tools.filter(t=>t.installed).length} tools installed</span><span className="badge">{tools.length} integrations catalogued</span></div></div></header>
    <div role="note" className="flex gap-3 rounded-lg border border-warning/30 bg-warning/5 px-4 py-3"><span className="mt-0.5 text-warning">◆</span><div><p className="text-xs font-semibold text-warning">Authorised targets only</p><p className="mt-1 text-xs leading-relaxed text-gray-400">Only assess systems you own or have explicit permission to test. The first probe sends one HTTP GET request, does not follow redirects, and does not crawl or test for vulnerabilities.</p></div></div>
    <section className="card"><div className="card-header"><div><h2 className="text-sm font-semibold text-gray-100">Initial web probe</h2><p className="mt-1 text-xs text-gray-500">Response status, selected headers, page title, and basic technology hints.</p></div><span className="badge badge-info">Built-in · single request</span></div>
      <form onSubmit={e=>void runProbe(e)} className="space-y-3 p-4"><label className="block"><span className="mb-1.5 block text-xs font-medium text-gray-300">Target URL</span><input className="input" value={target} onChange={e=>setTarget(e.target.value)} placeholder="https://your-authorised-domain.test" autoComplete="url" spellCheck={false} maxLength={2048}/></label>
        <label className="flex items-start gap-2 text-xs leading-relaxed text-gray-400"><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)} className="mt-0.5"/><span>I own this target or have explicit permission to send it a web request.</span></label>
        <div className="flex flex-wrap items-center gap-3"><button type="submit" className="btn btn-primary" disabled={!authorized||!target.trim()||probing}>{probing?"Probing…":"Probe web service"}</button>{probe&&<span className="text-xs text-gray-500">Inspected {probe.bytes_inspected.toLocaleString()} bytes · 64 KB cap</span>}</div>
        {probeError&&<div role="alert" className="rounded-md border border-danger/30 bg-danger/5 p-3 text-xs text-danger">{probeError}</div>}
      </form>
    </section>
    {probe&&<section className="card"><div className="card-header"><div><h2 className="text-sm font-semibold text-gray-100">Probe result</h2><p className="mt-1 break-all font-mono text-xs text-gray-500">{probe.final_url}</p></div><span className={`badge ${probe.status_code>=500?"badge-danger":probe.status_code>=400?"badge-warning":"badge-accent"}`}>HTTP {probe.status_code} {probe.reason??""}</span></div>
      <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-4">{[["Page title",probe.title||"Not detected"],["Content type",probe.content_type||"Not provided"],["Redirect",probe.redirect_location||"None"],["Technology hints",probe.technologies.join(", ")||"No clear fingerprint"]].map(([label,value])=><div key={String(label)} className="rounded-md border border-border bg-bg-primary p-3"><div className="text-[10px] uppercase tracking-wider text-gray-500">{label}</div><div className="mt-1 break-words text-sm text-gray-200">{value}</div></div>)}</div>
      <div className="border-t border-border px-4 py-3 text-xs leading-relaxed text-gray-400">{probe.assessment}</div>
      {!!Object.keys(probe.headers).length&&<div className="border-t border-border p-4"><h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">Selected response headers</h3><dl className="grid gap-2 sm:grid-cols-2">{Object.entries(probe.headers).map(([key,value])=><div key={key} className="min-w-0 rounded bg-bg-primary p-2"><dt className="text-[10px] uppercase text-gray-500">{key}</dt><dd className="mt-1 break-all font-mono text-xs text-gray-300">{value}</dd></div>)}</dl></div>}
    </section>}
    <section className="card"><div className="card-header"><div><h2 className="text-sm font-semibold text-gray-100">Reconnaissance toolchain</h2><p className="mt-1 text-xs text-gray-500">Checks executable availability only; no tool is launched.</p></div><button type="button" className="btn btn-sm" onClick={()=>void loadTools()} disabled={loading}>Refresh</button></div>
      {error&&<div role="alert" className="m-4 rounded-md border border-danger/30 bg-danger/5 p-3 text-xs text-danger">{error}</div>}
      {loading?<div className="p-5 text-xs text-gray-500">Checking local tool availability…</div>:<div className="grid gap-4 p-4 md:grid-cols-2 xl:grid-cols-3">{groups.map(group=><div key={group.category} className="rounded-lg border border-border bg-bg-primary p-3"><h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-gray-500">{group.category}</h3><div className="space-y-3">{group.items.map(tool=><div key={tool.id} className="flex items-start justify-between gap-3"><div className="min-w-0"><div className="text-xs font-medium text-gray-200">{tool.name}</div><p className="mt-0.5 text-[11px] leading-relaxed text-gray-500">{tool.purpose}</p>{tool.installed&&<p className="mt-1 truncate font-mono text-[10px] text-gray-600" title={tool.path??""}>{tool.path}</p>}</div><span className={`badge shrink-0 ${tool.installed?"badge-accent":""}`}>{tool.installed?"Installed":"Missing"}</span></div>)}</div></div>)}</div>}
    </section>
    <div className="rounded-lg border border-border bg-bg-secondary px-4 py-3 text-xs leading-relaxed text-gray-500">Next: connect selected tools through fixed command adapters, capture structured output, normalise evidence, and correlate findings with Metasploit modules. No tool is auto-installed or executed by this workspace yet.</div>
  </div></div>;
}
