import { useState } from "react";
import type { ReactNode } from "react";

type Recipe = {
  id: string; title: string; category: string; summary: string; purpose: string;
  moduleType: string; module: string; steps: string[]; note: string;
};

const RECIPES: Recipe[] = [
  { id:"tcp", title:"Discover TCP services", category:"Discovery",
    summary:"Identify reachable TCP ports on a lab host before choosing a focused test.",
    purpose:"Build an initial picture of exposed TCP ports. This does not identify software versions.",
    moduleType:"auxiliary", module:"scanner/portscan/tcp",
    steps:["Enter the authorized lab host or range in RHOSTS.","Choose a narrow port range appropriate to the exercise.","Review open ports, then use a version-detection recipe for a service of interest."],
    note:"A port scan creates network traffic and may be logged. Use only against systems you own or are explicitly authorized to assess." },
  { id:"ftp", title:"Identify an FTP service", category:"Service identification",
    summary:"Collect the banner and version information exposed by an FTP service.",
    purpose:"Confirm whether an FTP service is present and collect its banner. A banner is evidence, not proof of a vulnerability.",
    moduleType:"auxiliary", module:"scanner/ftp/ftp_version",
    steps:["Set RHOSTS to the lab host.","Set RPORT if the service uses a non-standard port.","Run the scanner and record the returned product/version banner."],
    note:"This sends a protocol-level request to the selected FTP service. Do not scan third-party systems." },
  { id:"http", title:"Identify an HTTP service", category:"Service identification",
    summary:"Collect HTTP server and application response details from a lab web service.",
    purpose:"Gather the server banner and basic HTTP response metadata to guide further manual investigation.",
    moduleType:"auxiliary", module:"scanner/http/http_version",
    steps:["Set RHOSTS to the lab host.","Set RPORT and SSL to match the service.","Review response headers and version information; treat missing banners as inconclusive."],
    note:"This makes an HTTP request to the target. It does not establish that the web server is vulnerable." },
  { id:"smb", title:"Identify an SMB service", category:"Service identification",
    summary:"Query SMB service details on a Windows or Samba lab host.",
    purpose:"Collect SMB protocol and version information before deciding whether a deeper, authorized assessment is warranted.",
    moduleType:"auxiliary", module:"scanner/smb/smb_version",
    steps:["Set RHOSTS to the lab host.","Set RPORT if SMB is exposed on a non-standard port.","Review returned OS, product, and version details where available."],
    note:"SMB probes can be visible to monitoring systems. Use only in an authorized lab or assessment." },
];

function Section({title,children}:{title:string;children:ReactNode}) {
  return <section className="rounded-lg border border-border bg-bg-secondary/60 p-4">
    <h3 className="text-[10px] font-semibold uppercase tracking-widest text-gray-500">{title}</h3>
    <div className="mt-2">{children}</div>
  </section>;
}

export function RecipesView({onOpenModule}:{onOpenModule:(type:string,query:string)=>void}) {
  const [selectedId,setSelectedId]=useState(RECIPES[0].id);
  const selected=RECIPES.find(recipe=>recipe.id===selectedId) ?? RECIPES[0];
  return <div className="h-full overflow-y-auto bg-bg-primary p-4 md:p-6">
    <div className="mx-auto max-w-6xl">
      <div className="mb-5">
        <div className="text-[10px] uppercase tracking-[0.2em] text-accent">Guided workflows</div>
        <h1 className="mt-1 text-xl font-semibold text-gray-100">Recipes</h1>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-gray-400">Start with a focused lab task instead of an empty module browser. Each recipe explains the goal, gives you a short sequence, and opens the relevant Metasploit module for review and configuration.</p>
      </div>
      <div className="mb-4 rounded border border-warning/30 bg-warning/5 px-4 py-3">
        <p className="text-xs font-semibold text-warning">Authorized targets only</p>
        <p className="mt-1 text-xs leading-relaxed text-gray-400">These workflows send real requests to the hosts you configure. Use them only on systems you own or have explicit permission to test. Nothing runs automatically when you open a recipe.</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(240px,0.8fr)_minmax(0,1.5fr)]">
        <div className="space-y-2">{RECIPES.map(recipe=><button key={recipe.id} type="button" onClick={()=>setSelectedId(recipe.id)}
          className={"w-full rounded-lg border p-3 text-left transition-colors " + (selectedId===recipe.id ? "border-accent/50 bg-accent/5" : "border-border bg-bg-secondary hover:border-gray-500")}>
          <span className="block text-[10px] uppercase tracking-widest text-gray-500">{recipe.category}</span>
          <span className="mt-1 block text-sm font-medium text-gray-100">{recipe.title}</span>
          <span className="mt-1 block text-xs leading-relaxed text-gray-400">{recipe.summary}</span>
        </button>)}</div>
        <div className="space-y-3">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="text-[10px] uppercase tracking-widest text-accent">{selected.category}</div>
            <h2 className="mt-1 text-lg font-semibold text-gray-100">{selected.title}</h2>
            <p className="mt-2 text-sm leading-relaxed text-gray-300">{selected.purpose}</p>
            <div className="mt-4 rounded border border-border bg-bg-primary p-3">
              <div className="text-[10px] uppercase tracking-widest text-gray-500">Metasploit module</div>
              <div className="mt-1 break-all font-mono text-xs text-accent">{selected.module}</div>
              <button type="button" onClick={()=>onOpenModule(selected.moduleType,selected.module)} className="mt-3 rounded bg-accent-dim px-3 py-2 text-xs font-medium text-black hover:bg-accent">Open module in browser</button>
            </div>
          </div>
          <Section title="Workflow"><ol className="space-y-2">{selected.steps.map((step,index)=><li key={step} className="flex gap-3 text-xs leading-relaxed text-gray-300">
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border font-mono text-[10px] text-accent">{index+1}</span><span>{step}</span>
          </li>)}</ol></Section>
          <Section title="Before you run it"><p className="text-xs leading-relaxed text-gray-400">{selected.note}</p>
            <p className="mt-2 text-xs text-gray-500">Review the module description, required options, and side-effect metadata in the Module Browser. Execution always requires your separate action there.</p>
          </Section>
        </div>
      </div>
    </div>
  </div>;
}
