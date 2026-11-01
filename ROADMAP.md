# Product Roadmap — Security Assessment Platform

## Product direction

This repository is being transformed from an MSF-centric web console into a
modular, local-first security assessment platform. Metasploit Framework remains
a first-class integration, but its responsibility is deliberately narrowed:
**Metasploit is the exploitation and post-exploitation engine, not the
platform's reconnaissance, asset-discovery, vulnerability-management, or
reporting foundation.**

The platform owns the assessment workflow and its data model. Independent
tools perform discovery and testing; their output is normalised into shared
assets, services, findings, and evidence. Metasploit is used when an operator
deliberately selects an appropriate exploitation action.

## Target architecture

```
React assessment workspace
          |
FastAPI platform API
          |
  Assessment orchestration
   |          |          |
Recon       Finding     Reporting
adapters    normaliser  and export
   |
httpx / WhatWeb / Katana / ffuf / Nuclei / Nmap / ...
   |
Shared assessment store
   |
Metasploit integration (explicit hand-off)
   |
Exploitation → Sessions → Post-exploitation evidence
```

Core platform contracts:
- Tool adapters own fixed command construction, validation, timeouts,
  cancellation, bounded output handling, and parser versions.
- Tool output is evidence, not automatically a vulnerability verdict.
- Findings use a common schema with target, asset, source, check, severity,
  confidence, evidence, timestamps, and status.
- Every execution is attributable to an assessment and records its tool,
  arguments (with secrets redacted), timestamps, exit status, and output.
- The UI never implies that an uninstalled or unexecuted tool has run.
- Active testing requires explicit authorization and remains separate from
  exploitation. The application remains local-only.

## Phase 0 — Preserve and separate the existing MSF capability

Status: existing functionality retained.

- Keep the Metasploit module browser, payload/encoder/NOP workflows, jobs,
  sessions, Meterpreter/shell interaction, database views, loot, CVE
  enrichment, and existing reports working.
- Treat these as the Metasploit integration and exploitation workspace.
- Avoid making general discovery or vulnerability workflows depend on
  Metasploit RPC or its database.
- Preserve the current local-only and authenticated security boundary.

## Phase 1 — Independent web reconnaissance adapters

Status: adapter implementation complete; validation and platform-wide normalisation remain in progress.

- [x] Web Security workspace and local tool availability inventory.
- [x] Built-in bounded HTTP response probe.
- [x] Fixed-argument httpx adapter with JSON result normalisation.
- [x] Fixed-argument WhatWeb adapter with structured plugin evidence.
- [x] Explicit authorization confirmation for each run.
- [x] Per-tool execution timeout and bounded output reading.
- [x] Unit tests for authorization, command construction, missing binaries,
      and output parsing.
- [ ] Verify httpx and WhatWeb CLI compatibility against the user's installed versions through local runtime smoke tests (CI uses mocks and cannot establish local binary compatibility).
- [x] Persist completed executions, timeouts, launch failures, parsed evidence, and bounded stderr in the assessment store.
- [x] Enforce wall-clock timeouts and combined stdout/stderr limits; terminate scanner process groups on timeout or output overflow.
- [x] Add a platform-owned SQLite assessment store independent of Metasploit's database, with assessment lifecycle and target-scope CRUD APIs.\n- [x] Require explicit authorization when registering targets; enforce exact scheme/host/port scope matching in the platform scope guard.\n- [x] Bind the built-in web probe, httpx, and WhatWeb executions to an active assessment and exact approved origin.\n- [x] Persist completed runs, timeouts, and launch failures with timestamps, exit status, parsed evidence, and bounded stderr.\n- [x] Expose assessment execution history and stored evidence in the Web Security workspace.\n- [x] Enforce a combined stdout/stderr capture ceiling and terminate the scanner process group when the ceiling is exceeded.
- [x] Enforce wall-clock timeouts with process-group termination so child processes do not outlive timed-out scans.
- [ ] Add an asynchronous execution-job lifecycle with polling, persisted running/cancelled states, and an operator-facing Cancel action; the process runner already accepts a cancellation signal.
- [ ] Persist parser-version metadata with each execution and its evidence.
- [x] Add a cancellation signal to the bounded process runner; it terminates the scanner process group and retains captured partial output. The operator-facing asynchronous job lifecycle is still outstanding.
- [x] Distinguish installed executables from implemented adapters in the tool catalogue. All 13 catalogued adapters now have fixed execution implementations; readiness still depends on the executable being installed.

## Phase 2 — Asset discovery and mapping

- [x] Add passive Subfinder discovery as a distinct workflow with bounded runtime/rate, structured output, provenance, and inventory persistence.
- [x] Add passive Amass enumeration as a separately constrained adapter; discovered names remain inventory leads and never become approved targets.
- [x] Add controlled crawling and endpoint discovery (Katana) with exact-origin scope, disabled redirects, JavaScript endpoint extraction, query deduplication, depth/page/time/request-rate limits, and endpoint provenance.
- [x] Add Gobuster directory/file enumeration with backend-allowlisted wordlists, exact-origin scope, fixed concurrency/request delay, validated extensions, disabled redirects, bounded runtime/output, and evidence persistence. DNS and virtual-host modes remain disabled.
- [x] Add content discovery (ffuf/Feroxbuster) with explicit wordlist,
      request-rate, and scope controls.
- [x] Add bounded Nmap network/service discovery as a separate adapter (TCP connect, top 100 ports, light service detection; no UDP, NSE, OS detection, or arbitrary port ranges).
- [x] Persist and deduplicate URL/host assets observed in HTTP probe, httpx, and WhatWeb evidence; track first/last seen and source tool.
- [ ] Expand the asset model to persist IPs, ports, and services (Nmap currently returns structured service evidence but does not yet populate a first-class service inventory).
- [x] Establish the first exact-origin target-scope boundary; extend it to discovered child assets through explicit scope expansion and approval.
- [x] Track discovered in-scope and out-of-scope URL/host assets; discovery never changes approved targets.
- [ ] Add an explicit review-and-approve workflow for expanding assessment scope; discovered assets remain out-of-scope until separately approved.

## Phase 3 — Vulnerability assessment

- [x] Add Nuclei as a template-driven HTTP scanner with backend-owned templates,
      rate limits, severity filters, disabled redirects/OAST, and evidence-only findings.
- [x] Add specialist web checks (Nikto, passive WPScan, and HTTPS-only testssl.sh) as bounded opt-in adapters.
- [x] Add an analyst-controlled evidence lifecycle with stable record IDs, review/dismiss/restore, notes, and evidence-versus-finding classification.
- [ ] Define a single platform-owned finding schema shared by all adapters; current parsers produce tool-specific evidence records.
- [ ] Correlate and deduplicate equivalent observations across tools while retaining every source and execution reference.
- [ ] Add consistent severity, confidence, verification state, and remediation fields without converting fingerprints or HTTP errors into vulnerability claims.

## Phase 4 — Analysis and prioritisation

- [ ] Correlate assets, services, software fingerprints, CVEs, and findings.
- [ ] Enrich CVEs from NVD without treating keyword matches as proof of impact.
- [ ] Build attack-path and exposure context from confirmed relationships.
- [x] Add triage states, analyst notes, dismissal/restore, and analyst-controlled finding/evidence classification.

## Phase 5 — Metasploit exploitation integration

- [ ] Keep Metasploit module browsing and execution as an explicit workflow.
- [ ] Hand selected findings to Metasploit with validated target context.
- [ ] Show why a module is suggested and distinguish compatibility from
      a successful module check or confirmed vulnerability.
- [ ] Require a separate operator action before exploitation.
- [ ] Preserve impact warnings, check-first behavior, job tracking, and
      outcome-unverified semantics.
- [ ] Link any resulting sessions and loot back to the originating finding.

## Phase 6 — Post-exploitation and evidence

- [ ] Contextual session guidance for Meterpreter versus shell sessions.
- [ ] Associate session activity and collected loot with the assessment.
- [ ] Preserve evidence provenance, timestamps, and integrity metadata.
- [ ] Keep post-exploitation actions visibly separate from discovery.

## Phase 7 — Reporting and workflow polish

- [x] Add assessment-wide evidence search, filtering, sorting, bulk triage, record detail, clipboard copy, and JSON/CSV export.
- [x] Add run-to-run comparison and historical execution/triage summaries.

- [ ] Produce platform-wide reports spanning assets, findings, evidence,
      exploitation outcomes, and remediation.
- [x] Add assessment lifecycle and persisted approved target scope.
- [ ] Add reusable assessment configurations and scope templates.
- [ ] Add onboarding and a persistent security terminology glossary.
- [ ] Add export formats and report templates.

## Engineering constraints

- Work directly on `main`; do not create feature branches unless explicitly
  requested.
- Keep the application local-only until a separate security review approves
  any change to its trust boundary.
- Do not install tools automatically. Detect availability and explain setup.
- Never invoke a shell to build tool commands; use fixed executable paths
  and argument arrays.
- Keep scanner execution independent of Metasploit RPC.
- Test parser behavior with fixtures from real tool versions and mock process
  execution in unit tests.
- Update this roadmap and the changelog as implementation progresses.
