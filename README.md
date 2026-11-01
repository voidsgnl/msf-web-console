# Security Assessment Platform

A local-first security assessment platform being built around independent
reconnaissance, asset discovery, vulnerability assessment, finding analysis,
and reporting workflows. Metasploit Framework is retained as a dedicated
exploitation and post-exploitation integration — it is not the platform's
general-purpose scanner or orchestration foundation.

FastAPI backend + React/TypeScript frontend. Scanner adapters execute locally
on the backend host; the Metasploit integration communicates with the user's
own local `msfrpcd`. There is no remote/hosted component.

## Architecture

```
React assessment workspace
          |
       FastAPI
          |
 Assessment orchestration
   |          |          |
Recon       Findings   Reporting
adapters    normaliser and export
   |
httpx / WhatWeb / future independent tools
   |
Shared assessment data
   |
Explicit hand-off to Metasploit
   |
Exploitation → Sessions → Post-exploitation
```

Reconnaissance and vulnerability-assessment adapters are independent of
Metasploit RPC. Tool output is stored as evidence and is not automatically
treated as a confirmed vulnerability. Metasploit is invoked only through
deliberate operator workflows for exploitation and related session handling.
The existing Metasploit console, module, jobs, sessions, database, loot, and
reporting capabilities are being preserved during the transformation.

See [ROADMAP.md](ROADMAP.md) for the target architecture and implementation
phases.

## Status

**v0.1 — vertical slice.** Implemented:

- Independent assessment foundation: platform-owned assessments and target scope persist in a local SQLite database (separate from Metasploit's database), with assessment lifecycle states, explicit authorization before target registration, duplicate-target protection, and exact scheme/host/port scope checks. The API is available under `/api/assessments`; set `ASSESSMENT_DATABASE_PATH` to override the default `backend/data/assessments.sqlite3` location.
- Assessment-scoped reconnaissance: create/select assessments in the Web Security workspace, register explicitly authorised targets, and run the built-in HTTP probe, httpx, WhatWeb, passive Subfinder, or controlled Katana crawling only against an explicitly approved target. Active HTTP tools require an exact approved origin (scheme, host, and port). Katana is restricted to that exact origin, depth 3, JavaScript endpoint extraction, page/API/redirect/static-resource classification, Next.js framework-resource and framework-redirect classification, identical method+URL deduplication with query variants retained, malformed encoded-backslash path flagging, hidden-by-default static assets, framework redirects, and malformed discoveries (still retained in stored evidence), explicit unverified-link labels, and a 100-page cap, 2 requests/second, a 90-second crawl duration, and a 1 MiB per-response read limit. The adapter uses Katana's supported `-fr` output filter for narrow URL suppression and keeps the final inventory aligned with the app's own classification rules so malformed candidates are not promoted into the default endpoint list while legitimate script-derived evidence remains available. The starting URL is preflighted through same-origin redirects only (maximum five); cross-origin redirect destinations are not followed. Redirects encountered on pages during the crawl remain disabled. Katana’s default host scope remains enabled; the adapter does not use its `-ns` no-scope option. Each completed scanner run, timeout, or launch failure is persisted with timestamps, exit status, parsed evidence, and bounded stderr; the latest 100 runs are listed in the workspace and their stored evidence can be reopened. URL and host assets are deduplicated into an assessment inventory with first/last-seen timestamps and source provenance. Discovered subdomains and endpoints remain unapproved until explicitly added to scope. Discoveries never expand the approved target list. Tool output remains evidence, not a confirmed vulnerability verdict.
- Independent reconnaissance foundation: local tool inventory, a bounded built-in HTTP probe, and explicit httpx/WhatWeb command adapters with fixed argument construction, authorization confirmation, execution timeouts, bounded output inspection, and structured evidence parsing. These adapters do not depend on Metasploit RPC and do not claim vulnerability status
- Live console (xterm.js) bridged to a real `msfconsole` instance, tabbed
  for multiple concurrent consoles
- Module search/browse across exploit, auxiliary, post, payload, encoder,
  nop
- Module info + option editing + execution for exploit, auxiliary, and post
  modules, including required-option checks, job/UUID tracking, explicit unverified
  outcomes when result retrieval fails, tracking timeouts that never cancel
  the Metasploit job, returned result display, and new-session detection
- Payload generation with a binary-safe artifact download
- Dedicated encoder workflow: encode supplied text, hex, or Base64 input with a selected Metasploit encoder, optional bad-character filtering, architecture/platform settings, iterations, and encoder-supported options; encoded output downloads as a raw binary artifact
- Dedicated NOP workflow: generate an architecture-specific NOP sled with a selected Metasploit NOP module, optional bad-character exclusions and save-register hints, then download the raw binary artifact. Uses a temporary authenticated Metasploit console because standard RPC exposes NOP listing/inspection but no direct NOP-generation method
- Target-aware compatible payload browsing and selection, including payload
  option editing before exploit execution
- Scan-to-module target context: opening a module or a matching exploit from scan results pre-fills declared `RHOSTS`/`RHOST` and `RPORT` options; route-aware local address detection suggests `LHOST` for the selected target. A supplied hostname is preserved separately from the connection IP and is passed as `VHOST` only when the selected module declares it. Auto-filled values are labeled by source and remain editable. No module runs automatically.
- Web-edge awareness: HTTP observations identify Cloudflare as an edge provider rather than the origin application, classify HTTP 403 as access denied (not a vulnerability verdict), and restrict edge-only recommendations to generic HTTP reconnaissance modules (never application-specific exploits without a product fingerprint). HTTPS version detection supports alternate TLS ports such as 8443 and passes a known virtual hostname when the detection module declares `VHOST`. Module checks allow up to 60 seconds; a timeout is reported as inconclusive, never as a safe/vulnerable verdict.
- Session list + kill + interactive session shell/meterpreter terminal
- Jobs list + stop
- Database explorer: hosts, services, vulnerabilities, loot, and credentials, with cross-record search, field/value filtering, record inspection, host-to-service/vulnerability navigation, and JSON metadata export; sensitive fields are redacted by default
- CVE/NVD enrichment: vulnerability records are scanned for CVE identifiers (in `refs` or elsewhere in the record), which can be looked up against the National Vulnerability Database for CVSS score, severity, description, and reference links. Lookups are self-throttled to stay under NVD's public rate limit and cached server-side; set `NVD_API_KEY` in `backend/.env` for a higher limit. Requires outbound network access from the backend to `services.nvd.nist.gov`.
- Assessment report for the active workspace: executive summary, severity counts, database-record-based vulnerability findings, affected-host summary, remediation guidance, open-service exposure observations, and sanitized inventory tables. Export a native PDF directly from the backend or download the HTML snapshot. Credential values, common filesystem paths, artifact bytes, and download references are filtered.
- Guided Recipes view with four documented lab workflows: TCP discovery and FTP, HTTP, and SMB service identification. Each explains the workflow and opens the relevant module for review; recipes never execute automatically.
- Phase 3 safety rails: higher-impact modules require explicit confirmation; module execution surfaces an authorized-target reminder; exploit and auxiliary modules offer a separate Check-first action where supported, with the verdict and raw output shown before any full run.
- Loot evidence browser: search records, inspect all returned metadata, copy a record, and export one or filtered records as JSON
- Loot artifact download: retrieve inline artifact data from the Framework `db.loots` RPC response or, when RPC returns metadata only, read the associated file only when its exact path or containing directory is allowlisted in backend configuration; browser-supplied filesystem paths are never accepted
- Workspace management: list, switch, create, rename and delete workspaces; rename uses Metasploit's native `workspace -r` console command and retains the existing workspace records; deleting the active workspace switches back to the default workspace, and the default workspace is protected from rename/delete

The application remains single-account; multi-user accounts and roles are outside the current design.

The plain-language layer, guided workflows, and initial safety rails are
implemented. Execution Reliability is being hardened before further workflow
guidance; see [ROADMAP.md](ROADMAP.md) for the remaining work.

## Security boundary

**Login is required for the console API and WebSockets. The application remains local-only and does not support remote deployment.** HTTP requests and browser terminal WebSockets require an authenticated server-side session. Login uses credentials configured in `backend/.env`, session cookies are HTTP-only and SameSite strict, sessions expire, logout revokes the session, and repeated failed login attempts are rate-limited. Sessions are kept in memory and are invalidated when the backend restarts.

The local-only client-address check, HTTP Host allowlist and browser-origin checks remain enabled in addition to login. These are defense-in-depth controls; do not expose this application to a LAN, the public internet, or an unauthenticated reverse proxy.

### Configure the web console login

After copying `backend/.env.example` to `backend/.env`, set these values before starting the backend:

```dotenv
MSF_WEB_USERNAME=admin
MSF_WEB_PASSWORD=use-a-unique-password-of-at-least-12-characters
MSF_WEB_SESSION_TTL_SECONDS=28800
MSF_WEB_COOKIE_SECURE=false
```

Replace the example password with a strong, unique password. The application refuses to unlock the API until a username and a password of at least 12 characters are configured; known placeholder passwords are rejected. Keep `MSF_WEB_COOKIE_SECURE=false` for the standard local HTTP development URL only. Set it to `true` when the browser-facing UI is served over HTTPS. Sessions are in-memory, so restarting the backend signs everyone out.

The optional `MSF_WEB_ALLOWED_HOSTS` and `MSF_WEB_CORS_ORIGINS` settings customize the local development allowlists. Adding an origin or host does not enable remote access. The app intentionally uses one configured account; multi-user accounts and roles are not part of this design.

Metasploit's `db.loots` RPC may return a registered artifact path without inline content. Inline content can be downloaded directly. For file-backed records, the backend reads only files under `MSF_LOOT_ALLOWED_DIRS` (default: `~/.msf4/loot`) or exact files listed in `MSF_LOOT_ALLOWED_FILES`; client requests cannot choose a filesystem path. To permit the synthetic test artifact, add `MSF_LOOT_ALLOWED_FILES=/tmp/msf-web-console-loot-test.txt` to `backend/.env` and restart the backend. Keep the list narrow because loot can contain sensitive evidence. JSON exports contain sanitized metadata, not the original artifact bytes.

CVE/NVD enrichment sends CVE identifiers found in your own vulnerability records to the public NVD API (`services.nvd.nist.gov`) over HTTPS; no other workspace data is sent. This is outbound-only lookup traffic, not exploitation activity, but it does mean the backend process needs internet access for that one endpoint if you use it. There is no `NVD_API_KEY` by default, so lookups run unauthenticated at a low, self-imposed rate.

## Setup

### 1. Start msfrpcd

```bash
msfrpcd -U msf -P changeme -a 127.0.0.1 -p 55553 -S
```

`-S` disables SSL, which is simplest for local-only use. Drop `-S` to keep
SSL on (recommended if this machine is multi-user), and set
`MSF_RPC_SSL=true` / `MSF_RPC_VERIFY_CERT=false` (self-signed cert) in the
backend `.env` accordingly.

### 2. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # set MSF_RPC_* and MSF_WEB_USERNAME / MSF_WEB_PASSWORD before starting
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** and sign in with the web-console credentials from `backend/.env`. The dev server proxies `/api` to the backend on port 8000, including authenticated WebSocket upgrades for the console and interactive sessions.

## Optional reconnaissance tools

Tool binaries are detected from the backend process PATH and are not installed automatically. For Katana, install the current ProjectDiscovery release with Go 1.26.10 or newer:

```bash
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo ln -sf "$(go env GOPATH)/bin/katana" /usr/local/bin/katana
katana -version
```

Restart the backend after installing a tool, then use **Web Security → Reconnaissance** to refresh availability. Katana's application adapter uses fixed safe defaults and does not accept browser-supplied crawler flags.

## Development checks

Run all backend unit tests from the `backend` directory:

```bash
python -m unittest discover -s tests
```

Run the frontend TypeScript check and production build from the `frontend`
directory:

```bash
npm run build
```

### Troubleshooting

- **"Cannot reach msfrpcd" banner** — confirm `msfrpcd` is running and the
  host/port/user/pass in `backend/.env` match what you started it with.
- **Workspace selector fails to load** — confirm the Metasploit database is
  connected and initialized; the workspace APIs require an available database.
- **401 / auth errors** — `MSF_RPC_USER`/`MSF_RPC_PASS` mismatch, or the
  token expired (the client re-authenticates automatically on the next
  call, so this should self-heal).
- **Console shows nothing** — check the backend terminal for the actual
  `msfrpcd` error; the WebSocket relays it into the terminal as a red
  `[error]` line too.
- **"NVD rejected the request" when enriching a CVE** — you've hit NVD's
  public rate limit (5 requests/30s); wait a moment and retry, or set
  `NVD_API_KEY` in `backend/.env` for a higher limit.

## Project layout

```
backend/
  app/
    main.py          FastAPI app + router wiring
    msf_rpc.py        msgpack-rpc client for msfrpcd
    nvd_client.py      NVD CVE REST API client (CVE enrichment)
    routes/
      system.py        health/status
      assessments.py    platform-owned assessment and target-scope API\n      web_recon.py      local web tool inventory + bounded HTTP probe
      modules.py        search, info, execute, encode, NOP generation
      sessions.py        list, read/write, stop
      db.py               database views + workspace management + reports
      cve.py               CVE/NVD enrichment
      reporting.py           safe HTML assessment report generator\n    pdf_reporting.py       native PDF assessment report generator
      jobs.py               list/info/stop
      console.py             WebSocket console bridge
frontend/
  src/
    components/        Sidebar, ConsoleView/Tab, ModuleBrowser, WorkspaceSwitcher,
                        SessionsView, HostsView, JobsView
    lib/api.ts          typed fetch client for the backend
    App.tsx              layout + connection status
```
