# MSF Web Console

A self-hosted web UI for the Metasploit Framework — full RPC-driven console,
module browser/launcher, session manager, and database views (hosts,
services, vulns, loot, creds). FastAPI backend + React/TS frontend, talks to
your own local `msfrpcd`.

This runs entirely on your machine, against a Metasploit install you control.
There is no remote/hosted component.

## Architecture

```
┌──────────────┐  HTTP + WS  ┌──────────────┐  msgpack-rpc   ┌───────────┐
│ React/Vite   │ ───────────▶│ FastAPI      │ ──────────────▶│ msfrpcd   │
│ (port 5173)  │◀─────────── │ (port 8000)  │◀────────────── │ (55553)   │
└──────────────┘             └──────────────┘                └───────────┘
```

The backend never talks to any exploit target directly — it's a thin proxy
over Metasploit's own RPC API. Every module execution, session interaction,
and console command is handled by `msfrpcd` itself, exactly as if you'd
typed it into `msfconsole`.

## Status

**v0.1 — vertical slice.** Implemented:

- Live console (xterm.js) bridged to a real `msfconsole` instance, tabbed
  for multiple concurrent consoles
- Module search/browse across exploit, auxiliary, post, payload, encoder,
  nop
- Module info + option editing + execution for exploit, auxiliary, and post
  modules, including required-option checks, job/UUID tracking, returned result
  display, and new-session detection
- Payload generation with a binary-safe artifact download; encoder and NOP
  modules remain inspectable but are not sent through the generic execute API
- Target-aware compatible payload browsing and selection, including payload
  option editing before exploit execution
- Session list + kill + interactive session shell/meterpreter terminal
- Jobs list + stop
- Database explorer: hosts, services, vulnerabilities, loot, and credentials, with cross-record search, field/value filtering, record inspection, host-to-service/vulnerability navigation, and JSON metadata export; sensitive fields are redacted by default
- Assessment report for the active workspace: executive summary, severity counts, database-record-based vulnerability findings, remediation guidance, open-service exposure observations, inventory tables, and print-to-PDF styling. Credential values, common filesystem paths, artifact bytes, and download references are filtered.
- Loot evidence browser: search records, inspect all returned metadata, copy a record, and export one or filtered records as JSON
- Loot artifact download: retrieve inline artifact data from the Framework `db.loots` RPC response or, when RPC returns metadata only, read the associated file only when its exact path or containing directory is allowlisted in backend configuration; browser-supplied filesystem paths are never accepted
- Workspace management: list, switch, create and delete workspaces; deleting the active workspace switches back to the default workspace, and the default workspace itself is protected

Still planned: workspace renaming (the standard Metasploit database RPC does not expose a rename operation), a real auth/login and user-permission system, a dedicated PDF export endpoint, and trusted external CVE/advisory enrichment beyond the metadata already stored in Metasploit.

## Security boundary

**This application is local-only and does not currently authenticate users. Do not expose it to a LAN, the public internet, or an unauthenticated reverse proxy.** The backend adds defense-in-depth protections: requests must originate from a loopback client address, HTTP Host headers are checked against an explicit allowlist, browser CORS origins are restricted, and the console/session WebSockets reject untrusted browser origins. These protections are not a replacement for login/authentication and are not a supported remote-access configuration.

The development server and backend should bind only to loopback addresses. Start the backend as shown below; do not change its host to `0.0.0.0`.

The optional `MSF_WEB_ALLOWED_HOSTS` and `MSF_WEB_CORS_ORIGINS` values in `backend/.env` customize the allowlists for local development setups. Adding an origin or host does not enable authentication. Do not add externally reachable hosts/origins until a dedicated authentication layer and remote deployment model are implemented. Metasploit's `db.loots` RPC may
return a registered artifact path without inline content. Inline content can be
downloaded directly. For file-backed records, the backend reads only files under
`MSF_LOOT_ALLOWED_DIRS` (default: `~/.msf4/loot`) or exact files listed in
`MSF_LOOT_ALLOWED_FILES`; client requests cannot choose a filesystem path. To
permit the synthetic test artifact, add
`MSF_LOOT_ALLOWED_FILES=/tmp/msf-web-console-loot-test.txt` to `backend/.env`
and restart the backend. Keep the list narrow because loot can contain sensitive
evidence. JSON exports contain sanitized metadata, not the original artifact
bytes.

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
cp .env.example .env            # edit MSF_RPC_USER / MSF_RPC_PASS to match step 1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**. The dev server proxies `/api` to the
backend on port 8000, including WebSocket upgrades for the console.

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

## Project layout

```
backend/
  app/
    main.py          FastAPI app + router wiring
    msf_rpc.py        msgpack-rpc client for msfrpcd
    routes/
      system.py        health/status
      modules.py        search, info, execute
      sessions.py        list, read/write, stop
      db.py               database views + workspace management + reports
      reporting.py           safe HTML assessment report generator
      jobs.py               list/info/stop
      console.py             WebSocket console bridge
frontend/
  src/
    components/        Sidebar, ConsoleView/Tab, ModuleBrowser, WorkspaceSwitcher,
                        SessionsView, HostsView, JobsView
    lib/api.ts          typed fetch client for the backend
    App.tsx              layout + connection status
```
