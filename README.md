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
- Module info + option editing + execute, with job progress and new-session
  detection
- Target-aware compatible payload browsing and selection, including payload
  option editing before exploit execution
- Session list + kill + interactive session shell/meterpreter terminal
- Jobs list + stop
- Database browser: hosts, services, vulns, loot, creds
- Printable HTML assessment report for the active workspace, with inventory summaries and sensitive credential values omitted
- Loot evidence browser: search records, inspect all returned metadata, copy a record, and export one or filtered records as JSON
- Loot artifact download: retrieve inline artifact data from the Framework `db.loots` RPC response or, when RPC returns metadata only, read the associated file only when its exact path or containing directory is allowlisted in backend configuration; browser-supplied filesystem paths are never accepted
- Database workspace switcher: list workspaces, switch active workspace,
  create a workspace and switch to it; database views refresh after switching

Still planned: workspace deletion/renaming, auth/login screen (currently
single-user, local-only), PDF-native report export. Metasploit's `db.loots` RPC may
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
uvicorn app.main:app --reload --port 8000
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
