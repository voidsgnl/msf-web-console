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
- Loot evidence browser: search records, inspect all returned metadata, copy a record, and export one or filtered records as JSON
- Loot artifact download: retrieve the artifact bytes exposed by the Framework `db.loots` RPC response; raw data stays on the backend during listing, download names/content types are validated, and no user-supplied filesystem paths are read
- Database workspace switcher: list workspaces, switch active workspace,
  create a workspace and switch to it; database views refresh after switching

Still planned: workspace deletion/renaming, auth/login screen (currently
single-user, local-only), report generation. Metasploit's `db.loots` RPC
returns a `data` field for loot content, but some records may have no content
in that field. The console can download content returned by RPC; records without
data remain metadata-only. The RPC does not expose a stable loot ID or a
retrievable filesystem path, so the download endpoint never accepts or reads an
arbitrary path from the browser. JSON exports contain sanitized metadata, not
the original artifact bytes.

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
      db.py               database views + workspace management
      jobs.py               list/info/stop
      console.py             WebSocket console bridge
frontend/
  src/
    components/        Sidebar, ConsoleView/Tab, ModuleBrowser, WorkspaceSwitcher,
                        SessionsView, HostsView, JobsView
    lib/api.ts          typed fetch client for the backend
    App.tsx              layout + connection status
```
