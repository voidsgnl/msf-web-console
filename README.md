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

**v0.1 — vertical slice.** Implemented and working end-to-end:

- Live console (xterm.js) bridged to a real `msfconsole` instance, tabbed
  for multiple concurrent consoles
- Module search/browse across exploit, auxiliary, post, payload, encoder,
  nop
- Module info + option editing + execute (runs as an MSF job)
- Session list + kill
- Jobs list + stop
- Database browser: hosts, services, vulns, loot, creds

Not yet built (planned next): per-session interactive shell/meterpreter UI
beyond the raw read/write endpoints, workspace switcher, auth/login screen
(currently single-user, local-only), loot/file download, report generation.

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
      db.py               hosts/services/vulns/loot/creds
      jobs.py               list/info/stop
      console.py             WebSocket console bridge
frontend/
  src/
    components/        Sidebar, ConsoleView/Tab, ModuleBrowser, SessionsView,
                        HostsView, JobsView
    lib/api.ts          typed fetch client for the backend
    App.tsx              layout + connection status
```
