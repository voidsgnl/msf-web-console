#!/usr/bin/env bash
#
# Starts msf-web-console's backend (FastAPI/uvicorn) and frontend
# (Vite dev server) together. Run scripts/start-msfrpcd.sh first (in its
# own terminal) - this script does NOT start msfrpcd itself.
#
# Usage:
#   ./scripts/start-app.sh
#
# Ctrl+C stops both the frontend and the backend.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
BACKEND_DIR="${REPO_ROOT}/backend"
FRONTEND_DIR="${REPO_ROOT}/frontend"

# Scanner binaries are installed in user-level locations as well as system
# directories. Export them before uvicorn starts so shutil.which() in FastAPI
# sees the same tools as the interactive shell.
RUBY_GEM_BIN=""
if command -v ruby >/dev/null 2>&1; then
  RUBY_GEM_BIN="$(ruby -e 'require "rubygems"; print Gem.user_dir' 2>/dev/null)/bin"
fi
export PATH="${HOME}/go/bin:${HOME}/.local/bin${RUBY_GEM_BIN:+:${RUBY_GEM_BIN}}:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

echo "Reconnaissance tool paths inherited by the backend:"
for tool in httpx whatweb katana ffuf gobuster feroxbuster nuclei nikto wpscan subfinder amass testssl.sh nmap; do
  if command -v "${tool}" >/dev/null 2>&1; then
    printf "  [available] %-12s %s\\n" "${tool}" "$(command -v "${tool}")"
  else
    printf "  [missing]   %s\\n" "${tool}"
  fi
done

BACKEND_HOST="127.0.0.1"
BACKEND_PORT="8000"

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo
  echo "Shutting down..."
  if [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
    kill "${FRONTEND_PID}" 2>/dev/null || true
  fi
  if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
    kill "${BACKEND_PID}" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- backend -----------------------------------------------------------

if [[ ! -d "${BACKEND_DIR}" ]]; then
  echo "error: ${BACKEND_DIR} not found. Run this from the repo, or check out the full project." >&2
  exit 1
fi

if [[ ! -f "${BACKEND_DIR}/.env" ]]; then
  if [[ -f "${BACKEND_DIR}/.env.example" ]]; then
    cp "${BACKEND_DIR}/.env.example" "${BACKEND_DIR}/.env"
    echo "Created backend/.env from backend/.env.example."
    echo "Set MSF_WEB_USERNAME / MSF_WEB_PASSWORD (12+ chars) in backend/.env, then re-run this script -"
    echo "the backend refuses to start without them."
    exit 1
  else
    echo "error: backend/.env is missing and there's no backend/.env.example to copy from." >&2
    exit 1
  fi
fi

# The backend hard-refuses to start without a real password (see README's
# Security boundary section); catch that here with a clearer message
# instead of letting uvicorn fail further in.
if ! grep -qE '^MSF_WEB_PASSWORD=.{12,}' "${BACKEND_DIR}/.env"; then
  echo "error: MSF_WEB_PASSWORD in backend/.env is missing or shorter than 12 characters." >&2
  echo "Set it before starting the app." >&2
  exit 1
fi

echo "Setting up backend..."
if [[ ! -d "${BACKEND_DIR}/venv" ]]; then
  python3 -m venv "${BACKEND_DIR}/venv"
fi
# shellcheck disable=SC1091
source "${BACKEND_DIR}/venv/bin/activate"
pip install --quiet -r "${BACKEND_DIR}/requirements.txt"

echo "Starting backend on http://${BACKEND_HOST}:${BACKEND_PORT} ..."
(
  cd "${BACKEND_DIR}"
  exec uvicorn app.main:app --reload --host "${BACKEND_HOST}" --port "${BACKEND_PORT}"
) &
BACKEND_PID=$!
deactivate

# Give the backend a few seconds to come up (or fail fast) before starting
# the frontend, rather than racing them.
for _ in $(seq 1 20); do
  if ! kill -0 "${BACKEND_PID}" 2>/dev/null; then
    echo "error: backend process exited during startup - check the output above." >&2
    exit 1
  fi
  if (exec 3<>"/dev/tcp/${BACKEND_HOST}/${BACKEND_PORT}") 2>/dev/null; then
    exec 3>&- 3<&-
    break
  fi
  sleep 0.5
done

# --- frontend ------------------------------------------------------------

if [[ ! -d "${FRONTEND_DIR}" ]]; then
  echo "error: ${FRONTEND_DIR} not found." >&2
  exit 1
fi

echo "Setting up frontend..."
if [[ ! -d "${FRONTEND_DIR}/node_modules" ]]; then
  (cd "${FRONTEND_DIR}" && npm install)
fi

echo "Starting frontend (Vite) ..."
(
  cd "${FRONTEND_DIR}"
  exec npm run dev
) &
FRONTEND_PID=$!

echo
echo "Backend:  http://${BACKEND_HOST}:${BACKEND_PORT}"
echo "Frontend: http://localhost:5173  (sign in with MSF_WEB_USERNAME / MSF_WEB_PASSWORD from backend/.env)"
echo "Make sure msfrpcd is running too (scripts/start-msfrpcd.sh)."
echo "Press Ctrl+C to stop both."
echo

wait "${FRONTEND_PID}"
