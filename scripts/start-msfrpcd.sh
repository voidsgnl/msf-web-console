#!/usr/bin/env bash
#
# Starts msfrpcd with the same host/port/user/pass msf-web-console's
# backend expects (per backend/.env.example and README.md's Setup section).
# Run this BEFORE start-app.sh, in its own terminal, since msfrpcd normally
# stays in the foreground and prints its own logs.
#
# Usage:
#   ./scripts/start-msfrpcd.sh
#
# Reads backend/.env if present (same variable names the backend itself
# reads: MSF_RPC_HOST, MSF_RPC_PORT, MSF_RPC_USER, MSF_RPC_PASS,
# MSF_RPC_SSL); falls back to the defaults from backend/.env.example /
# the README's example command otherwise. Does not edit backend/.env.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
ENV_FILE="${REPO_ROOT}/backend/.env"

MSF_RPC_HOST="127.0.0.1"
MSF_RPC_PORT="55553"
MSF_RPC_USER="msf"
MSF_RPC_PASS="changeme"
MSF_RPC_SSL="false"

if [[ -f "${ENV_FILE}" ]]; then
  echo "Reading RPC settings from ${ENV_FILE}"
  # Only pull the handful of keys we care about, ignoring everything else
  # (comments, the web-login/CORS/NVD settings, etc).
  while IFS='=' read -r key value; do
    case "${key}" in
      MSF_RPC_HOST) MSF_RPC_HOST="${value}" ;;
      MSF_RPC_PORT) MSF_RPC_PORT="${value}" ;;
      MSF_RPC_USER) MSF_RPC_USER="${value}" ;;
      MSF_RPC_PASS) MSF_RPC_PASS="${value}" ;;
      MSF_RPC_SSL) MSF_RPC_SSL="${value}" ;;
    esac
  done < <(grep -E '^(MSF_RPC_HOST|MSF_RPC_PORT|MSF_RPC_USER|MSF_RPC_PASS|MSF_RPC_SSL)=' "${ENV_FILE}" || true)
else
  echo "No ${ENV_FILE} found yet - using the README's default msfrpcd settings."
  echo "(host=${MSF_RPC_HOST} port=${MSF_RPC_PORT} user=${MSF_RPC_USER})"
fi

if ! command -v msfrpcd >/dev/null 2>&1; then
  echo "error: msfrpcd not found on PATH. Install/activate Metasploit Framework first." >&2
  exit 1
fi

# Bail out early (instead of letting msfrpcd fail with a confusing bind
# error) if something is already listening on the target port - most
# likely an msfrpcd instance you already started.
if (exec 3<>"/dev/tcp/${MSF_RPC_HOST}/${MSF_RPC_PORT}") 2>/dev/null; then
  exec 3>&- 3<&-
  echo "Something is already listening on ${MSF_RPC_HOST}:${MSF_RPC_PORT} - assuming msfrpcd is already running."
  echo "If that's not the case, stop whatever is bound to that port and re-run this script."
  exit 0
fi

# backend/.env.example notes this was confirmed empirically for one build:
# -S disabled SSL there. If your build does the opposite, set
# MSF_RPC_SSL=true in backend/.env and this script will drop -S for you.
SSL_FLAG="-S"
if [[ "${MSF_RPC_SSL,,}" == "true" ]]; then
  SSL_FLAG=""
fi

echo "Starting msfrpcd on ${MSF_RPC_HOST}:${MSF_RPC_PORT} (user=${MSF_RPC_USER})..."
echo "Press Ctrl+C to stop it."
echo

# Foreground on purpose: msfrpcd's own output (including the real RPC
# error you'd otherwise only see by digging through logs) stays visible
# here, and Ctrl+C cleanly stops it.
exec msfrpcd -U "${MSF_RPC_USER}" -P "${MSF_RPC_PASS}" -a "${MSF_RPC_HOST}" -p "${MSF_RPC_PORT}" ${SSL_FLAG}
