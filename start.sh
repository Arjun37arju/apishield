#!/usr/bin/env bash
# APIShield launcher for Linux and macOS. Runs the backend and the dashboard on this computer only.
# Usage: bash start.sh [--lab] [--no-browser]
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

LAB=0
OPEN=1
for arg in "$@"; do
  case "$arg" in
    --lab) LAB=1 ;;
    --no-browser) OPEN=0 ;;
    *) echo "Unknown option: $arg (use --lab or --no-browser)"; exit 1 ;;
  esac
done

fail() { echo "ERROR: $1" >&2; exit 1; }
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_url() {
  local url="$1" tries=$(( $2 * 2 ))
  while [ "$tries" -gt 0 ]; do
    if curl -s -o /dev/null --max-time 2 "$url"; then return 0; fi
    sleep 0.5
    tries=$(( tries - 1 ))
  done
  return 1
}

command -v python3 >/dev/null 2>&1 || fail "Python 3 is not installed."
command -v npm >/dev/null 2>&1 || fail "Node.js / npm is not installed."
command -v curl >/dev/null 2>&1 || fail "curl is not installed."

mkdir -p "$ROOT/logs"
PY="$ROOT/.venv/bin/python"

if [ ! -x "$PY" ]; then
  echo "First run: creating the Python environment..."
  python3 -m venv "$ROOT/.venv" || fail "Could not create the virtual environment (Debian/Ubuntu: sudo apt install python3-venv)."
  "$PY" -m pip install -q -r "$ROOT/backend/requirements.txt" || fail "pip install failed."
fi
if [ ! -f "$ROOT/backend/.env" ]; then
  cp "$ROOT/backend/.env.example" "$ROOT/backend/.env"
  echo "Created backend/.env from .env.example."
fi
if [ -f "$ROOT/frontend/.env.example" ] && [ ! -f "$ROOT/frontend/.env" ]; then
  cp "$ROOT/frontend/.env.example" "$ROOT/frontend/.env"
fi
if [ ! -d "$ROOT/frontend/node_modules" ]; then
  echo "First run: installing the frontend packages..."
  ( cd "$ROOT/frontend" && npm install --silent ) || fail "npm install failed."
fi

for p in 8000 5173; do
  if port_busy "$p"; then fail "Port $p is already in use. Stop the other backend or dashboard first."; fi
done
if [ "$LAB" -eq 1 ] && port_busy 5000; then fail "Port 5000 is already in use."; fi

PIDS=()
start_bg() { # start_bg <folder> <logfile> <command...>
  local dir="$1" log="$2"
  shift 2
  if command -v setsid >/dev/null 2>&1; then
    ( cd "$dir" && exec setsid "$@" ) >"$log" 2>&1 &
  else
    ( cd "$dir" && exec "$@" ) >"$log" 2>&1 &
  fi
  PIDS+=("$!")
}
cleanup() {
  trap - INT TERM EXIT
  echo
  echo "Stopping APIShield..."
  for p in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup INT TERM EXIT

# The lab exception is forced OFF unless --lab is given, whatever backend/.env says.
LABVAL=false
if [ "$LAB" -eq 1 ]; then LABVAL=true; fi

if [ "$LAB" -eq 1 ]; then
  echo "Starting the practice lab on 127.0.0.1:5000 ..."
  start_bg "$ROOT/lab" "$ROOT/logs/lab.log" "$PY" -m uvicorn lab_api:app --host 127.0.0.1 --port 5000
  wait_url "http://127.0.0.1:5000/api/search" 40 || { echo "The lab did not start. Last log lines:"; tail -n 15 "$ROOT/logs/lab.log"; exit 1; }
  curl -s -X POST "http://127.0.0.1:5000/lab/reset" >/dev/null
fi

echo "Starting the backend on 127.0.0.1:8000 ..."
start_bg "$ROOT/backend" "$ROOT/logs/backend.log" env ALLOW_LAB_EXCEPTION="$LABVAL" "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
wait_url "http://127.0.0.1:8000/checks" 45 || { echo "The backend did not start. Last log lines:"; tail -n 15 "$ROOT/logs/backend.log"; exit 1; }

echo "Starting the dashboard ..."
start_bg "$ROOT/frontend" "$ROOT/logs/frontend.log" npm run dev -- --strictPort --port 5173
wait_url "http://localhost:5173" 45 || { echo "The dashboard did not start. Last log lines:"; tail -n 15 "$ROOT/logs/frontend.log"; exit 1; }

echo
echo "=========================================================="
echo "  APIShield is running:   http://localhost:5173"
echo "  Only this computer can open it."
if [ "$LAB" -eq 1 ]; then
  echo "  Lab mode ON: scan the practice lab at http://127.0.0.1:5000"
fi
echo "  Press Enter (or Ctrl+C) here to stop everything."
echo "=========================================================="
if [ "$OPEN" -eq 1 ]; then
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "http://localhost:5173" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then open "http://localhost:5173" >/dev/null 2>&1 &
  fi
fi
read -r _