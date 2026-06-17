#!/usr/bin/env bash
# Cyber Defense SOC Lab — one-command launcher (Linux / macOS)
set -euo pipefail
cd "$(dirname "$0")"

PY=python3
command -v $PY >/dev/null 2>&1 || { echo "Python 3 is required but was not found."; exit 1; }

if [ ! -d ".venv" ]; then
  echo "[*] Creating virtual environment (.venv) ..."
  $PY -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Installing dependencies ..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "[*] Priming detection engine with a full attack simulation ..."
python -m soclab simulate --all || true

echo "[*] Launching tactical console at http://127.0.0.1:8000  (Ctrl+C to stop)"
python -m soclab serve --host 127.0.0.1 --port 8000
