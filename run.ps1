# Cyber Defense SOC Lab — one-command launcher (Windows PowerShell)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".venv")) {
    Write-Host "[*] Creating virtual environment (.venv) ..."
    python -m venv .venv
}
& ".\.venv\Scripts\Activate.ps1"

# Use the venv's own python for all installs so dependencies land in the
# right place. We do NOT upgrade pip (Windows blocks the in-place upgrade,
# and it isn't needed just to install Flask).
Write-Host "[*] Installing dependencies ..."
python -m pip install -q -r requirements.txt

Write-Host "[*] Priming detection engine with a full attack simulation ..."
python -m soclab simulate --all

Write-Host "[*] Launching tactical console at http://127.0.0.1:8000  (Ctrl+C to stop)"
python -m soclab serve --host 127.0.0.1 --port 8000
