param([switch]$Lab, [switch]$NoBrowser)
# APIShield launcher for Windows. Runs the backend and the dashboard on this computer only.
# Usage: powershell -ExecutionPolicy Bypass -File .\start.ps1 [-Lab] [-NoBrowser]
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function PortBusy($port) { return [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) }
function WaitPort($port, $seconds) {
  $end = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $end) {
    if (PortBusy $port) { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}
$script:procs = @()
function StopAll {
  $ErrorActionPreference = "Continue"
  foreach ($p in $script:procs) {
    if ($p -and -not $p.HasExited) { & taskkill /T /F /PID $p.Id 2>&1 | Out-Null }
  }
}
function StartBg($exe, $argText, $dir, $name) {
  return Start-Process -FilePath $exe -ArgumentList $argText -WorkingDirectory $dir -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root\logs\$name.out.log" -RedirectStandardError "$root\logs\$name.err.log"
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Fail "Python is not installed or not on PATH." }
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { Fail "Node.js (npm) is not installed or not on PATH." }
New-Item -ItemType Directory -Force "$root\logs" | Out-Null

$py = "$root\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
  Write-Host "First run: creating the Python environment..."
  python -m venv "$root\.venv"
  if ($LASTEXITCODE -ne 0) { Fail "Could not create the virtual environment." }
  & $py -m pip install -q -r "$root\backend\requirements.txt"
  if ($LASTEXITCODE -ne 0) { Fail "pip install failed." }
}
if (-not (Test-Path "$root\backend\.env")) {
  Copy-Item "$root\backend\.env.example" "$root\backend\.env"
  Write-Host "Created backend\.env from .env.example."
}
if ((Test-Path "$root\frontend\.env.example") -and -not (Test-Path "$root\frontend\.env")) {
  Copy-Item "$root\frontend\.env.example" "$root\frontend\.env"
}
if (-not (Test-Path "$root\frontend\node_modules")) {
  Write-Host "First run: installing the frontend packages..."
  Push-Location "$root\frontend"
  npm install --silent
  $code = $LASTEXITCODE
  Pop-Location
  if ($code -ne 0) { Fail "npm install failed." }
}

foreach ($p in 8000, 5173) {
  if (PortBusy $p) { Fail "Port $p is already in use. Close the other backend or dashboard window first." }
}
if ($Lab -and (PortBusy 5000)) { Fail "Port 5000 is already in use. Close the other lab window first." }

# The lab exception is forced OFF unless -Lab is given, whatever backend\.env says.
$env:ALLOW_LAB_EXCEPTION = $(if ($Lab) { "true" } else { "false" })

try {
  if ($Lab) {
    Write-Host "Starting the practice lab on 127.0.0.1:5000 ..."
    $script:procs += StartBg $py "-m uvicorn lab_api:app --host 127.0.0.1 --port 5000" "$root\lab" "lab"
    if (-not (WaitPort 5000 40)) {
      Write-Host "The lab did not start. Last log lines:"
      Get-Content "$root\logs\lab.err.log" -Tail 15
      StopAll; exit 1
    }
    try { Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/lab/reset" | Out-Null } catch { }
  }

  Write-Host "Starting the backend on 127.0.0.1:8000 ..."
  $script:procs += StartBg $py "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" "$root\backend" "backend"
  if (-not (WaitPort 8000 45)) {
    Write-Host "The backend did not start. Last log lines:"
    Get-Content "$root\logs\backend.err.log" -Tail 15
    StopAll; exit 1
  }

  Write-Host "Starting the dashboard ..."
  $script:procs += StartBg "npm.cmd" "run dev -- --strictPort --port 5173" "$root\frontend" "frontend"
  if (-not (WaitPort 5173 45)) {
    Write-Host "The dashboard did not start. Last log lines:"
    Get-Content "$root\logs\frontend.err.log" -Tail 15
    StopAll; exit 1
  }

  Write-Host ""
  Write-Host "=========================================================="
  Write-Host "  APIShield is running:   http://localhost:5173" -ForegroundColor Green
  Write-Host "  Only this computer can open it."
  if ($Lab) { Write-Host "  Lab mode ON: scan the practice lab at http://127.0.0.1:5000" }
  Write-Host "  Press Enter here (or Ctrl+C) to stop everything."
  Write-Host "=========================================================="
  if (-not $NoBrowser) { Start-Process "http://localhost:5173" }
  Read-Host | Out-Null
}
finally {
  StopAll
  Remove-Item Env:ALLOW_LAB_EXCEPTION -ErrorAction SilentlyContinue
  Write-Host "APIShield stopped."
}