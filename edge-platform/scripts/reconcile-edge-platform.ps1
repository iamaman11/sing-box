param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ConsoleExe = "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe"
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
$logCleanupScript = Join-Path $RepoRoot "edge-platform\scripts\clear-singbox-log.ps1"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$logPath = Join-Path $runtimeDir "reconcile.log"

function Write-ReconcileLog([string]$Message) {
    "$(Get-Date -Format o) $Message" | Add-Content -Path $logPath
}

if (-not (Test-Path $ConsoleExe)) { throw "edge-console binary not found: $ConsoleExe" }

$status = & $ConsoleExe status 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "Controller status query failed: $status" }

$localSingboxRunning = $status -match 'Local sing-box\s+: running'
$managedConfigActive = $status -match 'Local managed config\s+: yes'

if (-not $managedConfigActive) {
    Write-ReconcileLog "No Windows-local managed config is active; no server lifecycle action is permitted from Windows"
    exit 0
}

if ($localSingboxRunning) {
    if (Test-Path $logCleanupScript) { & $logCleanupScript -IfDue }
    Write-ReconcileLog "Windows-local sing-box is already running; no restart requested"
    exit 0
}

& $ConsoleExe start-local | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-ReconcileLog "Windows-local sing-box did not start; server state was not touched"
    exit 0
}
Write-ReconcileLog "Windows-local sing-box started; server lifecycle remains GitHub-owned"
