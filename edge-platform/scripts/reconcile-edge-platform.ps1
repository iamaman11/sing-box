param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ConsoleExe = "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe",
    [switch]$PendingShutdownIntent
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
$intentPath = Join-Path $runtimeDir "shutdown-intent.flag"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$logPath = Join-Path $runtimeDir "reconcile.log"
function Write-ReconcileLog([string]$Message) {
    "$(Get-Date -Format o) $Message" | Add-Content -Path $logPath
}

if (-not (Test-Path $ConsoleExe)) { throw "edge-console binary not found: $ConsoleExe" }

$status = & $ConsoleExe status 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "Controller status query failed: $status" }
$hasLiveState = $status -match 'Live deployment state\s+: present'

if ($hasLiveState) {
    $liveStatePath = Join-Path $RepoRoot "win\vultr-waw\current-edge.json"
    if (-not (Test-Path $liveStatePath)) {
        Write-ReconcileLog "Controller has recorded deployment but live-state file is absent; no replacement VM was created"
        exit 0
    }
    $liveState = Get-Content -Raw $liveStatePath | ConvertFrom-Json
    $instanceId = [string]$liveState.instance_id
    if ([string]::IsNullOrWhiteSpace($instanceId)) {
        Write-ReconcileLog "Live-state file has no instance id; no replacement VM was created"
        exit 0
    }

    if ($PendingShutdownIntent) {
        Write-ReconcileLog "Shutdown intent is pending; existing VM was retained until local recovery handles it"
        exit 0
    }

    & $ConsoleExe start-local | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-ReconcileLog "Local sing-box did not start; existing VM was left unchanged"; exit 0 }
    Write-ReconcileLog "Recorded deployment retained; periodic reconcile uses only local DPAPI-backed controller state"
    exit 0
}

Write-ReconcileLog "No recorded deployment; creating one replacement VM from the configured snapshot"
& $ConsoleExe deploy
if ($LASTEXITCODE -ne 0) { throw "Replacement VM deployment failed" }
if ($PendingShutdownIntent) { Remove-Item -LiteralPath $intentPath -Force -ErrorAction SilentlyContinue }
Write-ReconcileLog "Replacement VM deployed"
