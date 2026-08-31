param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ConsoleExe = "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe",
    [string]$WslDistribution = "Ubuntu",
    [string]$VaultPath = "/home/bose/projects/secret-vault/bin/secret-vault",
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

    $checkCode = @'
import json, os, sys, urllib.error, urllib.request
request=urllib.request.Request(
  'https://api.vultr.com/v2/instances/'+os.environ['EDGE_INSTANCE_ID'],
  headers={'Authorization':'Bearer '+os.environ['VULTR_API_KEY']},
)
try:
  with urllib.request.urlopen(request, timeout=20) as response:
    item=json.loads(response.read().decode('utf-8')).get('instance',{})
    state='healthy' if item.get('status') == 'active' and item.get('server_status') == 'ok' else 'unhealthy'
    print(json.dumps({'state':state}))
except urllib.error.HTTPError as error:
  if error.code == 404:
    print(json.dumps({'state':'missing'}))
  else:
    print(json.dumps({'state':'unknown','http':error.code}))
except Exception:
  print(json.dumps({'state':'unknown'}))
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($checkCode))
    $runner = "import base64;exec(base64.b64decode('$encoded'))"
    $oldWslenv = $env:WSLENV
    $env:EDGE_INSTANCE_ID = $instanceId
    $env:WSLENV = "EDGE_INSTANCE_ID"
    try {
        $instanceCheckRaw = & wsl.exe -d $WslDistribution -- $VaultPath run vultr.singbox-lifecycle VULTR_API_KEY -- python3 -c $runner
        if ($LASTEXITCODE -ne 0) { throw "Vultr instance inspection failed" }
        $instanceCheck = ($instanceCheckRaw | Out-String | ConvertFrom-Json)
    } finally {
        $env:WSLENV = $oldWslenv
        Remove-Item Env:EDGE_INSTANCE_ID -ErrorAction SilentlyContinue
    }

    if ($instanceCheck.state -eq 'missing') {
        Write-ReconcileLog "Recorded VM is absent at Vultr; clearing stale local state before replacement"
        $priorDeleteDns = $env:EDGE_DELETE_DNS
        $env:EDGE_DELETE_DNS = "0"
        try { & $ConsoleExe destroy | Out-Null } finally { $env:EDGE_DELETE_DNS = $priorDeleteDns }
        if ($LASTEXITCODE -ne 0) { throw "Failed to clear stale deployment state" }
        & $ConsoleExe deploy
        if ($LASTEXITCODE -ne 0) { throw "Replacement VM deployment failed" }
        if ($PendingShutdownIntent) { Remove-Item -LiteralPath $intentPath -Force -ErrorAction SilentlyContinue }
        Write-ReconcileLog "Replacement VM deployed after confirmed absence"
        exit 0
    }
    if ($PendingShutdownIntent) {
        Write-ReconcileLog "Shutdown intent is pending; existing VM was not renewed while Worker deletion completes"
        exit 0
    }
    if ($instanceCheck.state -ne 'healthy') {
        Write-ReconcileLog "Managed VM is present but not healthy; no duplicate VM was created and its lease was not renewed"
        exit 0
    }

    & $ConsoleExe start-local | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-ReconcileLog "Local sing-box did not start; existing VM was left unchanged"; exit 0 }
    Write-ReconcileLog "Healthy recorded deployment retained"
    exit 0
}

Write-ReconcileLog "No recorded deployment; creating one replacement VM from the configured snapshot"
& $ConsoleExe deploy
if ($LASTEXITCODE -ne 0) { throw "Replacement VM deployment failed" }
if ($PendingShutdownIntent) { Remove-Item -LiteralPath $intentPath -Force -ErrorAction SilentlyContinue }
Write-ReconcileLog "Replacement VM deployed"
