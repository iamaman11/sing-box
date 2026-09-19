[CmdletBinding()]
param(
    [string]$StatePath = '',
    [string]$SingBoxPath = 'V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe',
    [string]$ConfigPath = '',
    [string]$SyncConfigScript = '',
    [string]$MenuScript = '',
    [switch]$OpenUi,
    [switch]$OpenMenu
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$AppRoot = Join-Path $env:LOCALAPPDATA 'sing-box-vultr-dual'
$StateRoot = Join-Path $AppRoot 'state'
$LegacyStatePath = Join-Path $ProjectRoot 'vultr-waw\current-edge.json'

if (-not $StatePath) {
    $defaultStatePath = Join-Path $StateRoot 'current-edge.json'
    if (Test-Path -LiteralPath $defaultStatePath) {
        $StatePath = $defaultStatePath
    } elseif (Test-Path -LiteralPath $LegacyStatePath) {
        $StatePath = $LegacyStatePath
    } else {
        $StatePath = $defaultStatePath
    }
}
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'edge-dns-clean-vultr-dual.json' }
if (-not $SyncConfigScript) { $SyncConfigScript = Join-Path $PSScriptRoot 'sync-vultr-dual-config.ps1' }
if (-not $MenuScript) { $MenuScript = Join-Path $PSScriptRoot 'singbox-dual-menu.ps1' }

function Get-LocalSingBoxStatus {
    $result = [ordered]@{
        running = $false
        expected_config = $false
        process_id = ''
        command_line = ''
        note = ''
    }

    $process = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -ieq 'sing-box.exe' } |
        Select-Object -First 1

    if (-not $process) {
        $result.note = 'not running'
        return [pscustomobject]$result
    }

    $result.running = $true
    $result.process_id = [string]$process.ProcessId
    $result.command_line = [string]$process.CommandLine
    if ($process.CommandLine -like "*$ConfigPath*") {
        $result.expected_config = $true
        $result.note = 'running expected dual config'
    } else {
        $result.note = 'running different config'
    }
    return [pscustomobject]$result
}

if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "Backend state is absent: $StatePath. Server provisioning and application deployment are owned only by the canonical GitHub lifecycle."
}
if (-not (Test-Path -LiteralPath $SingBoxPath)) {
    throw "Windows sing-box binary not found: $SingBoxPath"
}
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Windows sing-box config not found: $ConfigPath"
}
if (-not (Test-Path -LiteralPath $SyncConfigScript)) {
    throw "Config sync script not found: $SyncConfigScript"
}

& powershell -ExecutionPolicy Bypass -File $SyncConfigScript -ConfigPath $ConfigPath -StatePath $StatePath | Out-Host

$localSingBox = Get-LocalSingBoxStatus
if ($localSingBox.running -and -not $localSingBox.expected_config) {
    throw "Another sing-box config is already running (PID $($localSingBox.process_id)). Stop it manually before starting the dual client."
}
if ($localSingBox.running -and $localSingBox.expected_config) {
    Get-Process -Id $localSingBox.process_id -ErrorAction SilentlyContinue | Stop-Process -Force
}

$process = Start-Process -FilePath $SingBoxPath -ArgumentList @('run', '-c', $ConfigPath) -WorkingDirectory (Split-Path -Parent $ConfigPath) -PassThru
Start-Sleep -Seconds 3

if ($OpenUi) {
    Start-Process 'http://127.0.0.1:9090/ui/#/proxies'
}
if ($OpenMenu) {
    Start-Process powershell -ArgumentList '-NoExit', '-File', $MenuScript
}

Write-Host ''
Write-Host "sing-box started, PID: $($process.Id)"
Write-Host "UI: http://127.0.0.1:9090/ui/#/proxies"
Write-Host ''
