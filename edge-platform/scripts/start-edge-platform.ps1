param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [int]$NetworkWaitSeconds = 120
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$deadline = (Get-Date).AddSeconds($NetworkWaitSeconds)
do {
    if (Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

& (Join-Path $RepoRoot "edge-platform\scripts\ensure-edge-controller.ps1") -RepoRoot $RepoRoot
& (Join-Path $RepoRoot "edge-platform\scripts\reconcile-edge-platform.ps1") -RepoRoot $RepoRoot
