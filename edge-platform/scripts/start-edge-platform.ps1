param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform"),
    [int]$NetworkWaitSeconds = 120
)

$ErrorActionPreference = "Stop"
$console = Join-Path $InstallRoot "bin\edge-console.exe"
if (-not (Test-Path -LiteralPath $console)) { throw "Installed edge-console is missing: $console" }

$deadline = (Get-Date).AddSeconds($NetworkWaitSeconds)
do {
    if (Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

& $console ensure-controller
if ($LASTEXITCODE -ne 0) { throw "Controller startup failed" }
& $console reconcile
if ($LASTEXITCODE -ne 0) { throw "Local runtime reconcile failed" }
