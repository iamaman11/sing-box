param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform")
)

$ErrorActionPreference = "Stop"
$console = Join-Path $InstallRoot "bin\edge-console.exe"
if (-not (Test-Path -LiteralPath $console)) { throw "Installed edge-console is missing: $console" }

& $console reconcile
if ($LASTEXITCODE -ne 0) { throw "Installed runtime reconcile failed" }
