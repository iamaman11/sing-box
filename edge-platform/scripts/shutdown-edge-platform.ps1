param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform")
)

$ErrorActionPreference = "Stop"
$console = Join-Path $InstallRoot "bin\edge-console.exe"
$runtimeDir = Join-Path $InstallRoot "runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$logPath = Join-Path $runtimeDir "shutdown-cleanup.log"

try {
    if (-not (Test-Path -LiteralPath $console)) { throw "Installed edge-console is missing: $console" }
    & $console stop-local 2>&1 | Add-Content -Path $logPath
    if ($LASTEXITCODE -ne 0) { throw "Windows-local runtime stop failed with exit code $LASTEXITCODE" }
    "$(Get-Date -Format o) Windows-local runtime stopped; provider lifecycle was not touched" | Add-Content -Path $logPath
} catch {
    "$(Get-Date -Format o) Windows-local shutdown cleanup failed: $($_.Exception.Message)" | Add-Content -Path $logPath
    exit 0
}
