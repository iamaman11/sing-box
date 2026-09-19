param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ConsoleExe = (Join-Path $env:LOCALAPPDATA "edge-platform\bin\edge-console.exe")
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$logPath = Join-Path $runtimeDir "shutdown-cleanup.log"

try {
    if (-not (Test-Path $ConsoleExe)) { throw "edge-console binary not found: $ConsoleExe" }
    & $ConsoleExe stop-local 2>&1 | Add-Content -Path $logPath
    if ($LASTEXITCODE -ne 0) { throw "Windows-local runtime stop failed with exit code $LASTEXITCODE" }
    "$(Get-Date -Format o) Windows-local runtime stopped; VM lifecycle was not touched" | Add-Content -Path $logPath
} catch {
    "$(Get-Date -Format o) Windows-local shutdown cleanup failed: $($_.Exception.Message)" | Add-Content -Path $logPath
    exit 0
}
