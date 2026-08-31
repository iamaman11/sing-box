param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box"
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$logPath = Join-Path $runtimeDir "shutdown-cleanup.log"
$intentPath = Join-Path $runtimeDir "shutdown-intent.flag"
# Persist intent before any network operation. If Windows terminates this task,
# the next boot will delete and replace the recorded VM locally.
Set-Content -NoNewline -Path $intentPath -Value (Get-Date -Format o)
try {
    & (Join-Path $RepoRoot "edge-platform\scripts\ensure-edge-controller.ps1") -RepoRoot $RepoRoot | Add-Content -Path $logPath
    $env:EDGE_LIFECYCLE_REASON = "planned_shutdown"
    & "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" destroy 2>&1 | Add-Content -Path $logPath
    if ($LASTEXITCODE -ne 0) { throw "Local VM destroy failed with exit code $LASTEXITCODE" }
    Remove-Item -LiteralPath $intentPath -Force -ErrorAction SilentlyContinue
    "$(Get-Date -Format o) Local VM deletion completed" | Add-Content -Path $logPath
} catch {
    "$(Get-Date -Format o) Local shutdown deletion failed; next boot will recover: $($_.Exception.Message)" | Add-Content -Path $logPath
    exit 0
} finally {
    Remove-Item Env:EDGE_LIFECYCLE_REASON -ErrorAction SilentlyContinue
}
