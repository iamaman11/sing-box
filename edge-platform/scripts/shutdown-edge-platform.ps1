param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box"
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$logPath = Join-Path $runtimeDir "shutdown-cleanup.log"
$stateDb = Join-Path $runtimeDir "controller-state.sqlite"
if (-not (Test-Path $stateDb)) { throw "Lifecycle database is absent: $stateDb" }

function Invoke-LifecycleSql([string]$Sql) {
    $output = & sqlite3.exe $stateDb $Sql 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SQLite lifecycle update failed: $output" }
    return $output
}
function Escape-SqlLiteral([string]$Value) { return $Value.Replace("'", "''") }

$bootId = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$requestKey = "planned_shutdown:$bootId"
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Invoke-LifecycleSql @"
CREATE TABLE IF NOT EXISTS recovery_requests (
    request_key TEXT PRIMARY KEY,
    boot_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    claimed_at_unix INTEGER,
    completed_at_unix INTEGER,
    claimed_by_boot_id TEXT,
    last_error TEXT
);
INSERT OR IGNORE INTO recovery_requests (request_key, boot_id, reason, status, created_at_unix)
VALUES ('$(Escape-SqlLiteral $requestKey)', '$(Escape-SqlLiteral $bootId)', 'planned_shutdown', 'PENDING', $now);
"@ | Out-Null

# A failed shutdown task leaves one PENDING request for the next boot. A
# successful deletion cancels it below, so it cannot trigger a later recovery.
try {
    & (Join-Path $RepoRoot "edge-platform\scripts\ensure-edge-controller.ps1") -RepoRoot $RepoRoot | Add-Content -Path $logPath
    $env:EDGE_LIFECYCLE_REASON = "planned_shutdown"
    & "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" destroy 2>&1 | Add-Content -Path $logPath
    if ($LASTEXITCODE -ne 0) { throw "Local VM destroy failed with exit code $LASTEXITCODE" }
    Invoke-LifecycleSql "UPDATE recovery_requests SET status='CANCELLED', completed_at_unix=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()), last_error=NULL WHERE request_key='$(Escape-SqlLiteral $requestKey)' AND status='PENDING';" | Out-Null
    "$(Get-Date -Format o) Local VM deletion completed" | Add-Content -Path $logPath
} catch {
    "$(Get-Date -Format o) Local shutdown deletion failed; next boot will recover: $($_.Exception.Message)" | Add-Content -Path $logPath
    exit 0
} finally {
    Remove-Item Env:EDGE_LIFECYCLE_REASON -ErrorAction SilentlyContinue
}
