param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [int]$NetworkWaitSeconds = 120
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$stateDb = Join-Path $runtimeDir "controller-state.sqlite"
if (-not (Test-Path $stateDb)) { throw "Lifecycle database is absent: $stateDb" }
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$bootStamp = $boot.ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

function Invoke-LifecycleSql([string]$Sql) {
    $output = & sqlite3.exe $stateDb $Sql 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SQLite lifecycle update failed: $output" }
    return $output
}
function Escape-SqlLiteral([string]$Value) { return $Value.Replace("'", "''") }
function Get-UnixNow { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

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
CREATE INDEX IF NOT EXISTS recovery_requests_pending_idx
    ON recovery_requests (status, created_at_unix);
"@ | Out-Null

# Migration: file flags had no boot identity and were re-read by the periodic
# task. They are deliberately retired; recovery authority now lives in SQLite.
$legacyIntent = Join-Path $runtimeDir "shutdown-intent.flag"
if (Test-Path $legacyIntent) {
    Remove-Item -LiteralPath $legacyIntent -Force -ErrorAction SilentlyContinue
    "$(Get-Date -Format o) Retired legacy shutdown-intent.flag; SQLite recovery requests are authoritative" | Add-Content -Path (Join-Path $runtimeDir "reconcile.log")
}

# A Kernel-Power 41 / EventLog 6008 after this boot creates exactly one pending
# recovery request. INSERT OR IGNORE makes this idempotent for the boot ID.
$unexpectedShutdown = Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $boot; EndTime = $boot.AddMinutes(2) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 41, 6008 } | Select-Object -First 1
if ($unexpectedShutdown) {
    $requestKey = "unexpected_shutdown:$bootStamp"
    Invoke-LifecycleSql "INSERT OR IGNORE INTO recovery_requests (request_key, boot_id, reason, status, created_at_unix) VALUES ('$(Escape-SqlLiteral $requestKey)', '$(Escape-SqlLiteral $bootStamp)', 'unexpected_shutdown', 'PENDING', $(Get-UnixNow));" | Out-Null
}

$deadline = (Get-Date).AddSeconds($NetworkWaitSeconds)
do {
    if (Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

& (Join-Path $RepoRoot "edge-platform\scripts\ensure-edge-controller.ps1") -RepoRoot $RepoRoot

# Claim one pending recovery atomically. Planned-shutdown requests are only
# eligible after a later boot; unexpected shutdown belongs to this boot.
$pendingRequest = (Invoke-LifecycleSql "SELECT request_key FROM recovery_requests WHERE status='PENDING' AND (request_key='unexpected_shutdown:$(Escape-SqlLiteral $bootStamp)' OR (reason='planned_shutdown' AND boot_id <> '$(Escape-SqlLiteral $bootStamp)')) ORDER BY created_at_unix LIMIT 1;").Trim()
if (-not [string]::IsNullOrWhiteSpace($pendingRequest)) {
    $claimResult = (Invoke-LifecycleSql "UPDATE recovery_requests SET status='RUNNING', claimed_at_unix=$(Get-UnixNow), claimed_by_boot_id='$(Escape-SqlLiteral $bootStamp)' WHERE request_key='$(Escape-SqlLiteral $pendingRequest)' AND status='PENDING'; SELECT changes();").Trim()
    if ($claimResult -ne "1") { exit 0 }
    $recoveryMutex = $null
    $recoveryLockHeld = $false
    try {
        $recoveryMutex = New-Object System.Threading.Mutex($false, "Local\EdgePlatformUnexpectedShutdownRecovery")
        $recoveryLockHeld = $recoveryMutex.WaitOne(0)
        if (-not $recoveryLockHeld) {
            "$(Get-Date -Format o) Recovery already owned by another task; skipped duplicate execution" | Add-Content -Path (Join-Path $runtimeDir "reconcile.log")
            exit 0
        }
        $env:EDGE_LIFECYCLE_REASON = "recovery:$pendingRequest"
        $destroyOutput = & "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" destroy 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Local stale VM deletion failed: $destroyOutput" }
        $deployOutput = & "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" deploy 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Replacement VM deployment failed: $deployOutput" }
        Invoke-LifecycleSql "UPDATE recovery_requests SET status='SUCCEEDED', completed_at_unix=$(Get-UnixNow), last_error=NULL WHERE request_key='$(Escape-SqlLiteral $pendingRequest)' AND status='RUNNING';" | Out-Null
    } catch {
        $errorText = Escape-SqlLiteral $_.Exception.Message
        Invoke-LifecycleSql "UPDATE recovery_requests SET status='FAILED', completed_at_unix=$(Get-UnixNow), last_error='$errorText' WHERE request_key='$(Escape-SqlLiteral $pendingRequest)' AND status='RUNNING';" | Out-Null
        "$(Get-Date -Format o) Local recovery failed: $($_.Exception.Message)" | Add-Content -Path (Join-Path $runtimeDir "reconcile.log")
        exit 1
    } finally {
        Remove-Item Env:EDGE_LIFECYCLE_REASON -ErrorAction SilentlyContinue
        if ($recoveryLockHeld) { $recoveryMutex.ReleaseMutex() }
        if ($recoveryMutex) { $recoveryMutex.Dispose() }
    }
    $recreateDeadline = (Get-Date).AddMinutes(3)
    do {
        break
        Start-Sleep -Seconds 15
    } while ((Get-Date) -lt $recreateDeadline)
    exit 0
}
& (Join-Path $RepoRoot "edge-platform\scripts\reconcile-edge-platform.ps1") -RepoRoot $RepoRoot
