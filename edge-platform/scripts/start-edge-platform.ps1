param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [int]$NetworkWaitSeconds = 120
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$intentPath = Join-Path $runtimeDir "shutdown-intent.flag"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$bootStamp = $boot.ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$bootScanPath = Join-Path $runtimeDir ("boot-scan-" + $bootStamp + ".done")

# A Kernel-Power 41 / EventLog 6008 immediately after this boot means Windows
# had no opportunity to run the shutdown task. Mark it once per boot so the
# old VM is reaped instead of being renewed by the normal reconcile cycle.
if (-not (Test-Path $bootScanPath)) {
    Set-Content -NoNewline -Path $bootScanPath -Value (Get-Date -Format o)
    $unexpectedShutdown = Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $boot; EndTime = $boot.AddMinutes(2) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 41, 6008 } | Select-Object -First 1
    if ($unexpectedShutdown) {
        Set-Content -NoNewline -Path $intentPath -Value (Get-Date -Format o)
    }
}

$deadline = (Get-Date).AddSeconds($NetworkWaitSeconds)
do {
    if (Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

& (Join-Path $RepoRoot "edge-platform\scripts\ensure-edge-controller.ps1") -RepoRoot $RepoRoot
if (Test-Path $intentPath) {
    try {
        $env:EDGE_LIFECYCLE_REASON = "unexpected_shutdown_recovery"
        & "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" destroy | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Local stale VM deletion failed" }
        & "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-console.exe" deploy | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Replacement VM deployment failed" }
        Remove-Item -LiteralPath $intentPath -Force -ErrorAction SilentlyContinue
    } catch {
        "$(Get-Date -Format o) Local recovery failed: $($_.Exception.Message)" | Add-Content -Path (Join-Path $runtimeDir "reconcile.log")
    } finally {
        Remove-Item Env:EDGE_LIFECYCLE_REASON -ErrorAction SilentlyContinue
    }
    $recreateDeadline = (Get-Date).AddMinutes(3)
    do {
        break
        Start-Sleep -Seconds 15
    } while ((Get-Date) -lt $recreateDeadline)
    exit 0
}
& (Join-Path $RepoRoot "edge-platform\scripts\reconcile-edge-platform.ps1") -RepoRoot $RepoRoot
