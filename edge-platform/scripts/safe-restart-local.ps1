param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ConsoleExe = (Join-Path $env:LOCALAPPDATA "edge-platform\bin\edge-console.exe")
)

$ErrorActionPreference = "Stop"
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
$probeScript = Join-Path $RepoRoot "edge-platform\scripts\test-proxy-profiles.ps1"
$metricsPath = Join-Path $runtimeDir "local-restart-metrics.jsonl"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

if (!(Test-Path -LiteralPath $ConsoleExe)) { throw "edge-console is missing: $ConsoleExe" }
if (!(Test-Path -LiteralPath $probeScript)) { throw "proxy probe is missing: $probeScript" }

$started = [DateTimeOffset]::UtcNow
$restartOutput = & $ConsoleExe restart-local 2>&1 | Out-String
$restartSucceeded = $LASTEXITCODE -eq 0
$statusOutput = & $ConsoleExe status 2>&1 | Out-String
$statusSucceeded = $LASTEXITCODE -eq 0
$tunReady = (Get-NetAdapter -Name "utun0" -ErrorAction SilentlyContinue).Status -eq "Up"
$profiles = @()
$probeSucceeded = $false
if ($restartSucceeded -and $tunReady) {
    try {
        $profiles = @(& $probeScript | ConvertFrom-Json)
        $probeSucceeded = @($profiles | Where-Object { -not $_.ok }).Count -eq 0 -and $profiles.Count -eq 6
    } catch {
        $probeSucceeded = $false
    }
}
$finished = [DateTimeOffset]::UtcNow

# Never persist egress IPs or credentials: operation evidence is limited to
# profile name, pass/fail and error class.
$metric = [ordered]@{
    schema_version = 1
    started_at_utc = $started.ToString("o")
    finished_at_utc = $finished.ToString("o")
    duration_ms = [int]($finished - $started).TotalMilliseconds
    singbox_check_and_restart = $restartSucceeded
    tun_ready = $tunReady
    post_restart_probes = @($profiles | ForEach-Object {
        [ordered]@{ profile = $_.profile; ok = [bool]$_.ok; error = $_.error }
    })
    post_restart_probes_passed = $probeSucceeded
    controller_status_available = $statusSucceeded
    rollback_observed = $restartOutput -match "previous local runtime restored"
}
($metric | ConvertTo-Json -Compress -Depth 4) | Add-Content -LiteralPath $metricsPath

if (!$restartSucceeded) { throw "guarded restart failed; see controller operation history" }
if (!$tunReady) { throw "guarded restart completed but utun0 is not Up" }
if (!$probeSucceeded) { throw "guarded restart completed but post-restart proxy probes failed" }
Write-Output "SAFE_LOCAL_RESTART=PASS duration_ms=$($metric.duration_ms) metrics=$metricsPath"
