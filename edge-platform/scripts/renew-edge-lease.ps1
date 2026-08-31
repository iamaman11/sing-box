param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$WslDistribution = "Ubuntu",
    [string]$VaultPath = "/home/bose/projects/secret-vault/bin/secret-vault",
    [string]$LeaseAuthVaultRecord = "edge.lease-reaper-auth",
    [int]$LeaseMinutes = 60
)

$ErrorActionPreference = "Stop"

$leaseConfigPath = Join-Path $RepoRoot "edge-platform\.runtime\lease-reaper.json"
$liveStatePath = Join-Path $RepoRoot "win\vultr-waw\current-edge.json"
if (-not (Test-Path $leaseConfigPath)) { throw "Lease-reaper configuration is absent: $leaseConfigPath" }
if (-not (Test-Path $liveStatePath)) { throw "Live edge state is absent: $liveStatePath" }

$leaseConfig = Get-Content -Raw $leaseConfigPath | ConvertFrom-Json
$state = Get-Content -Raw $liveStatePath | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($state.instance_id) -or [string]::IsNullOrWhiteSpace($state.ip)) {
    throw "Live edge state does not contain an instance id and IP"
}

$expiresAt = [DateTime]::UtcNow.AddMinutes($LeaseMinutes).ToString("o")
$postScript = Join-Path $RepoRoot "edge-platform\scripts\post-edge-lease.ps1"
if (-not (Test-Path $postScript)) { throw "Lease post script is absent: $postScript" }
$wslCommand = "export WSLENV=LEASE_AUTH_TOKEN; exec /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$postScript' -WorkerUrl '$($leaseConfig.worker_url)' -InstanceId '$($state.instance_id)' -Ip '$($state.ip)' -ExpiresAt '$expiresAt'"
$oldWslenv = $env:WSLENV
try {
    & wsl.exe -d $WslDistribution -- $VaultPath run $LeaseAuthVaultRecord LEASE_AUTH_TOKEN -- sh -lc $wslCommand
    if ($LASTEXITCODE -ne 0) { throw "Lease renewal failed" }
} finally {
    $env:WSLENV = $oldWslenv
}
