param(
    [Parameter(Mandatory = $true)][string]$WorkerUrl,
    [Parameter(Mandatory = $true)][string]$InstanceId,
    [Parameter(Mandatory = $true)][string]$Ip,
    [Parameter(Mandatory = $true)][string]$ExpiresAt
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:LEASE_AUTH_TOKEN)) {
    throw "Lease authentication was not supplied by the vault launcher"
}
$body = @{ instanceId = $InstanceId; ip = $Ip; expiresAt = $ExpiresAt } | ConvertTo-Json -Compress
$response = Invoke-RestMethod -Method Post -Uri ($WorkerUrl.TrimEnd('/') + '/renew') `
    -Headers @{ Authorization = "Bearer $env:LEASE_AUTH_TOKEN" } `
    -ContentType 'application/json' -Body $body -TimeoutSec 20
if (-not $response.ok) { throw "Lease reaper rejected the renewal" }
Write-Output "Lease renewed until $($response.expiresAt)"
