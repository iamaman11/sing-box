param(
    [string]$VaultRecord = "edge.proxy-credentials-v1",
    [string]$HostName = "edge.alegria.by",
    [string]$WslDistribution = "Ubuntu",
    [string]$VaultPath = "/home/bose/projects/secret-vault/bin/secret-vault"
)

$ErrorActionPreference = "Stop"

# `show` is intentional here: this is the explicit, local user-facing export
# command. Do not redirect its output to logs or commit it to files.
$raw = & wsl.exe -d $WslDistribution -- $VaultPath show $VaultRecord --confirm $VaultRecord
if ($LASTEXITCODE -ne 0) { throw "Vault could not reveal $VaultRecord (exit $LASTEXITCODE)" }
$credentials = ([string]$raw | ConvertFrom-Json -ErrorAction Stop)
if ([string]::IsNullOrWhiteSpace([string]$credentials.username) -or
    [string]::IsNullOrWhiteSpace([string]$credentials.password)) {
    throw "Vault record does not contain proxy username/password"
}

$user = [Uri]::EscapeDataString([string]$credentials.username)
$password = [Uri]::EscapeDataString([string]$credentials.password)
$authority = "$user`:$password@$HostName"

@(
    "VM HTTP    http://$authority`:4128",
    "VM SOCKS5  socks5h://$authority`:4080",
    "VM HTTPS   https://$authority`:4443",
    "WARP HTTP  http://$authority`:3128",
    "WARP SOCKS5 socks5h://$authority`:1080",
    "WARP HTTPS https://$authority`:9443"
) | ForEach-Object { Write-Output $_ }
