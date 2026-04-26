[CmdletBinding()]
param(
    [string]$StatePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$AppRoot = Join-Path $env:LOCALAPPDATA 'sing-box-vultr-dual'
$StateRoot = Join-Path $AppRoot 'state'
$LegacyStatePath = Join-Path $PSScriptRoot 'current-edge.json'
if (-not $StatePath) {
    $defaultStatePath = Join-Path $StateRoot 'current-edge.json'
    if (Test-Path -LiteralPath $defaultStatePath) {
        $StatePath = $defaultStatePath
    } elseif (Test-Path -LiteralPath $LegacyStatePath) {
        $StatePath = $LegacyStatePath
    } else {
        $StatePath = $defaultStatePath
    }
}

if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "State file not found: $StatePath"
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json

$sshBase = @(
    '-i', $state.paths.scoped_private_key,
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=NUL',
    '-o', 'IdentitiesOnly=yes'
)

Resolve-DnsName $state.dns.record | Select-Object Name,Type,IPAddress
& curl.exe --max-time 30 --proxy "http://$($state.warp_proxy.username):$($state.warp_proxy.password)@$($state.warp_proxy.host):$($state.warp_proxy.http_port)" https://cloudflare.com/cdn-cgi/trace
& curl.exe --max-time 30 --socks5-hostname "$($state.warp_proxy.host):$($state.warp_proxy.socks5_port)" --proxy-user "$($state.warp_proxy.username):$($state.warp_proxy.password)" https://cloudflare.com/cdn-cgi/trace
& curl.exe --max-time 30 --proxy-insecure --proxy "https://$($state.warp_proxy.username):$($state.warp_proxy.password)@$($state.warp_proxy.host):$($state.warp_proxy.https_port)" https://cloudflare.com/cdn-cgi/trace
& curl.exe --max-time 30 --proxy "http://$($state.direct_proxy.username):$($state.direct_proxy.password)@$($state.direct_proxy.host):$($state.direct_proxy.http_port)" https://cloudflare.com/cdn-cgi/trace
& curl.exe --max-time 30 --socks5-hostname "$($state.direct_proxy.host):$($state.direct_proxy.socks5_port)" --proxy-user "$($state.direct_proxy.username):$($state.direct_proxy.password)" https://cloudflare.com/cdn-cgi/trace
& curl.exe --max-time 30 --proxy-insecure --proxy "https://$($state.direct_proxy.username):$($state.direct_proxy.password)@$($state.direct_proxy.host):$($state.direct_proxy.https_port)" https://cloudflare.com/cdn-cgi/trace
& ssh @sshBase "root@$($state.ip)" "docker ps --format '{{.Names}}`t{{.Status}}`t{{.Ports}}'"
