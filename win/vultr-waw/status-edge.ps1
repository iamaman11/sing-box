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

$state | ConvertTo-Json -Depth 10
& ssh @sshBase "root@$($state.ip)" "hostnamectl; echo; uptime; echo; free -m; echo; docker ps --format '{{.Names}}`t{{.Status}}`t{{.Ports}}'; echo; docker stats --no-stream --format '{{.Name}}`t{{.CPUPerc}}`t{{.MemUsage}}'"
