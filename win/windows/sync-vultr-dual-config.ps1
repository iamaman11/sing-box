[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [string]$StatePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'edge-dns-clean-vultr-dual.json' }
$AppRoot = Join-Path $env:LOCALAPPDATA 'sing-box-vultr-dual'
$StateRoot = Join-Path $AppRoot 'state'
$LegacyStatePath = Join-Path $ProjectRoot 'vultr-waw\current-edge.json'
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
$RuntimeRoot = Join-Path $AppRoot 'runtime'
if (-not (Test-Path -LiteralPath $RuntimeRoot)) {
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
}

function Set-NoteValue {
    param(
        [Parameter(Mandatory)] [object]$Object,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Value
    )

    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}

if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "State file not found: $StatePath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json

$byTag = @{}
foreach ($outbound in $config.outbounds) {
    if ($outbound.tag) {
        $byTag[[string]$outbound.tag] = $outbound
    }
}

$uiPath = Join-Path $RuntimeRoot 'metacubexd-ui'
if ($config.experimental -and $config.experimental.clash_api) {
    Set-NoteValue -Object $config.experimental.clash_api -Name 'external_ui' -Value $uiPath
}
if ($config.experimental -and $config.experimental.cache_file) {
    Set-NoteValue -Object $config.experimental.cache_file -Name 'path' -Value (Join-Path $RuntimeRoot 'cache-dns-vultr-dual.db')
}

$h2Direct = $byTag['hysteria2-direct']
if ($h2Direct) {
    Set-NoteValue -Object $h2Direct -Name 'server' -Value $state.tunnel.domain
    Set-NoteValue -Object $h2Direct -Name 'server_port' -Value $state.tunnel.hy2_port
    Set-NoteValue -Object $h2Direct -Name 'password' -Value $state.tunnel.hy2_password
    Set-NoteValue -Object $h2Direct.tls -Name 'server_name' -Value $state.tunnel.domain
}

$vlessDirect = $byTag['vless-reality-direct']
if ($vlessDirect) {
    Set-NoteValue -Object $vlessDirect -Name 'server' -Value $state.tunnel.domain
    Set-NoteValue -Object $vlessDirect -Name 'server_port' -Value $state.tunnel.vless_port
    Set-NoteValue -Object $vlessDirect -Name 'uuid' -Value $state.tunnel.vless_uuid
    Set-NoteValue -Object $vlessDirect.tls.reality -Name 'public_key' -Value $state.tunnel.reality_public_key
    Set-NoteValue -Object $vlessDirect.tls.reality -Name 'short_id' -Value $state.tunnel.reality_short_id
}

$h2Warp = $byTag['hysteria2-warp']
if ($h2Warp) {
    Set-NoteValue -Object $h2Warp -Name 'server' -Value $state.tunnel_warp.domain
    Set-NoteValue -Object $h2Warp -Name 'server_port' -Value $state.tunnel_warp.hy2_port
    Set-NoteValue -Object $h2Warp -Name 'password' -Value $state.tunnel_warp.hy2_password
    Set-NoteValue -Object $h2Warp.tls -Name 'server_name' -Value $state.tunnel_warp.domain
}

$vlessWarp = $byTag['vless-reality-warp']
if ($vlessWarp) {
    Set-NoteValue -Object $vlessWarp -Name 'server' -Value $state.tunnel_warp.domain
    Set-NoteValue -Object $vlessWarp -Name 'server_port' -Value $state.tunnel_warp.vless_port
    Set-NoteValue -Object $vlessWarp -Name 'uuid' -Value $state.tunnel_warp.vless_uuid
    Set-NoteValue -Object $vlessWarp.tls.reality -Name 'public_key' -Value $state.tunnel_warp.reality_public_key
    Set-NoteValue -Object $vlessWarp.tls.reality -Name 'short_id' -Value $state.tunnel_warp.reality_short_id
}

$json = $config | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($ConfigPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Host "Windows dual config synced from state: $($state.instance_id)"
