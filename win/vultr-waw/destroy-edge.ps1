[CmdletBinding()]
param(
    [string]$ApiKey = $env:VULTR_API_KEY,
    [string]$InstanceId = '',
    [string]$StatePath = '',
    [string]$SecretsPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$ProjectRoot = Split-Path -Parent $PSScriptRoot
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
if (-not $SecretsPath) { $SecretsPath = Join-Path $ProjectRoot 'windows\local-secrets.ps1' }

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    if (Test-Path -LiteralPath $SecretsPath) {
        . $SecretsPath
        if ($script:VultrApiKey) {
            $ApiKey = $script:VultrApiKey
        }
    }
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    $ApiKey = Read-Host 'Enter VULTR_API_KEY'
}

$ApiKey = $ApiKey.Trim()

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    throw 'VULTR_API_KEY is required.'
}

if ($ApiKey -match '[^\u0000-\u007F]') {
    throw 'VULTR_API_KEY contains non-ASCII characters. Re-enter a plain API token.'
}

if (-not $InstanceId) {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        throw 'InstanceId not provided and state file not found.'
    }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $InstanceId = $state.instance_id
}

try {
    Invoke-RestMethod -Method Delete -TimeoutSec 10 -Headers @{ Authorization = "Bearer $ApiKey" } -Uri "https://api.vultr.com/v2/instances/$InstanceId"
    Write-Host "Delete request sent for instance: $InstanceId"
} catch {
    $response = $null
    if ($_.Exception -and $_.Exception.PSObject.Properties.Name -contains 'Response') {
        $response = $_.Exception.Response
    }
    if ($response -and [int]$response.StatusCode -eq 404) {
        Write-Host "Instance already missing: $InstanceId"
        return
    }
    throw
}
