[CmdletBinding()]
param(
    [string]$ProjectRoot = '',
    [string]$AppRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ProjectRoot) { $ProjectRoot = Split-Path -Parent $PSScriptRoot }
if (-not $AppRoot) { $AppRoot = Join-Path $env:LOCALAPPDATA 'sing-box-vultr-dual' }

$legacyStatePath = Join-Path $ProjectRoot 'vultr-waw\current-edge.json'
$stateRoot = Join-Path $AppRoot 'state'
$generatedRoot = Join-Path $stateRoot 'generated'
$newStatePath = Join-Path $stateRoot 'current-edge.json'

New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
New-Item -ItemType Directory -Path $generatedRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath $legacyStatePath)) {
    Write-Host "Legacy state not found: $legacyStatePath"
    return
}

$state = Get-Content -LiteralPath $legacyStatePath -Raw | ConvertFrom-Json
$sourceBundleRoot = if ($state.paths.local_stack) { Split-Path -Parent $state.paths.local_stack } else { '' }

if ($sourceBundleRoot -and (Test-Path -LiteralPath $sourceBundleRoot)) {
    $targetBundleRoot = Join-Path $generatedRoot (Split-Path -Leaf $sourceBundleRoot)
    robocopy $sourceBundleRoot $targetBundleRoot /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -gt 7) {
        throw "Robocopy failed with exit code $LASTEXITCODE"
    }

    if ($state.paths.PSObject.Properties.Name -contains 'local_stack') {
        $state.paths.local_stack = Join-Path $targetBundleRoot 'stack'
    }
    if ($state.paths.PSObject.Properties.Name -contains 'scoped_private_key') {
        $state.paths.scoped_private_key = Join-Path $targetBundleRoot 'id_rsa'
    }
    if ($state.paths.PSObject.Properties.Name -contains 'known_hosts') {
        $state.paths.known_hosts = Join-Path $targetBundleRoot 'known_hosts'
    }

    $migratedKeyPath = Join-Path $targetBundleRoot 'id_rsa'
    if (Test-Path -LiteralPath $migratedKeyPath) {
        & icacls $migratedKeyPath /inheritance:r | Out-Null
        & icacls $migratedKeyPath /grant:r "$env:USERNAME`:R" | Out-Null
    }
}

[System.IO.File]::WriteAllText($newStatePath, ($state | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
Write-Host "State migrated to: $newStatePath"
