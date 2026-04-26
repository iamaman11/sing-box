[CmdletBinding()]
param(
    [string]$ApiKey = $env:VULTR_API_KEY,
    [string]$CloudflareApiToken = $env:CLOUDFLARE_API_TOKEN,
    [string]$TunnelDomain = 'edge.alegria.by',
    [string]$AcmeEmail = 'admin@alegria.by',
    [string]$StatePath = '',
    [string]$DeployScript = '',
    [string]$DestroyScript = '',
    [string]$SingBoxPath = 'V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe',
    [string]$ConfigPath = '',
    [string]$SyncConfigScript = '',
    [string]$MenuScript = '',
    [string]$SecretsPath = '',
    [switch]$AutoCreate,
    [switch]$OpenUi,
    [switch]$OpenMenu,
    [switch]$DestroyOnExit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$ProjectRoot = Split-Path -Parent $PSScriptRoot
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
if (-not $DeployScript) { $DeployScript = Join-Path $ProjectRoot 'vultr-waw\deploy-waw.ps1' }
if (-not $DestroyScript) { $DestroyScript = Join-Path $ProjectRoot 'vultr-waw\destroy-edge.ps1' }
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'edge-dns-clean-vultr-dual.json' }
if (-not $SyncConfigScript) { $SyncConfigScript = Join-Path $PSScriptRoot 'sync-vultr-dual-config.ps1' }
if (-not $MenuScript) { $MenuScript = Join-Path $PSScriptRoot 'singbox-dual-menu.ps1' }
if (-not $SecretsPath) { $SecretsPath = Join-Path $PSScriptRoot 'local-secrets.ps1' }

if (Test-Path -LiteralPath $SecretsPath) {
    . $SecretsPath
}

function Invoke-VultrApi {
    param(
        [ValidateSet('GET')] [string]$Method,
        [string]$Uri
    )

    $headers = @{ Authorization = "Bearer $ApiKey" }
    Invoke-RestMethod -Method $Method -Headers $headers -Uri $Uri
}

function Get-CurrentState {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Repair-ScopedKeyPermissions {
    param([Parameter(Mandatory)] [string]$KeyPath)

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        throw "Scoped ssh key not found: $KeyPath"
    }

    & icacls $KeyPath /inheritance:r | Out-Null
    & icacls $KeyPath /grant:r "$env:USERNAME`:R" | Out-Null
}

function Ensure-KnownHostsPath {
    param([Parameter(Mandatory)] [object]$State)

    if (-not $State.paths.scoped_private_key -or -not (Test-Path -LiteralPath $State.paths.scoped_private_key)) {
        throw 'scoped ssh key not found'
    }

    Repair-ScopedKeyPermissions -KeyPath $State.paths.scoped_private_key

    $knownHostsPath = ''
    if ($State.paths.PSObject.Properties.Name -contains 'known_hosts' -and $State.paths.known_hosts) {
        $knownHostsPath = [string]$State.paths.known_hosts
    } else {
        $knownHostsPath = Join-Path (Split-Path -Parent $State.paths.scoped_private_key) 'known_hosts'
    }

    if (-not (Test-Path -LiteralPath $knownHostsPath)) {
        New-Item -ItemType File -Path $knownHostsPath -Force | Out-Null
    }

    $existingContent = try { Get-Content -LiteralPath $knownHostsPath -Raw } catch { '' }

    if (-not ($existingContent -match '\S')) {
        $acceptNewArgs = @(
            '-i', $State.paths.scoped_private_key,
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', "UserKnownHostsFile=$knownHostsPath",
            '-o', 'IdentitiesOnly=yes',
            '-o', 'ConnectTimeout=5',
            "root@$($State.ip)",
            'exit'
        )

        & ssh @acceptNewArgs 2>$null | Out-Null
        $existingContent = try { Get-Content -LiteralPath $knownHostsPath -Raw } catch { '' }
        if (-not ($existingContent -match '\S')) {
            throw "Unable to initialize SSH known_hosts for $($State.ip)"
        }

        if (-not ($State.paths.PSObject.Properties.Name -contains 'known_hosts')) {
            $State.paths | Add-Member -NotePropertyName 'known_hosts' -NotePropertyValue $knownHostsPath -Force
            $json = $State | ConvertTo-Json -Depth 20
            [System.IO.File]::WriteAllText($StatePath, $json, [System.Text.UTF8Encoding]::new($false))
        }
    }

    return $knownHostsPath
}

function Get-ExistingInstance {
    $state = Get-CurrentState
    if (-not $state -or [string]::IsNullOrWhiteSpace($state.instance_id)) {
        return $null
    }

    try {
        return (Invoke-VultrApi -Method GET -Uri "https://api.vultr.com/v2/instances/$($state.instance_id)").instance
    } catch {
        return $null
    }
}

function Test-BackendReady {
    $state = Get-CurrentState
    if (-not $state) {
        return $false
    }

    $keyPath = $state.paths.scoped_private_key
    if (-not $keyPath -or -not (Test-Path -LiteralPath $keyPath)) {
        return $false
    }

    try {
        $knownHostsPath = Ensure-KnownHostsPath -State $state
        $sshBase = @(
            '-i', $keyPath,
            '-o', 'StrictHostKeyChecking=yes',
            '-o', "UserKnownHostsFile=$knownHostsPath",
            '-o', 'IdentitiesOnly=yes'
        )
        $output = & ssh @sshBase "root@$($state.ip)" 'if ! command -v docker >/dev/null 2>&1; then echo docker_missing; exit 0; fi; docker ps --format "{{.Names}}"' 2>$null
        $lines = @($output | Where-Object { $_ })
        if ($lines -contains 'docker_missing') {
            return $false
        }

        $required = @(
            'vultr-warp-egress',
            'vultr-edge-gateway',
            'vultr-edge-gateway-direct',
            'vultr-tunnel-edge',
            'vultr-tunnel-edge-warp'
        )
        return (@($required | Where-Object { $_ -notin $lines }).Count -eq 0)
    } catch {
        return $false
    }
}

function Get-LocalSingBoxStatus {
    $result = [ordered]@{
        running = $false
        expected_config = $false
        process_id = ''
        command_line = ''
        note = ''
    }

    $process = Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -ieq 'sing-box.exe'
        } |
        Select-Object -First 1

    if (-not $process) {
        $result.note = 'not running'
        return [pscustomobject]$result
    }

    $result.running = $true
    $result.process_id = [string]$process.ProcessId
    $result.command_line = [string]$process.CommandLine

    if ($process.CommandLine -like "*$ConfigPath*") {
        $result.expected_config = $true
        $result.note = 'running expected dual config'
    } else {
        $result.note = 'running different config'
    }

    return [pscustomobject]$result
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    $ApiKey = if ($script:VultrApiKey) { $script:VultrApiKey } else { Read-Host 'Enter VULTR_API_KEY' }
}

$instance = Get-ExistingInstance
if (-not $instance) {
    if (-not $AutoCreate) {
        $answer = Read-Host 'Vultr server not found. Create it now? [Y/n]'
        if ($answer -match '^(n|no)$') {
            Write-Host 'Cancelled.'
            return
        }
    }

    if ([string]::IsNullOrWhiteSpace($CloudflareApiToken)) {
        $CloudflareApiToken = if ($script:CloudflareApiToken) { $script:CloudflareApiToken } else { Read-Host 'Enter CLOUDFLARE_API_TOKEN' }
    }

    $env:VULTR_API_KEY = $ApiKey
    $env:CLOUDFLARE_API_TOKEN = $CloudflareApiToken
    & powershell -ExecutionPolicy Bypass -File $DeployScript -TunnelDomain $TunnelDomain -AcmeEmail $AcmeEmail | Out-Host
    $instance = Get-ExistingInstance
    if (-not $instance) {
        throw 'Server creation/deploy did not produce an active instance.'
    }
}

if (-not (Test-BackendReady)) {
    throw 'Vultr backend is not ready. Do not start local sing-box yet.'
}

if (Test-Path -LiteralPath $SyncConfigScript) {
    & powershell -ExecutionPolicy Bypass -File $SyncConfigScript -ConfigPath $ConfigPath -StatePath $StatePath | Out-Host
}

$localSingBox = Get-LocalSingBoxStatus
if ($localSingBox.running -and -not $localSingBox.expected_config) {
    throw "Another sing-box config is already running (PID $($localSingBox.process_id)). Stop it manually before starting the dual client."
}

if ($localSingBox.running -and $localSingBox.expected_config) {
    Get-Process -Id $localSingBox.process_id -ErrorAction SilentlyContinue | Stop-Process -Force
}
$process = Start-Process -FilePath $SingBoxPath -ArgumentList @('run', '-c', $ConfigPath) -WorkingDirectory (Split-Path -Parent $ConfigPath) -PassThru
Start-Sleep -Seconds 3

if ($OpenUi) {
    Start-Process 'http://127.0.0.1:9090/ui/#/proxies'
}

if ($OpenMenu) {
    Start-Process powershell -ArgumentList '-NoExit', '-File', $MenuScript
}

Write-Host ''
Write-Host "sing-box started, PID: $($process.Id)"
Write-Host "UI: http://127.0.0.1:9090/ui/#/proxies"
Write-Host ''

if ($DestroyOnExit) {
    Write-Host 'DestroyOnExit enabled: waiting for sing-box to exit...'
    Wait-Process -Id $process.Id
    $env:VULTR_API_KEY = $ApiKey
    & powershell -ExecutionPolicy Bypass -File $DestroyScript | Out-Host
}
