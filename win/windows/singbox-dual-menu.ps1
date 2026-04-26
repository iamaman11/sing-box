[CmdletBinding()]
param(
    [string]$Controller = 'http://127.0.0.1:9090',
    [string]$SingBoxPath = 'V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe',
    [string]$ConfigPath = '',
    [string]$DeployScript = '',
    [string]$DestroyScript = '',
    [string]$SyncConfigScript = '',
    [string]$StatePath = '',
    [string]$TunnelDomain = 'edge.alegria.by',
    [string]$AcmeEmail = 'admin@alegria.by',
    [string]$SecretsPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:StatusCache = @{}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$AppRoot = Join-Path $env:LOCALAPPDATA 'sing-box-vultr-dual'
$StateRoot = Join-Path $AppRoot 'state'
$LegacyStatePath = Join-Path $ProjectRoot 'vultr-waw\current-edge.json'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'edge-dns-clean-vultr-dual.json' }
if (-not $DeployScript) { $DeployScript = Join-Path $ProjectRoot 'vultr-waw\deploy-waw.ps1' }
if (-not $DestroyScript) { $DestroyScript = Join-Path $ProjectRoot 'vultr-waw\destroy-edge.ps1' }
if (-not $SyncConfigScript) { $SyncConfigScript = Join-Path $PSScriptRoot 'sync-vultr-dual-config.ps1' }
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
if (-not $SecretsPath) { $SecretsPath = Join-Path $PSScriptRoot 'local-secrets.ps1' }

if (Test-Path -LiteralPath $SecretsPath) {
    . $SecretsPath
}

function Get-Proxies {
    Invoke-RestMethod -Method GET -Uri "$Controller/proxies"
}

function Get-CachedValue {
    param(
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [int]$TtlSeconds,
        [Parameter(Mandatory)] [scriptblock]$Factory
    )

    if ($script:StatusCache.ContainsKey($Key)) {
        $entry = $script:StatusCache[$Key]
        if ($entry -and $entry.PSObject.Properties.Name -contains 'Timestamp') {
            $age = ((Get-Date) - $entry.Timestamp).TotalSeconds
            if ($age -lt $TtlSeconds) {
                return $entry.Value
            }
        }
    }

    $value = & $Factory
    $script:StatusCache[$Key] = [pscustomobject]@{
        Timestamp = Get-Date
        Value = $value
    }
    return $value
}

function Clear-StatusCache {
    param([string[]]$Keys)

    if (-not $Keys -or $Keys.Count -eq 0) {
        $script:StatusCache.Clear()
        return
    }

    foreach ($key in $Keys) {
        if ($script:StatusCache.ContainsKey($key)) {
            $script:StatusCache.Remove($key)
        }
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

function Get-VultrServerStatus {
    return Get-CachedValue -Key 'vultr-server-status' -TtlSeconds 10 -Factory {
        $result = [ordered]@{
            state_file = $false
            instance_id = ''
            ip = ''
            exists = $false
            status = 'unknown'
            error = ''
            api_reachable = $false
        }

        if (-not (Test-Path -LiteralPath $StatePath)) {
            $result.error = 'state file not found'
            return [pscustomobject]$result
        }

        $result.state_file = $true
        try {
            $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
            $result.instance_id = [string]$state.instance_id
            $result.ip = [string]$state.ip
        } catch {
            $result.error = 'invalid state file'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($result.instance_id)) {
            $result.error = 'instance_id missing in state'
            return [pscustomobject]$result
        }

        $apiKey = Read-SecretValue -EnvName 'VULTR_API_KEY' -Prompt 'Enter VULTR_API_KEY'
        try {
            $instance = Invoke-RestMethod -Method GET -TimeoutSec 10 -Headers @{ Authorization = "Bearer $apiKey" } -Uri "https://api.vultr.com/v2/instances/$($result.instance_id)"
            $result.api_reachable = $true
            if ($instance.instance) {
                $result.exists = $true
                $result.status = [string]$instance.instance.status
                if ($instance.instance.main_ip) {
                    $result.ip = [string]$instance.instance.main_ip
                }
            }
        } catch {
            $response = $null
            if ($_.Exception -and $_.Exception.PSObject.Properties.Name -contains 'Response') {
                $response = $_.Exception.Response
            }
            if ($response -and [int]$response.StatusCode -eq 404) {
                $result.api_reachable = $true
                $result.exists = $false
                $result.status = 'missing'
                $result.error = 'instance not found in Vultr'
            } else {
                $result.error = $_.Exception.Message
            }
        }

        return [pscustomobject]$result
    }
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

function Get-SshBaseArguments {
    param(
        [Parameter(Mandatory)] [object]$State,
        [Parameter(Mandatory)] [string]$RemoteHost
    )

    $knownHostsPath = Ensure-KnownHostsPath -State $State
    return @(
        '-i', $State.paths.scoped_private_key,
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$knownHostsPath",
        '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=5',
        "root@$RemoteHost"
    )
}

function Get-VultrBackendHealth {
    return Get-CachedValue -Key 'vultr-backend-health' -TtlSeconds 15 -Factory {
        $result = [ordered]@{
            checked = $false
            ready = $false
            note = ''
        }

        $server = Get-VultrServerStatus
        $state = Get-CurrentState
        if (-not $state) {
            $result.note = 'invalid state file'
            return [pscustomobject]$result
        }

        $remoteIp = ''
        if ($server.ip) {
            $remoteIp = [string]$server.ip
        } elseif ($state.ip) {
            $remoteIp = [string]$state.ip
        }
        if ([string]::IsNullOrWhiteSpace($remoteIp)) {
            $result.note = 'server IP unavailable'
            return [pscustomobject]$result
        }

        if (-not $state.paths.scoped_private_key -or -not (Test-Path -LiteralPath $state.paths.scoped_private_key)) {
            $result.note = 'scoped ssh key not found'
            return [pscustomobject]$result
        }

        try {
            $sshBase = Get-SshBaseArguments -State $state -RemoteHost $remoteIp
            $output = & ssh @sshBase 'if ! command -v docker >/dev/null 2>&1; then echo docker_missing; exit 0; fi; docker ps --format "{{.Names}}"'
            $result.checked = $true
            $lines = @($output | Where-Object { $_ })
            if ($lines -contains 'docker_missing') {
                $result.note = 'docker missing'
                return [pscustomobject]$result
            }

            $required = @(
                'vultr-warp-egress',
                'vultr-edge-gateway',
                'vultr-edge-gateway-direct',
                'vultr-tunnel-edge',
                'vultr-tunnel-edge-warp'
            )

            $missing = @($required | Where-Object { $_ -notin $lines })
            if ($missing.Count -eq 0) {
                $result.ready = $true
                if ($server.error) {
                    $result.note = "all containers running (Vultr API note: $($server.error))"
                } else {
                    $result.note = 'all containers running'
                }
            } else {
                $result.note = 'missing containers: ' + ($missing -join ', ')
            }
        } catch {
            $result.note = $_.Exception.Message
        }

        return [pscustomobject]$result
    }
}

function Get-CurrentTunnelTrace {
    return Get-CachedValue -Key 'current-tunnel-trace' -TtlSeconds 5 -Factory {
        $result = [ordered]@{
            available = $false
            ip = ''
            warp = ''
            colo = ''
            note = ''
        }

        try {
            $trace = & curl.exe --silent --show-error --max-time 5 --proxy 'http://127.0.0.1:7890' https://cloudflare.com/cdn-cgi/trace
            $result.available = $true
            $result.ip = ($trace | Select-String '^ip=(.+)$').Matches.Groups[1].Value
            $result.warp = ($trace | Select-String '^warp=(.+)$').Matches.Groups[1].Value
            $result.colo = ($trace | Select-String '^colo=(.+)$').Matches.Groups[1].Value
        } catch {
            $result.note = $_.Exception.Message
        }

        return [pscustomobject]$result
    }
}

function Read-SecretValue {
    param(
        [Parameter(Mandatory)] [string]$EnvName,
        [Parameter(Mandatory)] [string]$Prompt
    )

    $value = [Environment]::GetEnvironmentVariable($EnvName, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = [Environment]::GetEnvironmentVariable($EnvName, 'User')
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        if ($EnvName -eq 'VULTR_API_KEY' -and $script:VultrApiKey) {
            $value = $script:VultrApiKey
        } elseif ($EnvName -eq 'CLOUDFLARE_API_TOKEN' -and $script:CloudflareApiToken) {
            $value = $script:CloudflareApiToken
        }
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = Read-Host $Prompt
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$EnvName is required."
    }
    return $value.Trim()
}

function Start-SingBoxWindow {
    $localSingBox = Get-LocalSingBoxStatus
    if ($localSingBox.running -and -not $localSingBox.expected_config) {
        Write-Host ''
        Write-Host 'Cannot start dual sing-box: another sing-box config is currently running'
        Write-Host "PID         : $($localSingBox.process_id)"
        Write-Host "Command line: $($localSingBox.command_line)"
        Write-Host 'Stop that process manually first, or keep using the current config.'
        Write-Host ''
        return
    }

    $backend = Get-VultrBackendHealth
    if (-not $backend.ready) {
        Write-Host ''
        Write-Host 'Cannot start local sing-box: Vultr backend is not ready'
        Write-Host "Backend note: $($backend.note)"
        Write-Host 'Run 11 first and wait for a successful deploy.'
        Write-Host ''
        return
    }

    if (Test-Path -LiteralPath $SyncConfigScript) {
        & $SyncConfigScript -ConfigPath $ConfigPath -StatePath $StatePath | Out-Host
    }

    if ($localSingBox.running -and $localSingBox.expected_config) {
        Get-Process -Id $localSingBox.process_id -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    Start-Process powershell -WorkingDirectory (Split-Path -Parent $ConfigPath) -ArgumentList '-NoExit', '-Command', "& '$SingBoxPath' run -c '$ConfigPath'"
    Clear-StatusCache
    Write-Host ''
    Write-Host 'sing-box started in a new PowerShell window'
    Write-Host ''
}

function Stop-SingBoxWindow {
    $localSingBox = Get-LocalSingBoxStatus
    if (-not $localSingBox.running) {
        Write-Host ''
        Write-Host 'sing-box is not running'
        Write-Host ''
        return
    }

    if (-not $localSingBox.expected_config) {
        Write-Host ''
        Write-Host 'Refusing to stop sing-box because the active process is not the dual config'
        Write-Host "PID         : $($localSingBox.process_id)"
        Write-Host "Command line: $($localSingBox.command_line)"
        Write-Host ''
        return
    }

    Get-Process -Id $localSingBox.process_id -ErrorAction SilentlyContinue | Stop-Process -Force
    Clear-StatusCache
    Write-Host ''
    Write-Host 'sing-box stopped'
    Write-Host ''
}

function Create-Or-RedeployServer {
    $server = Get-VultrServerStatus
    $apiKey = Read-SecretValue -EnvName 'VULTR_API_KEY' -Prompt 'Enter VULTR_API_KEY'
    $cfToken = Read-SecretValue -EnvName 'CLOUDFLARE_API_TOKEN' -Prompt 'Enter CLOUDFLARE_API_TOKEN'
    Write-Host ''
    if ($server.exists -eq $true) {
        Write-Host "Redeploying existing server: $($server.instance_id)"
    } else {
        Write-Host 'No active Vultr server found, creating/redeploying now...'
    }
    Write-Host ''
    $env:VULTR_API_KEY = $apiKey
    $env:CLOUDFLARE_API_TOKEN = $cfToken
    try {
        if ($server.exists -eq $true -and $server.instance_id) {
            & $DeployScript -TunnelDomain $TunnelDomain -AcmeEmail $AcmeEmail -InstanceId $server.instance_id | Out-Host
        } else {
            & $DeployScript -TunnelDomain $TunnelDomain -AcmeEmail $AcmeEmail | Out-Host
        }
        Clear-StatusCache
        Write-Host ''
        if (Test-Path -LiteralPath $SyncConfigScript) {
            & $SyncConfigScript -ConfigPath $ConfigPath -StatePath $StatePath | Out-Host
            Write-Host ''
        }
        $backend = Get-VultrBackendHealth
        Write-Host "Backend ready         : $($backend.ready)"
        Write-Host "Backend note          : $($backend.note)"
        Write-Host ''
    } catch {
        Clear-StatusCache
        Write-Host ''
        Write-Host "Deploy failed: $($_.Exception.Message)"
        Write-Host ''
    }
}

function Destroy-Server {
    $server = Get-VultrServerStatus
    if ($server.exists -ne $true) {
        Write-Host ''
        Write-Host 'No active Vultr server found'
        if ($server.instance_id) {
            Write-Host "Last known instance id: $($server.instance_id)"
        }
        if ($server.error) {
            Write-Host "Note: $($server.error)"
        }
        Write-Host ''
        return
    }

    $apiKey = Read-SecretValue -EnvName 'VULTR_API_KEY' -Prompt 'Enter VULTR_API_KEY'
    $answer = Read-Host 'Delete current Vultr server? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host ''
        Write-Host 'Cancelled'
        Write-Host ''
        return
    }

    Write-Host ''
    Write-Host 'Deleting server in this window...'
    Write-Host ''
    try {
        & $DestroyScript -ApiKey $apiKey -InstanceId $server.instance_id | Out-Host
        Clear-StatusCache
        Write-Host 'Server deleted or delete accepted by API'
        Write-Host ''
        Write-Host ''
    } catch {
        Clear-StatusCache
        Write-Host "Delete failed: $($_.Exception.Message)"
        Write-Host ''
    }
}

function Set-ProxySelection {
    param(
        [Parameter(Mandatory)] [string]$Group,
        [Parameter(Mandatory)] [string]$Name
    )

    $body = @{ name = $Name } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method PUT -Uri "$Controller/proxies/$Group" -ContentType 'application/json' -Body $body | Out-Null
}

function Show-Status {
    param([switch]$Fast)

    $proxies = $null
    try {
        $proxies = Get-Proxies
    } catch {
    }
    $server = Get-VultrServerStatus
    $backend = if ($Fast) {
        [pscustomobject]@{ ready = $false; note = 'skipped in fast mode' }
    } else {
        Get-VultrBackendHealth
    }
    $localSingBox = Get-LocalSingBoxStatus
    $trace = $null
    $serverExistsDisplay = if ($server.api_reachable) {
        if ($server.exists) { 'True' } else { 'False' }
    } else {
        'unknown'
    }
    if ($localSingBox.running -and $localSingBox.expected_config) {
        $trace = Get-CurrentTunnelTrace
    }

    Write-Host ''
    Write-Host 'Current status'
    Write-Host "Local sing-box         : $(if ($localSingBox.running) { 'running' } else { 'stopped' })"
    Write-Host "Local sing-box config  : $(if ($localSingBox.expected_config) { 'expected dual config' } elseif ($localSingBox.running) { 'different config' } else { '-' })"
    if ($localSingBox.process_id) {
        Write-Host "Local sing-box PID     : $($localSingBox.process_id)"
    }
    if ($localSingBox.note) {
        Write-Host "Local sing-box note    : $($localSingBox.note)"
    }
    Write-Host "Vultr server exists    : $serverExistsDisplay"
    Write-Host "Vultr server status    : $($server.status)"
    Write-Host "Vultr instance id      : $($server.instance_id)"
    Write-Host "Vultr server IP        : $($server.ip)"
    if ($server.error) {
        Write-Host "Vultr note             : $($server.error)"
    }
    Write-Host "Vultr backend ready    : $(if ($Fast) { 'cached/skip' } else { $backend.ready })"
    if ($backend.note) {
        Write-Host "Vultr backend note     : $($backend.note)"
    }
    if ($proxies) {
        Write-Host "proxy-selector         : $($proxies.proxies.'proxy-selector'.now)"
        Write-Host "auto-direct-tunnel     : $($proxies.proxies.'auto-direct-tunnel'.now)"
        Write-Host "auto-warp-tunnel       : $($proxies.proxies.'auto-warp-tunnel'.now)"
    } else {
        Write-Host 'proxy-selector         : sing-box API unavailable'
    }
    if ($trace -and $trace.available) {
        Write-Host "Current tunnel IP      : $($trace.ip)"
        Write-Host "Current tunnel WARP    : $($trace.warp)"
        Write-Host "Current tunnel colo    : $($trace.colo)"
    } elseif ($trace -and $trace.note) {
        Write-Host "Current tunnel note    : $($trace.note)"
    }
    Write-Host ''
}

function Show-CurrentIp {
    Write-Host ''
    Clear-StatusCache -Keys @('current-tunnel-trace')
    $trace = Get-CurrentTunnelTrace
    if (-not $trace.available) {
        Write-Host "Current tunnel note : $($trace.note)"
        Write-Host ''
        return
    }
    Write-Host "Current tunnel IP : $($trace.ip)"
    Write-Host "WARP              : $($trace.warp)"
    Write-Host "Colo              : $($trace.colo)"
    Write-Host ''
}

function Set-MainSelection {
    param(
        [Parameter(Mandatory)] [string]$Name
    )

    $proxies = Get-Proxies
    $current = $proxies.proxies.'proxy-selector'.now
    if ($current -eq $Name) {
        Write-Host ''
        Write-Host "Already selected: $Name"
        Write-Host ''
        Show-Status -Fast
        return
    }

    Set-ProxySelection -Group 'proxy-selector' -Name $Name
    Clear-StatusCache -Keys @('current-tunnel-trace')
    Write-Host ''
    Write-Host "Changed: $current -> $Name"
    Write-Host ''
    Show-Status -Fast
}

function Show-Menu {
    Write-Host ''
    Write-Host '1. Status'
    Write-Host '2. Direct tunnel -> auto'
    Write-Host '3. Direct tunnel -> hysteria2'
    Write-Host '4. Direct tunnel -> vless'
    Write-Host '5. WARP tunnel -> auto'
    Write-Host '6. WARP tunnel -> hysteria2'
    Write-Host '7. WARP tunnel -> vless'
    Write-Host '8. Show current IP'
    Write-Host '9. Start sing-box (new window)'
    Write-Host '10. Stop sing-box'
    Write-Host '11. Create/redeploy Vultr server'
    Write-Host '12. Delete current Vultr server'
    Write-Host '13. Open UI'
    Write-Host '0. Exit'
    Write-Host ''
}

while ($true) {
    Show-Menu
    $choice = Read-Host 'Select'

    switch ($choice) {
        '1' { Show-Status }
        '2' { Set-MainSelection -Name 'auto-direct-tunnel' }
        '3' { Set-MainSelection -Name 'hysteria2-direct' }
        '4' { Set-MainSelection -Name 'vless-reality-direct' }
        '5' { Set-MainSelection -Name 'auto-warp-tunnel' }
        '6' { Set-MainSelection -Name 'hysteria2-warp' }
        '7' { Set-MainSelection -Name 'vless-reality-warp' }
        '8' { Show-CurrentIp }
        '9' { Start-SingBoxWindow }
        '10' { Stop-SingBoxWindow }
        '11' { Create-Or-RedeployServer }
        '12' { Destroy-Server }
        '13' { Start-Process 'http://127.0.0.1:9090/ui/#/proxies' }
        '0' { return }
        default { Write-Host 'Unknown option' }
    }
}
