[CmdletBinding()]
param(
    [string]$ApiKey = $env:VULTR_API_KEY,
    [string]$CloudflareApiToken = $env:CLOUDFLARE_API_TOKEN,
    [string]$CloudflareZoneName = 'alegria.by',
    [string]$DnsRecordName = 'edge.alegria.by',
    [string]$StatePath = '',
    [string]$Region = 'waw',
    [string]$Plan = 'vc2-1c-1gb',
    [int]$OsId = 2136,
    [string]$SshKeyId = 'b379cde0-6ef3-46a0-8cf9-c4faa7cb6dd4',
    [string]$PrivateKeyPath = 'V:\.ssh\vultr_rsa',
    [string]$LabelPrefix = 'waw-edge',
    [string]$InstanceId = '',
    [string]$TargetIp = '',
    [string]$TunnelDomain = '',
    [string]$AcmeEmail = '',
    [string]$EdgeAgentBinaryPath = $env:EDGE_AGENT_BINARY_PATH,
    [string]$WarpEgressImage = $env:EDGE_WARP_EGRESS_IMAGE,
    [string]$GatewayImage = $env:EDGE_GATEWAY_IMAGE,
    [switch]$UsePrebuiltImages,
    [switch]$SkipCreate
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

function New-RandomSecret {
    param([int]$Bytes = 24)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $data = New-Object byte[] $Bytes
    $rng.GetBytes($data)
    [Convert]::ToBase64String($data).TrimEnd('=').Replace('+', 'A').Replace('/', 'B')
}

function New-HexSecret {
    param([int]$Bytes = 8)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $data = New-Object byte[] $Bytes
    $rng.GetBytes($data)
    -join ($data | ForEach-Object { $_.ToString('x2') })
}

function Read-EnvFile {
    param([string]$Path)

    $map = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }

        $parts = $line.Split('=', 2)
        if ($parts.Count -eq 2) {
            $map[$parts[0]] = $parts[1]
        }
    }
    return $map
}

function Invoke-VultrApi {
    param(
        [ValidateSet('GET','POST')] [string]$Method,
        [string]$Uri,
        [object]$Body
    )

    $headers = @{ Authorization = "Bearer $ApiKey" }
    if ($Method -eq 'GET') {
        return Invoke-RestMethod -Method GET -Headers $headers -Uri $Uri
    }

    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    return Invoke-RestMethod -Method POST -Headers $headers -Uri $Uri -ContentType 'application/json' -Body $json
}

function Invoke-CloudflareApi {
    param(
        [ValidateSet('GET','POST','PUT')] [string]$Method,
        [string]$Uri,
        [object]$Body
    )

    $headers = @{ Authorization = "Bearer $CloudflareApiToken" }
    if ($Method -eq 'GET') {
        return Invoke-RestMethod -Method GET -Headers $headers -Uri $Uri
    }

    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    return Invoke-RestMethod -Method $Method -Headers $headers -Uri $Uri -ContentType 'application/json' -Body $json
}

function Update-CloudflareARecord {
    param(
        [string]$ZoneName,
        [string]$RecordName,
        [string]$IpAddress
    )

    if ([string]::IsNullOrWhiteSpace($CloudflareApiToken)) {
        throw 'CLOUDFLARE_API_TOKEN is required for DNS update.'
    }

    $zoneResponse = Invoke-CloudflareApi -Method GET -Uri "https://api.cloudflare.com/client/v4/zones?name=$ZoneName"
    $zoneId = $zoneResponse.result[0].id
    if ([string]::IsNullOrWhiteSpace($zoneId)) {
        throw "Cloudflare zone not found: $ZoneName"
    }

    $recordResponse = Invoke-CloudflareApi -Method GET -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records?type=A&name=$RecordName"
    $body = @{
        type = 'A'
        name = $RecordName
        content = $IpAddress
        ttl = 120
        proxied = $false
    }

    if ($recordResponse.result.Count -gt 0) {
        $recordId = $recordResponse.result[0].id
        [void](Invoke-CloudflareApi -Method PUT -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records/$recordId" -Body $body)
    } else {
        [void](Invoke-CloudflareApi -Method POST -Uri "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records" -Body $body)
    }

    return $zoneId
}

function New-ScopedKeyCopy {
    param(
        [string]$SourcePath,
        [string]$DestinationDirectory
    )

    $targetPath = Join-Path $DestinationDirectory 'id_rsa'
    Copy-Item -LiteralPath $SourcePath -Destination $targetPath -Force
    & icacls $targetPath /inheritance:r | Out-Null
    & icacls $targetPath /grant:r "$env:USERNAME`:R" | Out-Null
    return $targetPath
}

function Initialize-KnownHostsFile {
    param(
        [Parameter(Mandatory)] [string]$HostName,
        [Parameter(Mandatory)] [string]$KeyPath,
        [Parameter(Mandatory)] [string]$DestinationDirectory
    )

    $targetPath = Join-Path $DestinationDirectory 'known_hosts'
    if (-not (Test-Path -LiteralPath $targetPath)) {
        New-Item -ItemType File -Path $targetPath -Force | Out-Null
    }

    $acceptNewArgs = @(
        '-i', $KeyPath,
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', "UserKnownHostsFile=$targetPath",
        '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=5',
        "root@$HostName",
        'exit'
    )

    for ($i = 0; $i -lt 30; $i++) {
        try {
            & ssh @acceptNewArgs 2>$null | Out-Null
            $content = ''
            try {
                $content = Get-Content -LiteralPath $targetPath -Raw
            } catch {
                $content = ''
            }

            if ($content -match '\S') {
                return $targetPath
            }
        } catch {
        }
        Start-Sleep -Seconds 2
    }

    throw "Unable to initialize SSH known_hosts for $HostName"
    return $targetPath
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter()] [string[]]$Arguments = @(),
        [switch]$IgnoreExitCode
    )

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if (-not $IgnoreExitCode -and $exitCode -ne 0) {
        throw ("Command failed with exit code {0}: {1} {2}" -f $exitCode, $FilePath, ($Arguments -join ' '))
    }
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    throw 'VULTR_API_KEY is required.'
}

if (-not (Test-Path -LiteralPath $PrivateKeyPath)) {
    throw "Private key not found: $PrivateKeyPath"
}

$root = Split-Path -Parent $PSCommandPath
$stackSource = Join-Path $root 'stack'
$cloudInitPath = Join-Path $root 'cloud-init.yaml'

$existingEnv = @{}
if (Test-Path -LiteralPath $StatePath) {
    try {
        $previousState = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        $sameTarget = $false

        if ($InstanceId -and $previousState.instance_id -eq $InstanceId) {
            $sameTarget = $true
        } elseif ($TargetIp -and $previousState.ip -eq $TargetIp) {
            $sameTarget = $true
        }

        if ($sameTarget) {
            $previousEnvPath = Join-Path $previousState.paths.local_stack '.env.runtime'
            if (Test-Path -LiteralPath $previousEnvPath) {
                $existingEnv = Read-EnvFile -Path $previousEnvPath
            }
        }
    } catch {
        $existingEnv = @{}
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$label = "$LabelPrefix-$timestamp"
$generatedRoot = Join-Path (Split-Path -Parent $StatePath) 'generated'
$generatedDir = Join-Path $generatedRoot $label
$localStackDir = Join-Path $generatedDir 'stack'
New-Item -ItemType Directory -Path $generatedDir -Force | Out-Null
Copy-Item -Path $stackSource -Destination $localStackDir -Recurse -Force
$scopedKeyPath = New-ScopedKeyCopy -SourcePath $PrivateKeyPath -DestinationDirectory $generatedDir
$knownHostsPath = ''

$realityPrivateKey = $existingEnv['REALITY_PRIVATE_KEY']
$realityPublicKey = $existingEnv['REALITY_PUBLIC_KEY']
if ([string]::IsNullOrWhiteSpace($realityPrivateKey) -or [string]::IsNullOrWhiteSpace($realityPublicKey)) {
    $realityOutput = & 'V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe' generate reality-keypair
    $realityPrivateKey = ($realityOutput | Select-String '^PrivateKey:\s+(.+)$').Matches[0].Groups[1].Value
    $realityPublicKey = ($realityOutput | Select-String '^PublicKey:\s+(.+)$').Matches[0].Groups[1].Value
}

$realityWarpPrivateKey = $existingEnv['REALITY_WARP_PRIVATE_KEY']
$realityWarpPublicKey = $existingEnv['REALITY_WARP_PUBLIC_KEY']
if ([string]::IsNullOrWhiteSpace($realityWarpPrivateKey) -or [string]::IsNullOrWhiteSpace($realityWarpPublicKey)) {
    $realityWarpOutput = & 'V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe' generate reality-keypair
    $realityWarpPrivateKey = ($realityWarpOutput | Select-String '^PrivateKey:\s+(.+)$').Matches[0].Groups[1].Value
    $realityWarpPublicKey = ($realityWarpOutput | Select-String '^PublicKey:\s+(.+)$').Matches[0].Groups[1].Value
}

$proxyUser = 'v_user'
$proxyPassword = if ($existingEnv['PROXY_PASSWORD']) { $existingEnv['PROXY_PASSWORD'] } else { New-RandomSecret }
$vlessUuid = if ($existingEnv['VLESS_UUID']) { $existingEnv['VLESS_UUID'] } else { [guid]::NewGuid().Guid }
$hy2Password = if ($existingEnv['HY2_PASSWORD']) { $existingEnv['HY2_PASSWORD'] } else { New-RandomSecret }
$realityShortId = if ($existingEnv['REALITY_SHORT_ID']) { $existingEnv['REALITY_SHORT_ID'] } else { New-HexSecret }
$vlessWarpUuid = if ($existingEnv['VLESS_WARP_UUID']) { $existingEnv['VLESS_WARP_UUID'] } else { [guid]::NewGuid().Guid }
$hy2WarpPassword = if ($existingEnv['HY2_WARP_PASSWORD']) { $existingEnv['HY2_WARP_PASSWORD'] } else { New-RandomSecret }
$realityWarpShortId = if ($existingEnv['REALITY_WARP_SHORT_ID']) { $existingEnv['REALITY_WARP_SHORT_ID'] } else { New-HexSecret }
$proxyCertCn = if ([string]::IsNullOrWhiteSpace($TunnelDomain)) { 'proxy.local' } else { $TunnelDomain }
$usePrebuiltImageValue = if ($UsePrebuiltImages -or $env:EDGE_USE_PREBUILT_IMAGES -eq '1') { '1' } else { '0' }
if ([string]::IsNullOrWhiteSpace($WarpEgressImage)) {
    $WarpEgressImage = 'ghcr.io/iamaman11/vultr-warp-egress:latest'
}
if ([string]::IsNullOrWhiteSpace($GatewayImage)) {
    $GatewayImage = 'ghcr.io/iamaman11/vultr-edge-gateway:latest'
}

$envRuntime = @"
PROXY_USERNAME=$proxyUser
PROXY_PASSWORD=$proxyPassword
PROXY_CERT_CN=$proxyCertCn
VLESS_UUID=$vlessUuid
HY2_PASSWORD=$hy2Password
REALITY_PRIVATE_KEY=$realityPrivateKey
REALITY_PUBLIC_KEY=$realityPublicKey
REALITY_SHORT_ID=$realityShortId
VLESS_WARP_UUID=$vlessWarpUuid
HY2_WARP_PASSWORD=$hy2WarpPassword
REALITY_WARP_PRIVATE_KEY=$realityWarpPrivateKey
REALITY_WARP_PUBLIC_KEY=$realityWarpPublicKey
REALITY_WARP_SHORT_ID=$realityWarpShortId
REALITY_SERVER_NAME=www.microsoft.com
TUNNEL_DOMAIN=$TunnelDomain
ACME_EMAIL=$AcmeEmail
EDGE_USE_PREBUILT_IMAGES=$usePrebuiltImageValue
EDGE_WARP_EGRESS_IMAGE=$WarpEgressImage
EDGE_GATEWAY_IMAGE=$GatewayImage
"@

$envRuntimePath = Join-Path $localStackDir '.env.runtime'
[System.IO.File]::WriteAllText($envRuntimePath, $envRuntime, [System.Text.UTF8Encoding]::new($false))

$instance = $null
if ($InstanceId) {
    Write-Host "Using existing instance: $InstanceId"
    $instance = (Invoke-VultrApi -Method GET -Uri "https://api.vultr.com/v2/instances/$InstanceId").instance
}

if (-not $SkipCreate -and -not $InstanceId -and -not $TargetIp) {
    Write-Host "Creating new Vultr instance in region '$Region' with plan '$Plan'..."
    $cloudInitBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $cloudInitPath -Raw)))
    $body = @{
        region = $Region
        plan = $Plan
        os_id = $OsId
        label = $label
        hostname = $label
        enable_ipv6 = $true
        sshkey_id = @($SshKeyId)
        user_data = $cloudInitBase64
    }

    $instance = (Invoke-VultrApi -Method POST -Uri 'https://api.vultr.com/v2/instances' -Body $body).instance
    Write-Host "Create request accepted. Instance id: $($instance.id)"

    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 5
        $current = (Invoke-VultrApi -Method GET -Uri "https://api.vultr.com/v2/instances/$($instance.id)").instance
        Write-Host ("Waiting for instance readiness ({0}/60): status={1}, server_status={2}, main_ip={3}" -f ($i + 1), $current.status, $current.server_status, $current.main_ip)
        if ($current.status -eq 'active' -and $current.main_ip -and $current.server_status -eq 'ok') {
            $instance = $current
            break
        }
        $instance = $current
    }

    if (-not $instance.main_ip) {
        throw ("Instance did not become ready in time. Last state: status={0}, server_status={1}, main_ip={2}" -f $instance.status, $instance.server_status, $instance.main_ip)
    }
}

$targetIp = if ($TargetIp) { $TargetIp } elseif ($instance) { $instance.main_ip } else { '' }
if ([string]::IsNullOrWhiteSpace($targetIp)) {
    throw 'No target IP available.'
}

Write-Host "Target IP: $targetIp"

$knownHostsPath = Initialize-KnownHostsFile -HostName $targetIp -KeyPath $scopedKeyPath -DestinationDirectory $generatedDir
Write-Host 'SSH host key pinned'

$sshBase = @(
    '-i', $scopedKeyPath,
    '-o', 'StrictHostKeyChecking=yes',
    '-o', "UserKnownHostsFile=$knownHostsPath",
    '-o', 'IdentitiesOnly=yes'
)

for ($i = 0; $i -lt 60; $i++) {
    try {
        Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'echo ready'))
        Write-Host 'SSH is reachable'
        break
    } catch {
        if ($i -eq 59) { throw }
        Write-Host ("Waiting for SSH ({0}/60)..." -f ($i + 1))
        Start-Sleep -Seconds 5
    }
}

for ($i = 0; $i -lt 90; $i++) {
    try {
        Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait >/dev/null 2>&1; fi; command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1'))
        Write-Host 'Docker is ready on the server'
        break
    } catch {
        if ($i -eq 89) { throw 'Docker was not ready after waiting for cloud-init.' }
        Write-Host ("Waiting for Docker/cloud-init ({0}/90)..." -f ($i + 1))
        Start-Sleep -Seconds 5
    }
}

Write-Host 'Uploading stack to the server...'
Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'mkdir -p /opt/vultr-edge-stack'))
Invoke-NativeChecked -FilePath 'scp' -Arguments ($sshBase + @('-r', $localStackDir, "root@${targetIp}:/opt/vultr-edge-stack/"))

if (-not [string]::IsNullOrWhiteSpace($EdgeAgentBinaryPath)) {
    if (-not (Test-Path -LiteralPath $EdgeAgentBinaryPath)) {
        throw "edge-agent binary not found: $EdgeAgentBinaryPath"
    }

    Write-Host 'Uploading edge-agent host binary...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'mkdir -p /opt/vultr-edge-stack/bin'))
    Invoke-NativeChecked -FilePath 'scp' -Arguments ($sshBase + @($EdgeAgentBinaryPath, "root@${targetIp}:/opt/vultr-edge-stack/bin/edge-agent.tmp"))
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'install -m 0755 /opt/vultr-edge-stack/bin/edge-agent.tmp /opt/vultr-edge-stack/bin/edge-agent && rm -f /opt/vultr-edge-stack/bin/edge-agent.tmp && systemctl daemon-reload && systemctl enable edge-agent.service && systemctl restart edge-agent.service'))
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'systemctl is-active --quiet edge-agent.service'))
    Write-Host 'edge-agent host service is active'
}

$baseVerifyCommand = "docker ps --format '{{.Names}}' | grep -x 'vultr-warp-egress' >/dev/null && docker ps --format '{{.Names}}' | grep -x 'vultr-edge-gateway' >/dev/null && docker ps --format '{{.Names}}' | grep -x 'vultr-edge-gateway-direct' >/dev/null"
$fullVerifyCommand = "$baseVerifyCommand && docker ps --format '{{.Names}}' | grep -x 'vultr-tunnel-edge' >/dev/null && docker ps --format '{{.Names}}' | grep -x 'vultr-tunnel-edge-warp' >/dev/null"
$cloudflareZoneId = ''

if (-not [string]::IsNullOrWhiteSpace($TunnelDomain) -and -not [string]::IsNullOrWhiteSpace($AcmeEmail)) {
    Write-Host 'Bootstrapping base stack...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'cd /opt/vultr-edge-stack/stack && chmod +x bootstrap.sh && ./bootstrap.sh base'))
    Write-Host 'Verifying base containers...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", $baseVerifyCommand))

    if (-not [string]::IsNullOrWhiteSpace($DnsRecordName)) {
        Write-Host "Updating DNS: $DnsRecordName -> $targetIp"
        $cloudflareZoneId = Update-CloudflareARecord -ZoneName $CloudflareZoneName -RecordName $DnsRecordName -IpAddress $targetIp
        Start-Sleep -Seconds 10
    }

    Write-Host 'Bootstrapping tunnel stack...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'cd /opt/vultr-edge-stack/stack && ./bootstrap.sh tunnel'))
    Write-Host 'Verifying tunnel containers...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", $fullVerifyCommand))
} else {
    Write-Host 'Bootstrapping base stack...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", 'cd /opt/vultr-edge-stack/stack && chmod +x bootstrap.sh && ./bootstrap.sh base'))
    Write-Host 'Verifying base containers...'
    Invoke-NativeChecked -FilePath 'ssh' -Arguments ($sshBase + @("root@$targetIp", $baseVerifyCommand))

    if (-not [string]::IsNullOrWhiteSpace($DnsRecordName)) {
        Write-Host "Updating DNS: $DnsRecordName -> $targetIp"
        $cloudflareZoneId = Update-CloudflareARecord -ZoneName $CloudflareZoneName -RecordName $DnsRecordName -IpAddress $targetIp
    }
}

$summary = [ordered]@{
    label = $label
    instance_id = if ($instance) { $instance.id } else { '' }
    ip = $targetIp
    plan = $Plan
    region = $Region
    proxy = [ordered]@{
        host = $targetIp
        http_port = 3128
        socks5_port = 1080
        https_port = 9443
        username = $proxyUser
        password = $proxyPassword
    }
    warp_proxy = [ordered]@{
        host = $targetIp
        http_port = 3128
        socks5_port = 1080
        https_port = 9443
        username = $proxyUser
        password = $proxyPassword
    }
    direct_proxy = [ordered]@{
        host = $targetIp
        http_port = 4128
        socks5_port = 4080
        https_port = 4443
        username = $proxyUser
        password = $proxyPassword
    }
    tunnel = [ordered]@{
        enabled = (-not [string]::IsNullOrWhiteSpace($TunnelDomain))
        domain = $TunnelDomain
        vless_port = 443
        hy2_port = 8443
        vless_uuid = $vlessUuid
        reality_public_key = $realityPublicKey
        reality_short_id = $realityShortId
        hy2_password = $hy2Password
    }
    tunnel_warp = [ordered]@{
        enabled = (-not [string]::IsNullOrWhiteSpace($TunnelDomain))
        domain = $TunnelDomain
        vless_port = 5443
        hy2_port = 9444
        vless_uuid = $vlessWarpUuid
        reality_public_key = $realityWarpPublicKey
        reality_short_id = $realityWarpShortId
        hy2_password = $hy2WarpPassword
    }
    dns = [ordered]@{
        zone = $CloudflareZoneName
        zone_id = $cloudflareZoneId
        record = $DnsRecordName
        ip = $targetIp
    }
    paths = [ordered]@{
        local_stack = $localStackDir
        private_key = $PrivateKeyPath
        scoped_private_key = $scopedKeyPath
        known_hosts = $knownHostsPath
    }
}

$summaryPath = Join-Path $generatedDir 'deployment-summary.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $StatePath -Encoding UTF8
Write-Host 'Deployment completed successfully'
$summary | ConvertTo-Json -Depth 10
