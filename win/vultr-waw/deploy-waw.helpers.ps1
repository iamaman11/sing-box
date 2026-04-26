Set-StrictMode -Version Latest

function Get-EdgePrebuiltModeValue {
    param(
        [bool]$UsePrebuiltImages,
        [string]$EnvironmentValue
    )

    if ($UsePrebuiltImages -or $EnvironmentValue -eq '1') {
        return '1'
    }

    return '0'
}

function Get-EdgeImageConfig {
    param(
        [string]$WarpEgressImage,
        [string]$GatewayImage
    )

    return @{
        WarpEgressImage = if ([string]::IsNullOrWhiteSpace($WarpEgressImage)) {
            'ghcr.io/iamaman11/vultr-warp-egress:latest'
        } else {
            $WarpEgressImage
        }
        GatewayImage = if ([string]::IsNullOrWhiteSpace($GatewayImage)) {
            'ghcr.io/iamaman11/vultr-edge-gateway:latest'
        } else {
            $GatewayImage
        }
    }
}

function Get-EdgeRuntimeEnvContent {
    param(
        [Parameter(Mandatory)] [hashtable]$Values
    )

    $orderedKeys = @(
        'PROXY_USERNAME',
        'PROXY_PASSWORD',
        'PROXY_CERT_CN',
        'VLESS_UUID',
        'HY2_PASSWORD',
        'REALITY_PRIVATE_KEY',
        'REALITY_PUBLIC_KEY',
        'REALITY_SHORT_ID',
        'VLESS_WARP_UUID',
        'HY2_WARP_PASSWORD',
        'REALITY_WARP_PRIVATE_KEY',
        'REALITY_WARP_PUBLIC_KEY',
        'REALITY_WARP_SHORT_ID',
        'REALITY_SERVER_NAME',
        'TUNNEL_DOMAIN',
        'ACME_EMAIL',
        'EDGE_USE_PREBUILT_IMAGES',
        'EDGE_WARP_EGRESS_IMAGE',
        'EDGE_GATEWAY_IMAGE'
    )

    $lines = foreach ($key in $orderedKeys) {
        $value = ''
        if ($Values.ContainsKey($key) -and $null -ne $Values[$key]) {
            $value = [string]$Values[$key]
        }
        '{0}={1}' -f $key, $value
    }

    return (($lines -join [Environment]::NewLine) + [Environment]::NewLine)
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
