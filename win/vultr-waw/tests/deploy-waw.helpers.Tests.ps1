Set-StrictMode -Version Latest

Describe 'deploy-waw helpers' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'deploy-waw.helpers.ps1')
    }

    It 'returns prebuilt mode when switch is enabled' {
        Get-EdgePrebuiltModeValue -UsePrebuiltImages $true -EnvironmentValue '' | Should -Be '1'
    }

    It 'returns prebuilt mode when environment value is enabled' {
        Get-EdgePrebuiltModeValue -UsePrebuiltImages $false -EnvironmentValue '1' | Should -Be '1'
    }

    It 'returns build mode by default' {
        Get-EdgePrebuiltModeValue -UsePrebuiltImages $false -EnvironmentValue '' | Should -Be '0'
    }

    It 'fills default image references' {
        $resolved = Get-EdgeImageConfig -WarpEgressImage '' -GatewayImage ''
        $resolved.WarpEgressImage | Should -Be 'ghcr.io/iamaman11/vultr-warp-egress:latest'
        $resolved.GatewayImage | Should -Be 'ghcr.io/iamaman11/vultr-edge-gateway:latest'
    }

    It 'resolves default controller binary from repository root' {
        $repoRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        $binaryPath = Join-Path $repoRoot 'edge-platform/target/release/edge-controller.exe'
        try {
            New-Item -ItemType Directory -Path (Split-Path -Parent $binaryPath) -Force | Out-Null
            Set-Content -LiteralPath $binaryPath -Value 'stub' -Encoding utf8

            $resolved = Resolve-EdgeControllerBinaryPath -ExplicitPath '' -RepositoryRoot $repoRoot
            $resolved | Should -Be $binaryPath
        } finally {
            Remove-Item -LiteralPath $repoRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'builds local edge-agent endpoint from forwarded port' {
        $endpoint = Get-EdgeAgentEndpoint -ExplicitEndpoint '' -LocalPort 51061
        $endpoint | Should -Be 'http://127.0.0.1:51061'
    }

    It 'builds runtime env content with prebuilt image keys' {
        $content = Get-EdgeRuntimeEnvContent -Values @{
            PROXY_USERNAME = 'v_user'
            PROXY_PASSWORD = 'secret'
            PROXY_CERT_CN = 'edge.example.com'
            VLESS_UUID = 'uuid-a'
            HY2_PASSWORD = 'hy2-a'
            REALITY_PRIVATE_KEY = 'rpv'
            REALITY_PUBLIC_KEY = 'rpb'
            REALITY_SHORT_ID = 'sid'
            VLESS_WARP_UUID = 'uuid-b'
            HY2_WARP_PASSWORD = 'hy2-b'
            REALITY_WARP_PRIVATE_KEY = 'wrpv'
            REALITY_WARP_PUBLIC_KEY = 'wrpb'
            REALITY_WARP_SHORT_ID = 'wsid'
            REALITY_SERVER_NAME = 'www.microsoft.com'
            TUNNEL_DOMAIN = 'edge.example.com'
            ACME_EMAIL = 'admin@example.com'
            EDGE_USE_PREBUILT_IMAGES = '1'
            EDGE_WARP_EGRESS_IMAGE = 'ghcr.io/example/warp:1'
            EDGE_GATEWAY_IMAGE = 'ghcr.io/example/gateway:1'
        }

        $content | Should -Match 'EDGE_USE_PREBUILT_IMAGES=1'
        $content | Should -Match 'EDGE_WARP_EGRESS_IMAGE=ghcr.io/example/warp:1'
        $content | Should -Match 'EDGE_GATEWAY_IMAGE=ghcr.io/example/gateway:1'
    }

    It 'parses env files and skips comments' {
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            @(
                '# comment'
                ''
                'A=1'
                'B=two=parts'
            ) | Set-Content -LiteralPath $tempFile -Encoding utf8

            $parsed = Read-EnvFile -Path $tempFile
            $parsed['A'] | Should -Be '1'
            $parsed['B'] | Should -Be 'two=parts'
            $parsed.ContainsKey('# comment') | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
        }
    }
}
