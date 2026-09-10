param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$HostName = "edge.alegria.by",
    [int]$TimeoutSeconds = 30,
    [switch]$AllowInsecureHttpsProxy,
    [string]$TargetUrl = "https://api.ipify.org"
)

$ErrorActionPreference = "Stop"
$mirror = Join-Path $RepoRoot "edge-platform\.runtime\proxy-credentials-v1.dpapi"
if (-not (Test-Path -LiteralPath $mirror)) { throw "Proxy credential DPAPI mirror is absent" }

function Protect-TempFile([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, "FullControl", "Allow")))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Clear-RemoveFile([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($length -gt 0) { [IO.File]::WriteAllBytes($Path, (New-Object byte[] $length)) }
        Remove-Item -Force -LiteralPath $Path -ErrorAction SilentlyContinue
    }
}

Add-Type -AssemblyName System.Security
$cipher = [IO.File]::ReadAllBytes($mirror)
$plain = $null
try {
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $credentials = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json -ErrorAction Stop
    if ($credentials.schema_version -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$credentials.username) -or
        [string]::IsNullOrWhiteSpace([string]$credentials.password)) {
        throw "Proxy credential mirror has invalid schema"
    }

    $profiles = @(
        @{ name = "VM HTTP"; scheme = "http"; port = 4128 },
        @{ name = "VM SOCKS5"; scheme = "socks5h"; port = 4080 },
        @{ name = "VM HTTPS"; scheme = "https"; port = 4443 },
        @{ name = "WARP HTTP"; scheme = "http"; port = 3128 },
        @{ name = "WARP SOCKS5"; scheme = "socks5h"; port = 1080 },
        @{ name = "WARP HTTPS"; scheme = "https"; port = 9443 }
    )

    $results = foreach ($profile in $profiles) {
        $config = [IO.Path]::GetTempFileName()
        Protect-TempFile $config
        try {
            $proxy = "$($profile.scheme)://$HostName`:$($profile.port)"
            $curlEscape = {
                param([string]$value)
                $value.Replace('\\', '\\\\').Replace('"', '\"').Replace("`r", '').Replace("`n", '')
            }
            $body = @(
                "proxy = `"$proxy`"",
                "proxy-user = `"$(& $curlEscape ([string]$credentials.username))`:$(& $curlEscape ([string]$credentials.password))`"",
                "url = `"$TargetUrl`""
            ) -join "`n"
            [IO.File]::WriteAllText($config, $body, [Text.UTF8Encoding]::new($false))
            $curlArgs = @("--config", $config, "--silent", "--show-error", "--fail", "--connect-timeout", "15", "--max-time", $TimeoutSeconds)
            if ($AllowInsecureHttpsProxy -and $profile.scheme -eq "https") { $curlArgs += "--proxy-insecure" }
            $output = & curl.exe @curlArgs 2>&1
            $exit = $LASTEXITCODE
            $ip = ([string]$output).Trim()
            [pscustomobject]@{
                profile = $profile.name
                endpoint = "$HostName`:$($profile.port)"
                ok = ($exit -eq 0 -and $ip -match '^(?:\d{1,3}\.){3}\d{1,3}$')
                egress_ip = if ($exit -eq 0 -and $ip -match '^(?:\d{1,3}\.){3}\d{1,3}$') { $ip } else { $null }
                error = if ($exit -eq 0) { $null } else { ([string]$output).Trim() }
            }
        } finally {
            Clear-RemoveFile $config
        }
    }
    $results | ConvertTo-Json -Compress
    if (($results | Where-Object { -not $_.ok }).Count -gt 0) { exit 1 }
} finally {
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
}
