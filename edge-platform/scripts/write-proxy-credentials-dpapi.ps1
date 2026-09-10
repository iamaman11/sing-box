param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$InputPath
)

$ErrorActionPreference = "Stop"

# This script deliberately accepts the record only through the environment
# provided by `secret-vault run`; it never prints or writes plaintext secrets.
$raw = $env:EDGE_PROXY_CREDENTIALS
if ([string]::IsNullOrWhiteSpace($raw) -and [Console]::IsInputRedirected) {
    $raw = [Console]::In.ReadToEnd()
}
if ([string]::IsNullOrWhiteSpace($raw) -and -not [string]::IsNullOrWhiteSpace($InputPath)) {
    $raw = [IO.File]::ReadAllText($InputPath, [Text.Encoding]::UTF8)
}
if ([string]::IsNullOrWhiteSpace($raw)) {
    throw "EDGE_PROXY_CREDENTIALS was not supplied by Vault"
}

try {
    $document = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($document.schema_version -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$document.username) -or
        [string]::IsNullOrWhiteSpace([string]$document.password)) {
        throw "record must contain schema_version=1, username, and password"
    }

    $runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
    New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
    $target = Join-Path $runtimeDir "proxy-credentials-v1.dpapi"
    $temporary = "$target.new"
    $bytes = [Text.Encoding]::UTF8.GetBytes($raw)
    try {
        Add-Type -AssemblyName System.Security
        $cipher = [Security.Cryptography.ProtectedData]::Protect(
            $bytes,
            $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        [IO.File]::WriteAllBytes($temporary, $cipher)
        Move-Item -Force -LiteralPath $temporary -Destination $target
    } finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
        Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item Env:EDGE_PROXY_CREDENTIALS -ErrorAction SilentlyContinue
}

Write-Output "Proxy credential DPAPI mirror updated"
