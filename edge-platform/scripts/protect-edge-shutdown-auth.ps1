param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
if ([string]::IsNullOrWhiteSpace($env:LEASE_AUTH_TOKEN)) {
    throw "Lease authentication was not supplied by the vault launcher"
}
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$path = Join-Path $runtimeDir "shutdown-worker-auth.dpapi"
$plain = [Text.Encoding]::UTF8.GetBytes($env:LEASE_AUTH_TOKEN)
try {
    $cipher = [Security.Cryptography.ProtectedData]::Protect(
        $plain,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    [IO.File]::WriteAllBytes($path, $cipher)
    & icacls.exe $path /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to restrict DPAPI credential file permissions" }
    Write-Output "Stored DPAPI-protected shutdown authorization."
} finally {
    [Array]::Clear($plain, 0, $plain.Length)
    if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    $env:LEASE_AUTH_TOKEN = ""
}
