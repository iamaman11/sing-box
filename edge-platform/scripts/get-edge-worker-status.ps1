param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
$credentialPath = Join-Path $runtimeDir "shutdown-worker-auth.dpapi"
$configPath = Join-Path $runtimeDir "lease-reaper.json"
if (-not (Test-Path $credentialPath)) { throw "DPAPI shutdown authorization is absent" }
if (-not (Test-Path $configPath)) { throw "Lease-reaper configuration is absent" }

$cipher = [IO.File]::ReadAllBytes($credentialPath)
$plain = $null
try {
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $cipher,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $token = [Text.Encoding]::UTF8.GetString($plain)
    $workerUrl = (Get-Content -Raw $configPath | ConvertFrom-Json).worker_url
    Invoke-RestMethod -Method Get -Uri ($workerUrl.TrimEnd('/') + '/status') `
        -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 10
} finally {
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    $token = ""
}
