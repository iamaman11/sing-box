param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [switch]$VerifyOnly
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
    if ($VerifyOnly) {
        Write-Output "DPAPI shutdown authorization is readable."
        return
    }
    $workerUrl = (Get-Content -Raw $configPath | ConvertFrom-Json).worker_url
    $response = Invoke-RestMethod -Method Post -Uri ($workerUrl.TrimEnd('/') + '/shutdown') `
        -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 7
    if (-not $response.ok) { throw "Lease reaper rejected the shutdown request" }
    Write-Output "External shutdown deletion accepted."
} finally {
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    $token = ""
}
