param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ControllerExe = "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-controller.exe",
    [string]$BindAddress = "127.0.0.1:50051",
    [int]$WaitSeconds = 30
)

$ErrorActionPreference = "Stop"

function Test-ControllerPort {
    param([int]$Port)
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Get-ExistingController {
    param([string]$ExecutablePath, [string]$RepoRoot, [string]$BindAddress)

    Get-CimInstance Win32_Process -Filter "name='edge-controller.exe'" | Where-Object {
        $_.ExecutablePath -eq $ExecutablePath -and
        $_.CommandLine -like "*serve $RepoRoot $BindAddress*"
    } | Select-Object -First 1
}

function Get-RuntimeSecret {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "Runtime credential is absent: $Path" }
    Add-Type -AssemblyName System.Security
    $cipher = [IO.File]::ReadAllBytes($Path)
    $plain = $null
    try {
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plain)
    } finally {
        if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    }
}

if (-not (Test-Path $RepoRoot)) {
    throw "Repo root not found: $RepoRoot"
}
if (-not (Test-Path $ControllerExe)) {
    throw "Controller binary not found: $ControllerExe"
}

$port = [int]($BindAddress.Split(":")[-1])
$existing = Get-ExistingController -ExecutablePath $ControllerExe -RepoRoot $RepoRoot -BindAddress $BindAddress
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
$pidFile = Join-Path $runtimeDir "controller.pid"
if ($existing -and (Test-ControllerPort -Port $port)) {
    $managedPid = if (Test-Path $pidFile) { (Get-Content -Raw $pidFile).Trim() } else { "" }
    if ($managedPid -eq [string]$existing.ProcessId) {
        Write-Output "edge-controller already running (pid $($existing.ProcessId))"
        exit 0
    }
    # A listening controller may be serving a long-running deploy or destroy.
    # A stale/missing PID file is not evidence that the process is unsafe; adopt
    # the verified process instead of interrupting the operation in progress.
    Set-Content -NoNewline -Path $pidFile -Value $existing.ProcessId
    Write-Output "Adopted existing edge-controller process (pid $($existing.ProcessId))"
    exit 0
}

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$stdout = Join-Path $runtimeDir "controller-service-stdout.log"
$stderr = Join-Path $runtimeDir "controller-service-stderr.log"

$env:CLOUDFLARE_API_TOKEN = Get-RuntimeSecret (Join-Path $runtimeDir "cloudflare-dns-token.dpapi")
$env:CF_API_TOKEN = $env:CLOUDFLARE_API_TOKEN
$env:VULTR_API_KEY = Get-RuntimeSecret (Join-Path $runtimeDir "vultr-lifecycle-token.dpapi")
$env:EDGE_VULTR_SSH_KEY_ID = "b379cde0-6ef3-46a0-8cf9-c4faa7cb6dd4"
Start-Process -FilePath $ControllerExe `
    -ArgumentList @("serve", $RepoRoot, $BindAddress) `
    -WorkingDirectory $RepoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr | Out-Null

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-ControllerPort -Port $port) {
        $started = Get-ExistingController -ExecutablePath $ControllerExe -RepoRoot $RepoRoot -BindAddress $BindAddress
        if ($started) {
            Set-Content -NoNewline -Path $pidFile -Value $started.ProcessId
            Write-Output "edge-controller started with DPAPI credentials on $BindAddress (pid $($started.ProcessId))"
            exit 0
        }
    }
    Start-Sleep -Milliseconds 500
}

throw "edge-controller did not start listening on $BindAddress within $WaitSeconds seconds"
