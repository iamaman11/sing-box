param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ControllerExe = "",
    [string]$BindAddress = "127.0.0.1:50051",
    [int]$WaitSeconds = 30
)

$ErrorActionPreference = "Stop"

function Test-ControllerPort {
    param([int]$Port)
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Resolve-ControllerExe {
    param([string]$ExplicitPath)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) { throw "Controller binary not found: $ExplicitPath" }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $currentPath = Join-Path $env:LOCALAPPDATA "edge-platform\current.json"
    if (-not (Test-Path -LiteralPath $currentPath)) {
        throw "Accepted Windows control release is not installed. Run edge-platform\scripts\install-windows-release.ps1."
    }

    $current = Get-Content -Raw $currentPath | ConvertFrom-Json
    if ($current.schema -ne 1 -or [string]$current.source_revision -notmatch '^[0-9a-f]{40}$') {
        throw "Installed Windows control pointer has invalid schema"
    }

    $path = [string]$current.controller_path
    $expectedSha = ([string]$current.controller_sha256).ToLowerInvariant()
    if (-not (Test-Path -LiteralPath $path)) { throw "Installed controller binary not found: $path" }
    if ($expectedSha -notmatch '^[0-9a-f]{64}$') { throw "Installed controller digest is invalid" }

    $actualSha = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
    if ($actualSha -ne $expectedSha) { throw "Installed controller binary failed SHA-256 verification" }
    return (Resolve-Path -LiteralPath $path).Path
}

function Get-ExistingController {
    param([string]$ExecutablePath, [string]$RepoRoot, [string]$BindAddress)

    Get-CimInstance Win32_Process -Filter "name='edge-controller.exe'" | Where-Object {
        $_.ExecutablePath -eq $ExecutablePath -and
        $_.CommandLine -like "*serve $RepoRoot $BindAddress*"
    } | Select-Object -First 1
}

function Get-RuntimeProxyCredentials {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "Proxy credential mirror is absent: $Path. Run sync-proxy-credentials.ps1." }
    Add-Type -AssemblyName System.Security
    $cipher = [IO.File]::ReadAllBytes($Path)
    $plain = $null
    try {
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $document = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json -ErrorAction Stop
        if ($document.schema_version -ne 1 -or [string]::IsNullOrWhiteSpace([string]$document.username) -or [string]::IsNullOrWhiteSpace([string]$document.password)) {
            throw "Proxy credential mirror has invalid schema"
        }
        return $document
    } finally {
        if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
    }
}

if (-not (Test-Path $RepoRoot)) {
    throw "Repo root not found: $RepoRoot"
}
$ControllerExe = Resolve-ControllerExe -ExplicitPath $ControllerExe

$port = [int]($BindAddress.Split(":")[-1])
$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
$pidFile = Join-Path $runtimeDir "controller.pid"
$existing = Get-ExistingController -ExecutablePath $ControllerExe -RepoRoot $RepoRoot -BindAddress $BindAddress

if ($existing -and (Test-ControllerPort -Port $port)) {
    $managedPid = if (Test-Path $pidFile) { (Get-Content -Raw $pidFile).Trim() } else { "" }
    if ($managedPid -ne [string]$existing.ProcessId) {
        Set-Content -NoNewline -Path $pidFile -Value $existing.ProcessId
    }
    Write-Output "edge-controller already running accepted release (pid $($existing.ProcessId))"
    exit 0
}

if (Test-ControllerPort -Port $port) {
    $managedPid = if (Test-Path $pidFile) { (Get-Content -Raw $pidFile).Trim() } else { "" }
    $managed = $null
    if ($managedPid -match '^\d+$') {
        $managed = Get-CimInstance Win32_Process -Filter "ProcessId=$managedPid" -ErrorAction SilentlyContinue
    }
    $managedIsOurs = $managed -and
        $managed.Name -ieq "edge-controller.exe" -and
        $managed.CommandLine -like "*serve $RepoRoot $BindAddress*"

    if (-not $managedIsOurs) {
        throw "Port $port is occupied by an unmanaged process; refusing to terminate it"
    }

    Stop-Process -Id ([int]$managedPid) -Force
    $stopDeadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $stopDeadline -and (Test-ControllerPort -Port $port)) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-ControllerPort -Port $port) {
        throw "Previous managed edge-controller did not release port $port"
    }
}

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$stdout = Join-Path $runtimeDir "controller-service-stdout.log"
$stderr = Join-Path $runtimeDir "controller-service-stderr.log"

$proxyCredentials = Get-RuntimeProxyCredentials (Join-Path $runtimeDir "proxy-credentials-v1.dpapi")
$env:EDGE_PROXY_USERNAME = [string]$proxyCredentials.username
$env:EDGE_PROXY_PASSWORD = [string]$proxyCredentials.password
$startArgs = @{
    FilePath = $ControllerExe
    ArgumentList = @("serve", $RepoRoot, $BindAddress)
    WorkingDirectory = $RepoRoot
    WindowStyle = "Hidden"
    RedirectStandardOutput = $stdout
    RedirectStandardError = $stderr
}
Start-Process @startArgs | Out-Null

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-ControllerPort -Port $port) {
        $started = Get-ExistingController -ExecutablePath $ControllerExe -RepoRoot $RepoRoot -BindAddress $BindAddress
        if ($started) {
            Set-Content -NoNewline -Path $pidFile -Value $started.ProcessId
            Write-Output "edge-controller started from accepted Windows release on $BindAddress (pid $($started.ProcessId))"
            exit 0
        }
    }
    Start-Sleep -Milliseconds 500
}

throw "edge-controller did not start listening on $BindAddress within $WaitSeconds seconds"
