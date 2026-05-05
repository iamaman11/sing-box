param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ControllerExe = "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-controller.exe",
    [string]$BindAddress = "127.0.0.1:50051",
    [int]$WaitSeconds = 15
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

if (-not (Test-Path $RepoRoot)) {
    throw "Repo root not found: $RepoRoot"
}
if (-not (Test-Path $ControllerExe)) {
    throw "Controller binary not found: $ControllerExe"
}

$port = [int]($BindAddress.Split(":")[-1])
$existing = Get-ExistingController -ExecutablePath $ControllerExe -RepoRoot $RepoRoot -BindAddress $BindAddress
if ($existing -and (Test-ControllerPort -Port $port)) {
    Write-Output "edge-controller already running (pid $($existing.ProcessId))"
    exit 0
}

$runtimeDir = Join-Path $RepoRoot "edge-platform\.runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$stdout = Join-Path $runtimeDir "controller-service-stdout.log"
$stderr = Join-Path $runtimeDir "controller-service-stderr.log"

Start-Process -FilePath $ControllerExe `
    -ArgumentList @("serve", $RepoRoot, $BindAddress) `
    -WorkingDirectory $RepoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr | Out-Null

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-ControllerPort -Port $port) {
        Write-Output "edge-controller started on $BindAddress"
        exit 0
    }
    Start-Sleep -Milliseconds 500
}

throw "edge-controller did not start listening on $BindAddress within $WaitSeconds seconds"
