param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ControllerExe = "C:\Users\Bose\AppData\Local\edge-platform-win-target\x86_64-pc-windows-msvc\debug\edge-controller.exe",
    [string]$BindAddress = "127.0.0.1:50051",
    [string]$TaskName = "EdgePlatformController"
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $RepoRoot "edge-platform\scripts\ensure-edge-controller.ps1"
$wrapperPath = Join-Path $RepoRoot "edge-platform\scripts\start-edge-controller.cmd"
if (-not (Test-Path $scriptPath)) {
    throw "Startup script not found: $scriptPath"
}
if (-not (Test-Path $wrapperPath)) {
    throw "Startup wrapper not found: $wrapperPath"
}

$taskCommand = '"' + $wrapperPath + '"'
schtasks /Create /F /SC ONLOGON /RL HIGHEST /TN $TaskName /TR $taskCommand | Out-Null
Write-Output "Registered scheduled task: $TaskName"
