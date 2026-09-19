param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ControllerExe = "",
    [string]$BindAddress = "127.0.0.1:50051",
    [string]$TaskName = "EdgePlatformController"
)

$ErrorActionPreference = "Stop"

$automation = Join-Path $RepoRoot "edge-platform\scripts\register-edge-platform-automation.ps1"
if (-not (Test-Path $automation)) { throw "Automation registration script not found: $automation" }
& $automation -RepoRoot $RepoRoot -ControllerTaskName $TaskName
