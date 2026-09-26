param(
    [string]$InstallRoot = "C:\sing-box",
    [string]$TaskName = "EdgePlatformController"
)

$ErrorActionPreference = "Stop"
$automation = Join-Path $PSScriptRoot "register-edge-platform-automation.ps1"
& $automation -InstallRoot $InstallRoot -ControllerTaskName $TaskName
