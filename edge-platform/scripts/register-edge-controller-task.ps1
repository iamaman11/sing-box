param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform"),
    [string]$TaskName = "EdgePlatformController"
)

$ErrorActionPreference = "Stop"
$automation = Join-Path $PSScriptRoot "register-edge-platform-automation.ps1"
& $automation -InstallRoot $InstallRoot -ControllerTaskName $TaskName
