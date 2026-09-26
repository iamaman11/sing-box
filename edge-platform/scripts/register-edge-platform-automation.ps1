param(
    [string]$InstallRoot = "C:\sing-box",
    [string]$ControllerTaskName = "EdgePlatformController",
    [string]$ReconcileTaskName = "EdgePlatformReconcile",
    [string]$ShutdownTaskName = "EdgePlatformShutdown"
)

$ErrorActionPreference = "Stop"
$console = Join-Path $InstallRoot "bin\edge-console.exe"
if (-not (Test-Path -LiteralPath $console)) {
    throw "Installed edge-console is missing: $console"
}

$quotedConsole = '"' + $console + '"'
schtasks /Create /F /SC ONLOGON /DELAY 0001:30 /RL HIGHEST /IT /TN $ControllerTaskName /TR "$quotedConsole ensure-controller" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to register $ControllerTaskName" }

schtasks /Create /F /SC MINUTE /MO 15 /RL HIGHEST /IT /TN $ReconcileTaskName /TR "$quotedConsole reconcile" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to register $ReconcileTaskName" }

$shutdownSubscription = "*[System[Provider[@Name='USER32'] and (EventID=1074)]]"
schtasks /Create /F /SC ONEVENT /EC System /MO $shutdownSubscription /RL HIGHEST /IT /TN $ShutdownTaskName /TR "$quotedConsole stop-local" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to register $ShutdownTaskName" }

Unregister-ScheduledTask -TaskName "EdgePlatformSingboxLogCleanup" -Confirm:$false -ErrorAction SilentlyContinue
Write-Output "Registered installed console automation: $ControllerTaskName, $ReconcileTaskName, $ShutdownTaskName"
