param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$ControllerTaskName = "EdgePlatformController",
    [string]$ReconcileTaskName = "EdgePlatformReconcile",
    [string]$ShutdownTaskName = "EdgePlatformShutdown"
)

$ErrorActionPreference = "Stop"
$startScript = Join-Path $RepoRoot "edge-platform\scripts\start-edge-platform.ps1"
$reconcileScript = Join-Path $RepoRoot "edge-platform\scripts\reconcile-edge-platform.ps1"
$shutdownScript = Join-Path $RepoRoot "edge-platform\scripts\shutdown-edge-platform.ps1"
$hiddenRunner = Join-Path $RepoRoot "edge-platform\scripts\run-hidden-powershell.vbs"
foreach ($path in @($startScript, $reconcileScript, $shutdownScript, $hiddenRunner)) {
    if (-not (Test-Path $path)) { throw "Task wrapper not found: $path" }
}

$wscript = Join-Path $env:SystemRoot "System32\wscript.exe"
$startCommand = '"' + $wscript + '" "' + $hiddenRunner + '" "' + $startScript + '"'
$reconcileCommand = '"' + $wscript + '" "' + $hiddenRunner + '" "' + $reconcileScript + '"'
$shutdownCommand = '"' + $wscript + '" "' + $hiddenRunner + '" "' + $shutdownScript + '"'

# Windows automation is local-only. Server lifecycle credentials and mutations
# belong exclusively to the canonical GitHub lifecycle.
schtasks /Create /F /SC ONLOGON /DELAY 0001:30 /RL HIGHEST /IT /TN $ControllerTaskName /TR $startCommand | Out-Null
# Periodic reconcile may only inspect/restart the Windows-local runtime.
schtasks /Create /F /SC MINUTE /MO 15 /RL HIGHEST /IT /TN $ReconcileTaskName /TR $reconcileCommand | Out-Null

# USER32/1074 stops only the Windows-local runtime; it never changes VM state.
$shutdownSubscription = "*[System[Provider[@Name='USER32'] and (EventID=1074)]]"
schtasks /Create /F /SC ONEVENT /EC System /MO $shutdownSubscription /RL HIGHEST /IT /TN $ShutdownTaskName /TR $shutdownCommand | Out-Null
Unregister-ScheduledTask -TaskName "EdgePlatformSingboxLogCleanup" -Confirm:$false -ErrorAction SilentlyContinue

$startupSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$shutdownSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Set-ScheduledTask -TaskName $ControllerTaskName -Settings $startupSettings | Out-Null
Set-ScheduledTask -TaskName $ReconcileTaskName -Settings $startupSettings | Out-Null
Set-ScheduledTask -TaskName $ShutdownTaskName -Settings $shutdownSettings | Out-Null
Enable-ScheduledTask -TaskName $ControllerTaskName | Out-Null
Enable-ScheduledTask -TaskName $ReconcileTaskName | Out-Null
Enable-ScheduledTask -TaskName $ShutdownTaskName | Out-Null

Write-Output "Registered and enabled: $ControllerTaskName, $ReconcileTaskName, $ShutdownTaskName"
