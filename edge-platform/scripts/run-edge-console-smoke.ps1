param(
    [string]$ConsolePath = (Join-Path $env:LOCALAPPDATA "edge-platform\bin\edge-console.exe"),
    [string]$Endpoint = "http://127.0.0.1:50051"
)

$ErrorActionPreference = "Stop"

function Invoke-ConsoleStep {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    Write-Host ""
    Write-Host "=== $Name ==="
    Write-Host "$ConsolePath $($Arguments -join ' ')"

    & $ConsolePath @Arguments
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "Step failed: $Name (exit $exitCode)"
    }

    [pscustomobject]@{
        Name = $Name
        ExitCode = $exitCode
        AllowedFailure = [bool]$AllowFailure
    }
}

if (-not (Test-Path $ConsolePath)) {
    throw "Console binary not found: $ConsolePath"
}

$results = @()

$results += Invoke-ConsoleStep -Name "Status" -Arguments @("status", $Endpoint)
$results += Invoke-ConsoleStep -Name "Desktop auto" -Arguments @("set-selector", "auto-direct-tunnel", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Desktop hysteria2" -Arguments @("set-selector", "hysteria2-direct", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Desktop vless" -Arguments @("set-selector", "vless-reality-direct", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Desktop warp auto" -Arguments @("set-selector", "auto-warp-tunnel", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Desktop warp hysteria2" -Arguments @("set-selector", "hysteria2-warp", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Desktop warp vless" -Arguments @("set-selector", "vless-reality-warp", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Ubuntu auto direct" -Arguments @("set-ubuntu-selector", "auto-direct-tunnel", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Ubuntu hysteria2 direct" -Arguments @("set-ubuntu-selector", "hysteria2-direct", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Ubuntu vless direct" -Arguments @("set-ubuntu-selector", "vless-reality-direct", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Ubuntu auto warp" -Arguments @("set-ubuntu-selector", "auto-warp-tunnel", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Ubuntu hysteria2 warp" -Arguments @("set-ubuntu-selector", "hysteria2-warp", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Ubuntu vless warp" -Arguments @("set-ubuntu-selector", "vless-reality-warp", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Show Ubuntu selector" -Arguments @("get-ubuntu-selector", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Trace Ubuntu" -Arguments @("trace-ubuntu", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Trace desktop" -Arguments @("trace", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Start local visible" -Arguments @("start-local-visible", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Stop local" -Arguments @("stop-local", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Restart local visible" -Arguments @("restart-local-visible", $Endpoint) -AllowFailure
$results += Invoke-ConsoleStep -Name "Doctor" -Arguments @("doctor", $Endpoint) -AllowFailure


Write-Host ""
Write-Host "=== Smoke Summary ==="
$results | Format-Table -AutoSize
