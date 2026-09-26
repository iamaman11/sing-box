param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform")
)

$ErrorActionPreference = "Stop"
$console = Join-Path $InstallRoot "bin\edge-console.exe"
if (-not (Test-Path -LiteralPath $console)) {
    throw "Installed edge-console is missing: $console"
}

& $console ensure-controller
if ($LASTEXITCODE -ne 0) {
    throw "Installed edge-console failed to ensure the exact current.pb controller"
}
