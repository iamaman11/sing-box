[CmdletBinding()]
param(
    [string]$RunnerRoot = "C:\sing-box-runner",
    [string]$ApplicationRoot = "C:\sing-box",
    [string]$RunnerName = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$Repository = "iamaman11/sing-box"
$RunnerVersion = "2.337.0"
$RunnerAsset = "actions-runner-win-x64-$RunnerVersion.zip"
$RunnerSha256 = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc"
$RunnerUrl = "https://github.com/actions/runner/releases/download/v$RunnerVersion/$RunnerAsset"
$RunnerLabel = "sing-box-windows-lab"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this bootstrap once from an elevated PowerShell session"
    }
}

function Assert-IsolatedRoots {
    $runner = [IO.Path]::GetFullPath($RunnerRoot).TrimEnd("\")
    $application = [IO.Path]::GetFullPath($ApplicationRoot).TrimEnd("\")
    if ($runner -ieq $application) { throw "Runner root and application root must be different" }
    if ($runner.StartsWith($application + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Runner transport must not live inside the application root"
    }
    if ($application.StartsWith($runner + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Application root must not live inside the runner root"
    }
    if ($application -ine "C:\sing-box") {
        throw "Application root must be exactly C:\sing-box during Slice 2"
    }
}

function Assert-MainProtected {
    $headers = @{
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent" = "sing-box-windows-runner-bootstrap"
    }
    $branch = Invoke-RestMethod -Method Get -Uri "https://api.github.com/repos/$Repository/branches/main" -Headers $headers
    if (-not [bool]$branch.protected) {
        throw "Refusing physical runner registration: GitHub main is not protected"
    }
}

function Grant-RunnerApplicationAccess {
    New-Item -ItemType Directory -Force -Path $ApplicationRoot | Out-Null
    & icacls.exe $ApplicationRoot /grant "NT AUTHORITY\NETWORK SERVICE:(OI)(CI)M" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to grant NetworkService modify access to C:\sing-box" }
}

function Get-RunnerService {
    $serviceMarker = Join-Path $RunnerRoot ".service"
    $runnerMarker = Join-Path $RunnerRoot ".runner"
    $hasService = Test-Path -LiteralPath $serviceMarker -PathType Leaf
    $hasRunner = Test-Path -LiteralPath $runnerMarker -PathType Leaf
    if ($hasService -ne $hasRunner) {
        throw "Runner configuration markers are inconsistent; refusing implicit repair"
    }
    if (-not $hasService) { return $null }
    $serviceName = (Get-Content -LiteralPath $serviceMarker -Raw).Trim()
    if (-not $serviceName) { throw "Runner service marker is empty" }
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $service) { throw "Configured runner service was not found: $serviceName" }
    if ([string]$service.StartName -ine "NT AUTHORITY\NETWORK SERVICE") {
        throw "Configured runner service must run as NetworkService"
    }
    return $service
}

function Install-RunnerFiles {
    New-Item -ItemType Directory -Force -Path $RunnerRoot | Out-Null
    $config = Join-Path $RunnerRoot "config.cmd"
    if (Test-Path -LiteralPath $config -PathType Leaf) { return }

    $tempRoot = Join-Path $env:TEMP ("sing-box-runner-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    try {
        $archive = Join-Path $tempRoot $RunnerAsset
        Invoke-WebRequest -UseBasicParsing -Uri $RunnerUrl -OutFile $archive
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
        if ($actual -ne $RunnerSha256) { throw "GitHub Actions Runner SHA-256 mismatch" }
        Expand-Archive -LiteralPath $archive -DestinationPath $RunnerRoot -Force
        if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
            throw "Runner archive did not provide config.cmd"
        }
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Register-Runner {
    $config = Join-Path $RunnerRoot "config.cmd"
    if (-not $RunnerName) { $script:RunnerName = "sing-box-" + $env:COMPUTERNAME.ToLowerInvariant() }

    Write-Host "Open GitHub repository Settings > Actions > Runners > New self-hosted runner."
    Write-Host "Paste only the short-lived registration token. It is not stored."
    $secureToken = Read-Host "GitHub runner registration token" -AsSecureString
    if ($secureToken.Length -eq 0) { throw "Runner registration token is required" }

    $bstr = [IntPtr]::Zero
    $plainToken = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        Push-Location $RunnerRoot
        try {
            & $config `
                --unattended `
                --url "https://github.com/$Repository" `
                --token $plainToken `
                --name $RunnerName `
                --labels $RunnerLabel `
                --work "_work" `
                --runasservice `
                --windowslogonaccount "NT AUTHORITY\NETWORK SERVICE" `
                --disableupdate
            if ($LASTEXITCODE -ne 0) { throw "GitHub Actions Runner registration failed" }
        } finally {
            Pop-Location
        }
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainToken = $null
        $secureToken.Dispose()
    }
}

Assert-Administrator
Assert-IsolatedRoots
Assert-MainProtected
Grant-RunnerApplicationAccess

$service = Get-RunnerService
if (-not $service) {
    Install-RunnerFiles
    Register-Runner
    $service = Get-RunnerService
}
if (-not $service) { throw "Runner registration completed without a valid service" }

$serviceName = [string]$service.Name
Set-Service -Name $serviceName -StartupType Automatic
Start-Service -Name $serviceName
$started = Get-Service -Name $serviceName
if ($started.Status -ne "Running") {
    throw "GitHub Actions Runner service did not enter Running state"
}

Write-Output "status=PASS"
Write-Output "runner_root=$RunnerRoot"
Write-Output "application_root=$ApplicationRoot"
Write-Output "runner_label=$RunnerLabel"
Write-Output "runner_service=$serviceName"
Write-Output "runner_identity=NT AUTHORITY\NETWORK SERVICE"
Write-Output "local_build_toolchain_installed=false"
Write-Output "provider_credentials_installed=false"
