[CmdletBinding(DefaultParameterSetName = "Activate")]
param(
    [string]$Repository = "iamaman11/sing-box",
    [Parameter(ParameterSetName = "Activate", Mandatory = $true)]
    [string]$ReleaseSetSha256,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform"),
    [string]$GhExe = "gh.exe",
    [Parameter(ParameterSetName = "Rollback", Mandatory = $true)]
    [switch]$Rollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Assert-HexSha256 {
    param([string]$Value, [string]$Name)
    if ($Value -notmatch "^[0-9a-f]{64}$") { throw "$Name must be an exact lowercase SHA-256 digest" }
}

function Get-ExactHash {
    param([Parameter(Mandatory)] [string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-ShaSidecar {
    param(
        [Parameter(Mandatory)] [string]$File,
        [Parameter(Mandatory)] [string]$Sidecar,
        [Parameter(Mandatory)] [string]$ExpectedName,
        [string]$ExpectedDigest = ""
    )
    $line = (Get-Content -LiteralPath $Sidecar -Raw).TrimEnd("`r", "`n")
    if ($line -notmatch "^([0-9a-f]{64})  (.+)$") { throw "Invalid SHA-256 sidecar: $Sidecar" }
    $sidecarDigest = $Matches[1]
    $sidecarName = $Matches[2]
    if ($sidecarName -ne $ExpectedName) { throw "SHA-256 sidecar filename mismatch: expected $ExpectedName, got $sidecarName" }
    if ($ExpectedDigest -and $sidecarDigest -ne $ExpectedDigest) { throw "SHA-256 sidecar digest mismatch for $ExpectedName" }
    $actual = Get-ExactHash -Path $File
    if ($actual -ne $sidecarDigest) { throw "SHA-256 mismatch for $ExpectedName" }
    return $sidecarDigest
}

function Invoke-Diagnostic {
    param(
        [Parameter(Mandatory)] [string]$Diagnostic,
        [Parameter(Mandatory)] [string]$State
    )
    $output = @(& $Diagnostic doctor $State)
    if ($LASTEXITCODE -ne 0) { throw "Windows diagnostic failed for $State" }
    $values = @{}
    foreach ($line in $output) {
        $parts = ([string]$line).Split("=", 2)
        if ($parts.Count -eq 2) { $values[$parts[0]] = $parts[1] }
    }
    if ($values["status"] -ne "PASS" -or $values["exact_release_files"] -ne "PASS") {
        throw "Windows diagnostic did not prove exact release state"
    }
    return $values
}

function Copy-StableBinary {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$Target
    )
    $temp = "$Target.new"
    Copy-Item -LiteralPath $Source -Destination $temp -Force
    if ((Get-ExactHash -Path $temp) -ne (Get-ExactHash -Path $Source)) {
        Remove-Item -Force $temp -ErrorAction SilentlyContinue
        throw "Stable binary copy failed SHA-256 verification: $Target"
    }
    Move-Item -LiteralPath $temp -Destination $Target -Force
}

if (-not (Get-Command $GhExe -ErrorAction SilentlyContinue)) { throw "GitHub CLI not found: $GhExe" }
& $GhExe auth status 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "GitHub CLI is not authenticated" }

$binDir = Join-Path $InstallRoot "bin"
$releasesDir = Join-Path $InstallRoot "releases"
$currentPath = Join-Path $InstallRoot "current.pb"
$previousPath = Join-Path $InstallRoot "previous.pb"
New-Item -ItemType Directory -Force -Path $binDir, $releasesDir | Out-Null

if ($Rollback) {
    if (-not (Test-Path -LiteralPath $currentPath) -or -not (Test-Path -LiteralPath $previousPath)) {
        throw "Rollback requires both current.pb and previous.pb"
    }
    $stableDiagnostic = Join-Path $binDir "edge-diagnostic.exe"
    if (-not (Test-Path -LiteralPath $stableDiagnostic)) { throw "Rollback diagnostic is missing: $stableDiagnostic" }
    $previous = Invoke-Diagnostic -Diagnostic $stableDiagnostic -State $previousPath
    $oldCurrent = "$previousPath.next"
    $newCurrent = "$currentPath.new"
    Copy-Item -LiteralPath $currentPath -Destination $oldCurrent -Force
    Copy-Item -LiteralPath $previousPath -Destination $newCurrent -Force
    Copy-StableBinary -Source $previous["console_path"] -Target (Join-Path $binDir "edge-console.exe")
    Copy-StableBinary -Source $previous["diagnostic_path"] -Target $stableDiagnostic
    Move-Item -LiteralPath $newCurrent -Destination $currentPath -Force
    Move-Item -LiteralPath $oldCurrent -Destination $previousPath -Force
    [void](Invoke-Diagnostic -Diagnostic $stableDiagnostic -State $currentPath)
    Write-Output ("Rolled back Windows release to " + $previous["release_set_sha256"])
    exit 0
}

Assert-HexSha256 -Value $ReleaseSetSha256 -Name "ReleaseSetSha256"
$tag = "edge-release-$ReleaseSetSha256"
$releaseDir = Join-Path $releasesDir $ReleaseSetSha256
$releaseSetPath = Join-Path $releaseDir "release-set.pb"
$releaseSetSidecar = Join-Path $releaseDir "release-set.pb.sha256"
$packagePath = Join-Path $releaseDir "edge-platform-windows.zip"
$packageSidecar = Join-Path $releaseDir "edge-platform-windows.zip.sha256"

$requiredInstalled = @(
    $releaseSetPath, $releaseSetSidecar, $packagePath, $packageSidecar,
    (Join-Path $releaseDir "bin\edge-release-set.exe"),
    (Join-Path $releaseDir "bin\edge-diagnostic.exe")
)
$needsInstall = @($requiredInstalled | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -gt 0

if ($needsInstall) {
    $stage = Join-Path $env:TEMP ("edge-platform-release-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        $patterns = @("release-set.pb", "release-set.pb.sha256", "edge-platform-windows.zip", "edge-platform-windows.zip.sha256")
        $downloadArgs = @("release", "download", $tag, "-R", $Repository, "--dir", $stage)
        foreach ($pattern in $patterns) { $downloadArgs += @("--pattern", $pattern) }
        & $GhExe @downloadArgs
        if ($LASTEXITCODE -ne 0) { throw "Failed to download durable release $tag" }

        $stageReleaseSet = Join-Path $stage "release-set.pb"
        $stageReleaseSetSidecar = Join-Path $stage "release-set.pb.sha256"
        $stagePackage = Join-Path $stage "edge-platform-windows.zip"
        $stagePackageSidecar = Join-Path $stage "edge-platform-windows.zip.sha256"
        [void](Assert-ShaSidecar -File $stageReleaseSet -Sidecar $stageReleaseSetSidecar -ExpectedName "release-set.pb" -ExpectedDigest $ReleaseSetSha256)
        [void](Assert-ShaSidecar -File $stagePackage -Sidecar $stagePackageSidecar -ExpectedName "edge-platform-windows.zip")

        $unpacked = Join-Path $stage "unpacked"
        Expand-Archive -LiteralPath $stagePackage -DestinationPath $unpacked -Force
        foreach ($name in @("edge-controller.exe", "edge-console.exe", "sing-box.exe", "edge-diagnostic.exe", "edge-release-set.exe")) {
            if (-not (Test-Path -LiteralPath (Join-Path $unpacked "bin\$name"))) { throw "Windows release package is missing bin\$name" }
        }

        $tool = Join-Path $unpacked "bin\edge-release-set.exe"
        $verifyArgs = @(
            "verify-windows", "--input", $stageReleaseSet, "--sha256-file", $stageReleaseSetSidecar,
            "--windows-artifact", $stagePackage,
            "--windows-controller", (Join-Path $unpacked "bin\edge-controller.exe"),
            "--windows-console", (Join-Path $unpacked "bin\edge-console.exe"),
            "--windows-diagnostic", (Join-Path $unpacked "bin\edge-diagnostic.exe"),
            "--windows-sing-box", (Join-Path $unpacked "bin\sing-box.exe")
        )
        & $tool @verifyArgs
        if ($LASTEXITCODE -ne 0) { throw "Downloaded Windows release failed ReleaseSet verification" }

        $releaseStage = "$releaseDir.new"
        if (Test-Path -LiteralPath $releaseStage) { Remove-Item -Recurse -Force $releaseStage }
        New-Item -ItemType Directory -Force -Path $releaseStage | Out-Null
        Copy-Item -LiteralPath $stageReleaseSet -Destination (Join-Path $releaseStage "release-set.pb")
        Copy-Item -LiteralPath $stageReleaseSetSidecar -Destination (Join-Path $releaseStage "release-set.pb.sha256")
        Copy-Item -LiteralPath $stagePackage -Destination (Join-Path $releaseStage "edge-platform-windows.zip")
        Copy-Item -LiteralPath $stagePackageSidecar -Destination (Join-Path $releaseStage "edge-platform-windows.zip.sha256")
        Copy-Item -LiteralPath (Join-Path $unpacked "bin") -Destination $releaseStage -Recurse
        if (Test-Path -LiteralPath $releaseDir) { Remove-Item -Recurse -Force $releaseDir }
        Move-Item -LiteralPath $releaseStage -Destination $releaseDir
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -Recurse -Force $stage }
    }
}

[void](Assert-ShaSidecar -File $releaseSetPath -Sidecar $releaseSetSidecar -ExpectedName "release-set.pb" -ExpectedDigest $ReleaseSetSha256)
[void](Assert-ShaSidecar -File $packagePath -Sidecar $packageSidecar -ExpectedName "edge-platform-windows.zip")

$tool = Join-Path $releaseDir "bin\edge-release-set.exe"
$diagnostic = Join-Path $releaseDir "bin\edge-diagnostic.exe"
$controller = Join-Path $releaseDir "bin\edge-controller.exe"
$console = Join-Path $releaseDir "bin\edge-console.exe"
$singBox = Join-Path $releaseDir "bin\sing-box.exe"
$verifyArgs = @(
    "verify-windows", "--input", $releaseSetPath, "--sha256-file", $releaseSetSidecar,
    "--windows-artifact", $packagePath, "--windows-controller", $controller,
    "--windows-console", $console, "--windows-diagnostic", $diagnostic, "--windows-sing-box", $singBox
)
& $tool @verifyArgs
if ($LASTEXITCODE -ne 0) { throw "Installed Windows release failed exact ReleaseSet verification" }

$currentTemp = "$currentPath.new"
$activationArgs = @(
    "write-windows-activation", "--input", $releaseSetPath, "--sha256-file", $releaseSetSidecar,
    "--release-dir", $releaseDir, "--controller", $controller, "--console", $console,
    "--diagnostic", $diagnostic, "--sing-box", $singBox, "--output", $currentTemp
)
& $tool @activationArgs
if ($LASTEXITCODE -ne 0) { throw "Failed to create typed Windows activation state" }
[void](Invoke-Diagnostic -Diagnostic $diagnostic -State $currentTemp)

$stableConsole = Join-Path $binDir "edge-console.exe"
$stableDiagnostic = Join-Path $binDir "edge-diagnostic.exe"
Copy-StableBinary -Source $console -Target $stableConsole
Copy-StableBinary -Source $diagnostic -Target $stableDiagnostic

if (Test-Path -LiteralPath $currentPath) {
    Copy-Item -LiteralPath $currentPath -Destination "$previousPath.new" -Force
    Move-Item -LiteralPath "$previousPath.new" -Destination $previousPath -Force
}
Move-Item -LiteralPath $currentTemp -Destination $currentPath -Force
[void](Invoke-Diagnostic -Diagnostic $stableDiagnostic -State $currentPath)

Write-Output "Activated exact Windows ReleaseSet $ReleaseSetSha256"
Write-Output "current_state=$currentPath"
Write-Output "diagnostic=$stableDiagnostic"
