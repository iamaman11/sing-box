[CmdletBinding()]
param(
    [string]$Repository = "iamaman11/sing-box",
    [Parameter(Mandatory = $true)]
    [string]$ReleaseSetSha256,
    [Parameter(Mandatory = $true)]
    [string]$AcceptedRevision,
    [string]$InstallRoot = "C:\sing-box",
    [string]$GitHubToken = $env:EDGE_GITHUB_TOKEN,
    [switch]$ForceRematerialize
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$GitHubReadAttempts = 3
$GitHubReadTimeoutSec = 15
$GitHubAssetTimeoutSec = 120
$GitHubRetryDelaySec = 2

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

function Get-GitHubHeaders {
    param([string]$Accept = "application/vnd.github+json")
    $headers = @{
        Accept = $Accept
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent" = "sing-box-edge-platform"
    }
    if (-not [string]::IsNullOrWhiteSpace($GitHubToken)) {
        $headers["Authorization"] = "Bearer $GitHubToken"
    }
    return $headers
}

function Test-TransientGitHubReadFailure {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $response = $ErrorRecord.Exception.Response
    if ($null -eq $response) { return $true }

    try {
        $statusCode = [int]$response.StatusCode
    } catch {
        return $false
    }

    return @(408, 425, 429, 500, 502, 503, 504) -contains $statusCode
}

function Invoke-GitHubJsonGet {
    param([Parameter(Mandatory)] [string]$Uri)

    for ($attempt = 1; $attempt -le $GitHubReadAttempts; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers (Get-GitHubHeaders) -TimeoutSec $GitHubReadTimeoutSec
        } catch {
            $transient = Test-TransientGitHubReadFailure -ErrorRecord $_
            if (-not $transient -or $attempt -ge $GitHubReadAttempts) { throw }
            Write-Warning "Transient GitHub metadata read failure; retrying attempt $($attempt + 1)/$GitHubReadAttempts"
            Start-Sleep -Seconds $GitHubRetryDelaySec
        }
    }

    throw "GitHub metadata read exhausted without a terminal result"
}

function Invoke-GitHubAssetGet {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [Parameter(Mandatory)] [string]$Destination
    )

    for ($attempt = 1; $attempt -le $GitHubReadAttempts; $attempt++) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        try {
            Invoke-WebRequest -UseBasicParsing -Method Get -Uri $Uri -Headers (Get-GitHubHeaders "application/octet-stream") -OutFile $Destination -TimeoutSec $GitHubAssetTimeoutSec
            return
        } catch {
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
            $transient = Test-TransientGitHubReadFailure -ErrorRecord $_
            if (-not $transient -or $attempt -ge $GitHubReadAttempts) { throw }
            Write-Warning "Transient GitHub asset read failure; retrying attempt $($attempt + 1)/$GitHubReadAttempts"
            Start-Sleep -Seconds $GitHubRetryDelaySec
        }
    }

    throw "GitHub asset read exhausted without a terminal result"
}

function Assert-LowerHexRevision {
    param([string]$Value, [string]$Name)
    if ($Value -notmatch "^[0-9a-f]{40}$") { throw "$Name must be an exact lowercase 40-character Git revision" }
}

function Assert-AcceptedReleaseAuthority {
    param(
        [Parameter(Mandatory)] [string]$AcceptedRevision,
        [Parameter(Mandatory)] [string]$Tag
    )
    Assert-LowerHexRevision -Value $AcceptedRevision -Name "AcceptedRevision"

    $branchUri = "https://api.github.com/repos/$Repository/branches/main"
    $branch = Invoke-GitHubJsonGet -Uri $branchUri
    if ([string]$branch.commit.sha -ne $AcceptedRevision) {
        throw "AcceptedRevision is not the current canonical main"
    }
    if (-not [bool]$branch.protected) {
        throw "Canonical main is not protected; refusing Windows release activation"
    }

    $tagUri = "https://api.github.com/repos/$Repository/git/ref/tags/$Tag"
    $tagRef = Invoke-GitHubJsonGet -Uri $tagUri
    if ([string]$tagRef.object.type -ne "commit") {
        throw "Durable release tag must resolve directly to a commit"
    }
    if ([string]$tagRef.object.sha -ne $AcceptedRevision) {
        throw "Durable release tag does not resolve to AcceptedRevision"
    }
}

function Get-DurableRelease {
    param([Parameter(Mandatory)] [string]$Tag)
    $uri = "https://api.github.com/repos/$Repository/releases/tags/$Tag"
    try {
        return Invoke-GitHubJsonGet -Uri $uri
    } catch {
        throw "Failed to resolve exact durable GitHub Release $Tag. For a private repository provide EDGE_GITHUB_TOKEN with read access. $($_.Exception.Message)"
    }
}

function Download-DurableReleaseAsset {
    param(
        [Parameter(Mandatory)] $Release,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Destination
    )
    $matches = @($Release.assets | Where-Object { [string]$_.name -eq $Name })
    if ($matches.Count -ne 1) {
        throw "Durable release must contain exactly one asset named $Name; observed $($matches.Count)"
    }
    $assetUri = [string]$matches[0].url
    if ([string]::IsNullOrWhiteSpace($assetUri)) { throw "Durable release asset $Name has no API URL" }
    Invoke-GitHubAssetGet -Uri $assetUri -Destination $Destination
    if (-not (Test-Path -LiteralPath $Destination)) { throw "Durable release asset download did not create $Destination" }
}

function Assert-AcceptedCandidateSource {
    param(
        [Parameter(Mandatory)] [string[]]$VerificationOutput,
        [string]$AcceptedRevision
    )
    if ([string]::IsNullOrWhiteSpace($AcceptedRevision)) { return }

    $matches = @($VerificationOutput | Where-Object { ([string]$_).StartsWith("source_revision=") })
    if ($matches.Count -ne 1) {
        throw "Windows ReleaseSet verification must emit exactly one source_revision"
    }
    $sourceRevision = ([string]$matches[0]).Substring("source_revision=".Length)
    Assert-LowerHexRevision -Value $sourceRevision -Name "ReleaseSet.source_revision"

    $acceptedCommit = Invoke-GitHubJsonGet -Uri "https://api.github.com/repos/$Repository/git/commits/$AcceptedRevision"
    $sourceCommit = Invoke-GitHubJsonGet -Uri "https://api.github.com/repos/$Repository/git/commits/$sourceRevision"

    $parents = @($acceptedCommit.parents)
    if ($parents.Count -ne 2 -or [string]$parents[1].sha -ne $sourceRevision) {
        throw "ReleaseSet.source_revision is not the accepted PR-head parent of AcceptedRevision"
    }
    if ([string]$sourceCommit.tree.sha -ne [string]$acceptedCommit.tree.sha) {
        throw "ReleaseSet source tree does not match AcceptedRevision tree"
    }
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

function Refresh-StableBootstrapInstaller {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$InstallRoot
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Verified release is missing bootstrap installer: $Source"
    }

    $bootstrapDir = Join-Path $InstallRoot "bootstrap"
    New-Item -ItemType Directory -Force -Path $bootstrapDir | Out-Null
    $target = Join-Path $bootstrapDir "install-windows-release.ps1"
    $temp = "$target.new"
    Copy-Item -LiteralPath $Source -Destination $temp -Force
    if ((Get-ExactHash -Path $temp) -ne (Get-ExactHash -Path $Source)) {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        throw "Bootstrap installer refresh failed SHA-256 verification"
    }
    Move-Item -LiteralPath $temp -Destination $target -Force
}
function Activate-ReleaseAuthority {
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$ReleaseSetPath,
        [Parameter(Mandatory)] [string]$ReleaseSetSidecar,
        [Parameter(Mandatory)] [string]$ReleaseDir,
        [Parameter(Mandatory)] [string]$Controller,
        [Parameter(Mandatory)] [string]$Console,
        [Parameter(Mandatory)] [string]$Diagnostic,
        [Parameter(Mandatory)] [string]$SingBox,
        [Parameter(Mandatory)] [string]$InstallRoot,
        [switch]$PreservePrevious
    )

    $binDir = Join-Path $InstallRoot "bin"
    $currentPath = Join-Path $InstallRoot "current.pb"
    $previousPath = Join-Path $InstallRoot "previous.pb"
    $currentTemp = "$currentPath.new"

    $activationArgs = @(
        "write-windows-activation", "--input", $ReleaseSetPath, "--sha256-file", $ReleaseSetSidecar,
        "--release-dir", $ReleaseDir, "--controller", $Controller, "--console", $Console,
        "--diagnostic", $Diagnostic, "--sing-box", $SingBox, "--output", $currentTemp
    )
    $null = & $Tool @activationArgs
    if ($LASTEXITCODE -ne 0) { throw "Failed to create typed Windows activation state" }
    [void](Invoke-Diagnostic -Diagnostic $Diagnostic -State $currentTemp)

    $stableConsole = Join-Path $binDir "edge-console.exe"
    $stableDiagnostic = Join-Path $binDir "edge-diagnostic.exe"
    Copy-StableBinary -Source $Console -Target $stableConsole
    Copy-StableBinary -Source $Diagnostic -Target $stableDiagnostic

    if ((Test-Path -LiteralPath $currentPath) -and -not $PreservePrevious) {
        Copy-Item -LiteralPath $currentPath -Destination "$previousPath.new" -Force
        Move-Item -LiteralPath "$previousPath.new" -Destination $previousPath -Force
    }
    Move-Item -LiteralPath $currentTemp -Destination $currentPath -Force
    [void](Invoke-Diagnostic -Diagnostic $stableDiagnostic -State $currentPath)

    return @{
        current_state = $currentPath
        console = $stableConsole
        diagnostic = $stableDiagnostic
    }
}

$binDir = Join-Path $InstallRoot "bin"
$releasesDir = Join-Path $InstallRoot "releases"
$currentPath = Join-Path $InstallRoot "current.pb"
$previousPath = Join-Path $InstallRoot "previous.pb"
New-Item -ItemType Directory -Force -Path $binDir, $releasesDir | Out-Null

Assert-HexSha256 -Value $ReleaseSetSha256 -Name "ReleaseSetSha256"
$tag = "edge-release-$ReleaseSetSha256"
Assert-AcceptedReleaseAuthority -AcceptedRevision $AcceptedRevision -Tag $tag
$canonicalReleaseDir = Join-Path $releasesDir $ReleaseSetSha256
$repairReleaseDir = Join-Path $releasesDir ($ReleaseSetSha256 + ".repair")
$releaseDir = $canonicalReleaseDir
$preservePrevious = $false
$currentReleaseDir = ""

if ($ForceRematerialize) {
    $stableDiagnostic = Join-Path $binDir "edge-diagnostic.exe"
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
        throw "ForceRematerialize requires a verified current activation"
    }
    if (-not (Test-Path -LiteralPath $stableDiagnostic -PathType Leaf)) {
        throw "ForceRematerialize requires the stable diagnostic boundary"
    }
    $current = Invoke-Diagnostic -Diagnostic $stableDiagnostic -State $currentPath
    if ([string]$current["release_set_sha256"] -ne $ReleaseSetSha256) {
        throw "ForceRematerialize target must equal the exact current ReleaseSet"
    }
    $currentReleaseDir = [IO.Path]::GetFullPath([string]$current["release_dir"]).TrimEnd('\')
    $canonicalFull = [IO.Path]::GetFullPath($canonicalReleaseDir).TrimEnd('\')
    $repairFull = [IO.Path]::GetFullPath($repairReleaseDir).TrimEnd('\')
    if ($currentReleaseDir -ceq $canonicalFull) {
        $releaseDir = $repairReleaseDir
    } elseif ($currentReleaseDir -ceq $repairFull) {
        $releaseDir = $canonicalReleaseDir
    } else {
        throw "ForceRematerialize current activation is outside the bounded canonical/repair slots"
    }
    if ([IO.Path]::GetFullPath($releaseDir).TrimEnd('\') -ceq $currentReleaseDir) {
        throw "ForceRematerialize refuses to overwrite the active immutable release directory"
    }
    $preservePrevious = $true
    Write-Output "rematerialize_from=$currentReleaseDir"
    Write-Output "rematerialize_to=$([IO.Path]::GetFullPath($releaseDir))"
}

$releaseSetPath = Join-Path $releaseDir "release-set.pb"
$releaseSetSidecar = Join-Path $releaseDir "release-set.pb.sha256"
$packagePath = Join-Path $releaseDir "edge-platform-windows.zip"
$packageSidecar = Join-Path $releaseDir "edge-platform-windows.zip.sha256"

$requiredInstalled = @(
    $releaseSetPath, $releaseSetSidecar, $packagePath, $packageSidecar,
    (Join-Path $releaseDir "bin\edge-release-set.exe"),
    (Join-Path $releaseDir "bin\edge-diagnostic.exe"),
    (Join-Path $releaseDir "bootstrap\install-windows-release.ps1")
)
$needsInstall = $ForceRematerialize -or @($requiredInstalled | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -gt 0

if ($needsInstall) {
    $stage = Join-Path $env:TEMP ("edge-platform-release-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        $release = Get-DurableRelease -Tag $tag
        foreach ($name in @("release-set.pb", "release-set.pb.sha256", "edge-platform-windows.zip", "edge-platform-windows.zip.sha256")) {
            Download-DurableReleaseAsset -Release $release -Name $name -Destination (Join-Path $stage $name)
        }

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
        if (-not (Test-Path -LiteralPath (Join-Path $unpacked "bootstrap\install-windows-release.ps1") -PathType Leaf)) {
            throw "Windows release package is missing bootstrap\install-windows-release.ps1"
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
        $verificationOutput = @(& $tool @verifyArgs)
        if ($LASTEXITCODE -ne 0) { throw "Downloaded Windows release failed ReleaseSet verification" }
        Assert-AcceptedCandidateSource -VerificationOutput $verificationOutput -AcceptedRevision $AcceptedRevision
        $verificationOutput | Write-Output

        $releaseStage = "$releaseDir.new"
        if (Test-Path -LiteralPath $releaseStage) { Remove-Item -Recurse -Force $releaseStage }
        New-Item -ItemType Directory -Force -Path $releaseStage | Out-Null
        Copy-Item -LiteralPath $stageReleaseSet -Destination (Join-Path $releaseStage "release-set.pb")
        Copy-Item -LiteralPath $stageReleaseSetSidecar -Destination (Join-Path $releaseStage "release-set.pb.sha256")
        Copy-Item -LiteralPath $stagePackage -Destination (Join-Path $releaseStage "edge-platform-windows.zip")
        Copy-Item -LiteralPath $stagePackageSidecar -Destination (Join-Path $releaseStage "edge-platform-windows.zip.sha256")
        Copy-Item -LiteralPath (Join-Path $unpacked "bin") -Destination $releaseStage -Recurse
        Copy-Item -LiteralPath (Join-Path $unpacked "bootstrap") -Destination $releaseStage -Recurse
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
$releaseInstaller = Join-Path $releaseDir "bootstrap\install-windows-release.ps1"
$verifyArgs = @(
    "verify-windows", "--input", $releaseSetPath, "--sha256-file", $releaseSetSidecar,
    "--windows-artifact", $packagePath, "--windows-controller", $controller,
    "--windows-console", $console, "--windows-diagnostic", $diagnostic, "--windows-sing-box", $singBox
)
$verificationOutput = @(& $tool @verifyArgs)
if ($LASTEXITCODE -ne 0) { throw "Installed Windows release failed exact ReleaseSet verification" }
Assert-AcceptedCandidateSource -VerificationOutput $verificationOutput -AcceptedRevision $AcceptedRevision
$verificationOutput | Write-Output

if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
    $current = Invoke-Diagnostic -Diagnostic $diagnostic -State $currentPath
    if (-not $ForceRematerialize -and $current["release_set_sha256"] -eq $ReleaseSetSha256) {
        Assert-AcceptedCandidateSource -VerificationOutput @("source_revision=$($current["source_revision"])") -AcceptedRevision $AcceptedRevision
        Refresh-StableBootstrapInstaller -Source $releaseInstaller -InstallRoot $InstallRoot
        Write-Output "Windows ReleaseSet $ReleaseSetSha256 is already active"
        Write-Output "activation=NOOP"
        Write-Output "current_state=$currentPath"
        Write-Output "console=$($current["console_path"])"
        Write-Output "diagnostic=$($current["diagnostic_path"])"
        Write-Output "runtime_state=NOT_CONFIGURED"
        Write-Output "runtime_config=NOT_CONFIGURED"
        Write-Output "automation_registered=false"
        exit 0
    }
}

$activation = Activate-ReleaseAuthority `
    -Tool $tool `
    -ReleaseSetPath $releaseSetPath `
    -ReleaseSetSidecar $releaseSetSidecar `
    -ReleaseDir $releaseDir `
    -Controller $controller `
    -Console $console `
    -Diagnostic $diagnostic `
    -SingBox $singBox `
    -InstallRoot $InstallRoot `
    -PreservePrevious:$preservePrevious

Refresh-StableBootstrapInstaller -Source $releaseInstaller -InstallRoot $InstallRoot
if ($ForceRematerialize) {
    Write-Output "rematerialization=PASS"
}
Write-Output "Activated exact Windows ReleaseSet $ReleaseSetSha256"
Write-Output "current_state=$($activation["current_state"])"
Write-Output "console=$($activation["console"])"
Write-Output "diagnostic=$($activation["diagnostic"])"
Write-Output "runtime_state=NOT_CONFIGURED"
Write-Output "runtime_config=NOT_CONFIGURED"
Write-Output "automation_registered=false"
