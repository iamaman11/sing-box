param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$Repository = "iamaman11/sing-box",
    [string]$Revision = "",
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "edge-platform"),
    [string]$GhExe = "gh.exe"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Assert-HexSha256 {
    param([string]$Value, [string]$Name)
    if ($Value -notmatch '^[0-9a-f]{64}$') { throw "$Name is not a lowercase SHA-256 digest" }
}

function Test-Release {
    param([string]$ReleaseDir, [string]$ExpectedRevision)

    $manifestPath = Join-Path $ReleaseDir "manifest.json"
    $controller = Join-Path $ReleaseDir "edge-controller.exe"
    $console = Join-Path $ReleaseDir "edge-console.exe"
    if (-not (Test-Path $manifestPath) -or -not (Test-Path $controller) -or -not (Test-Path $console)) {
        return $false
    }

    $manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or [string]$manifest.source_revision -ne $ExpectedRevision) {
        return $false
    }

    $controllerExpected = ([string]$manifest.controller_sha256).ToLowerInvariant()
    $consoleExpected = ([string]$manifest.console_sha256).ToLowerInvariant()
    Assert-HexSha256 $controllerExpected "controller_sha256"
    Assert-HexSha256 $consoleExpected "console_sha256"

    $controllerActual = (Get-FileHash -Algorithm SHA256 $controller).Hash.ToLowerInvariant()
    $consoleActual = (Get-FileHash -Algorithm SHA256 $console).Hash.ToLowerInvariant()
    return $controllerActual -eq $controllerExpected -and $consoleActual -eq $consoleExpected
}

if (-not (Test-Path $RepoRoot)) { throw "Repo root not found: $RepoRoot" }
if (-not (Get-Command $GhExe -ErrorAction SilentlyContinue)) { throw "GitHub CLI not found: $GhExe" }
& $GhExe auth status 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "GitHub CLI is not authenticated; run 'gh auth login' first" }

if ([string]::IsNullOrWhiteSpace($Revision)) {
    $line = (& git ls-remote "https://github.com/$Repository.git" refs/heads/main | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($line)) { throw "Unable to resolve canonical remote main" }
    $Revision = ($line -split '\s+')[0].Trim().ToLowerInvariant()
}
if ($Revision -notmatch '^[0-9a-f]{40}$') { throw "Revision must be an exact 40-character Git commit SHA" }

$releaseDir = Join-Path (Join-Path $InstallRoot "releases") $Revision
$artifactName = "edge-platform-windows-$Revision"

if (-not (Test-Release -ReleaseDir $releaseDir -ExpectedRevision $Revision)) {
    $apiArgs = @(
        "api", "--method", "GET",
        "-f", "branch=main",
        "-f", "event=push",
        "-f", "status=success",
        "-f", "head_sha=$Revision",
        "-f", "per_page=20",
        "repos/$Repository/actions/workflows/edge-platform-ci.yml/runs"
    )
    $runsRaw = & $GhExe @apiArgs
    if ($LASTEXITCODE -ne 0) { throw "Failed to resolve accepted Edge Platform CI build" }
    $runs = ($runsRaw | ConvertFrom-Json).workflow_runs |
        Where-Object { $_.head_sha -eq $Revision -and $_.conclusion -eq "success" } |
        Sort-Object created_at
    $run = $runs | Select-Object -First 1
    if (-not $run) { throw "No successful accepted Edge Platform CI run exists for exact revision $Revision" }

    $staging = Join-Path $env:TEMP ("edge-platform-windows-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $staging | Out-Null
    try {
        & $GhExe run download ([string]$run.id) -R $Repository -n $artifactName -D $staging
        if ($LASTEXITCODE -ne 0) { throw "Failed to download $artifactName from run $($run.id)" }
        if (-not (Test-Release -ReleaseDir $staging -ExpectedRevision $Revision)) {
            throw "Downloaded Windows control artifact failed exact provenance verification"
        }

        $releaseParent = Split-Path -Parent $releaseDir
        New-Item -ItemType Directory -Force -Path $releaseParent | Out-Null
        if (Test-Path $releaseDir) { Remove-Item -Recurse -Force $releaseDir }
        Move-Item -LiteralPath $staging -Destination $releaseDir
        $staging = ""
    } finally {
        if ($staging -and (Test-Path $staging)) { Remove-Item -Recurse -Force $staging }
    }
}

if (-not (Test-Release -ReleaseDir $releaseDir -ExpectedRevision $Revision)) {
    throw "Installed release failed exact provenance verification"
}

$manifest = Get-Content -Raw (Join-Path $releaseDir "manifest.json") | ConvertFrom-Json
$binDir = Join-Path $InstallRoot "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$consoleSource = Join-Path $releaseDir "edge-console.exe"
$consoleTarget = Join-Path $binDir "edge-console.exe"
$consoleTemp = Join-Path $binDir "edge-console.exe.new"
Copy-Item -LiteralPath $consoleSource -Destination $consoleTemp -Force
if ((Get-FileHash -Algorithm SHA256 $consoleTemp).Hash.ToLowerInvariant() -ne ([string]$manifest.console_sha256).ToLowerInvariant()) {
    Remove-Item -Force $consoleTemp -ErrorAction SilentlyContinue
    throw "Stable edge-console copy failed SHA-256 verification"
}
Move-Item -LiteralPath $consoleTemp -Destination $consoleTarget -Force

$current = [ordered]@{
    schema = 1
    source_revision = $Revision
    release_dir = $releaseDir
    controller_path = (Join-Path $releaseDir "edge-controller.exe")
    console_path = $consoleTarget
    controller_sha256 = ([string]$manifest.controller_sha256).ToLowerInvariant()
    console_sha256 = ([string]$manifest.console_sha256).ToLowerInvariant()
}
$currentPath = Join-Path $InstallRoot "current.json"
$currentTemp = "$currentPath.new"
$current | ConvertTo-Json | Set-Content -Encoding utf8NoBOM $currentTemp
Move-Item -LiteralPath $currentTemp -Destination $currentPath -Force

Write-Output "Installed accepted Windows control release $Revision"
Write-Output "edge-console: $consoleTarget"
Write-Output "edge-controller: $($current.controller_path)"
