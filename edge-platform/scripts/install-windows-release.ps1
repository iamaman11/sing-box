[CmdletBinding()]
param(
    [string]$Repository = "iamaman11/sing-box",
    [string]$ReleaseSetSha256 = "",
    [string]$AcceptedRevision = "",
    # One operator entrypoint: select exact published main ReleaseSet, no SHA
    # hand-copied from GitHub. Retained old BEGIN needs separate explicit scope.
    [switch]$ConnectWindows,
    [switch]$ApproveRetainedBegin,
    [string]$InstallRoot = "C:\sing-box",
    [string]$GitHubToken = $env:EDGE_GITHUB_TOKEN,
    [switch]$ForceRematerialize,
    # Historical ReleaseSet is permitted ONLY for one already-published
    # first-use acceptance, never for the installed serving application.
    [UInt64]$ArchivedAcceptanceSourceRunId = 0,
    [switch]$Offline,
    # Exact candidate staging only. No pointer, SCM or task mutation.
    [switch]$StageOnly,
    [switch]$BootstrapNow,
    # An explicit opt-in for the SAME approved offline-bootstrap invocation.
    # The SYSTEM task (not this script) generates the private Ed25519 key.
    [switch]$EnrollReceipt,
    # Explicit local elevated Administrator supersession of an OLD retained
    # one-shot BEGIN. Never silently inferred from an installed newer version.
    [string]$RetainedIntentSha256 = "",
    [string]$ExpectedCurrentReleaseSetSha256 = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$GitHubReadAttempts = 3
$GitHubReadTimeoutSec = 15
$GitHubAssetTimeoutSec = 120
$GitHubRetryDelaySec = 2

function Assert-OfflineWindow {
    if (-not $Offline) { return }
    if ($ForceRematerialize) {
        throw 'OFFLINE_HANDOFF_BLOCKED: offline rematerialization is not a supported transition'
    }
    if ([IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') -cne 'C:\sing-box') {
        throw 'OFFLINE_HANDOFF_BLOCKED: unexpected install root'
    }
    # Exact SCM service identity, account, status and command are verified
    # exclusively by the native privileged owner, not the release installer.
    $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='sing-box.exe'" -ErrorAction Stop)
    if ($processes.Count -ne 0) {
        throw 'OFFLINE_HANDOFF_BLOCKED: sing-box process exists, no owner will be killed'
    }
    $tuns = @(Get-NetAdapter -Name 'sing-box-tun' -ErrorAction SilentlyContinue)
    if ($tuns.Count -ne 0) {
        throw 'OFFLINE_HANDOFF_BLOCKED: managed TUN adapter still exists'
    }
}

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

    # PowerShell 7 transport failures may have no HTTP Response property.
    # StrictMode must not replace the original IOException/HttpRequestException
    # with a missing-property RuntimeException. A response-less failure keeps
    # the pre-existing bounded read-retry policy; the caller rethrows the
    # ORIGINAL ErrorRecord verbatim on the final attempt.
    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($null -eq $responseProperty -or $null -eq $responseProperty.Value) {
        return $true
    }
    $response = $responseProperty.Value

    try {
        $statusCode = [int]$response.StatusCode
    } catch {
        return $false
    }

    return @(408, 425, 429, 500, 502, 503, 504) -contains $statusCode
}


function Get-GitHubTransportOptions {
    param([Parameter(Mandatory)] [string]$Uri)

    if (-not $Offline) { return @{} }
    # First-use offline bootstrap has an independently proven direct GitHub
    # route. Ignore ambient HTTP(S)_PROXY only for bounded official GitHub
    # reads; normal installations retain their existing transport policy.
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: PowerShell 7 required for direct GitHub transport'
    }
    $target = [Uri]$Uri
    if ($target.Scheme -cne 'https' -or $target.Host -cne 'api.github.com' -or
        $target.Port -ne 443 -or $target.UserInfo) {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: only HTTPS GitHub API downloads permitted'
    }
    return @{ NoProxy = $true }
}

function Invoke-GitHubJsonGet {
    param([Parameter(Mandatory)] [string]$Uri)
    $transport = Get-GitHubTransportOptions -Uri $Uri

    for ($attempt = 1; $attempt -le $GitHubReadAttempts; $attempt++) {
        try {
            return Invoke-RestMethod @transport -Method Get -Uri $Uri -Headers (Get-GitHubHeaders) -TimeoutSec $GitHubReadTimeoutSec
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
    $transport = Get-GitHubTransportOptions -Uri $Uri

    for ($attempt = 1; $attempt -le $GitHubReadAttempts; $attempt++) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        try {
            Invoke-WebRequest @transport -UseBasicParsing -Method Get -Uri $Uri -Headers (Get-GitHubHeaders "application/octet-stream") -OutFile $Destination -TimeoutSec $GitHubAssetTimeoutSec
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
        [Parameter(Mandatory)] [string]$Tag,
        [UInt64]$ArchivedAcceptanceSourceRunId = 0
    )
    Assert-LowerHexRevision -Value $AcceptedRevision -Name "AcceptedRevision"

    $branchUri = "https://api.github.com/repos/$Repository/branches/main"
    $branch = Invoke-GitHubJsonGet -Uri $branchUri
    if ([string]$branch.commit.sha -ne $AcceptedRevision) {
        if ($ArchivedAcceptanceSourceRunId -lt 10000000) {
            throw "AcceptedRevision is not the current canonical main"
        }
        # The only permitted exception is an independently journal-attested
        # first-use release within a disposable, isolated Windows root.
        if ([IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') -cne 'C:\sing-box-acceptance' -or
            $env:GITHUB_EVENT_NAME -cne 'issue_comment' -or
            $env:GITHUB_RUN_ATTEMPT -cne '1' -or
            $env:GITHUB_REPOSITORY -cne 'iamaman11/sing-box' -or
            $env:GITHUB_REPOSITORY_ID -cne '1221750822') {
            throw 'ARCHIVED_ACCEPTANCE_BLOCKED: foreign Windows owner or non-isolated root'
        }
        $original = Invoke-GitHubJsonGet -Uri "https://api.github.com/repos/$Repository/actions/runs/$ArchivedAcceptanceSourceRunId"
        if ([UInt64]$original.id -ne $ArchivedAcceptanceSourceRunId -or
            [string]$original.head_sha -cne $AcceptedRevision -or
            [string]$original.status -cne 'completed' -or
            [string]$original.conclusion -cne 'failure' -or
            [string]$original.event -cne 'issue_comment' -or
            [UInt64]$original.run_attempt -ne 1 -or
            [UInt64]$original.actor.id -ne 44100369) {
            throw 'ARCHIVED_ACCEPTANCE_BLOCKED: exact original GitHub run is not proved'
        }
        $compare = Invoke-GitHubJsonGet -Uri "https://api.github.com/repos/$Repository/compare/$AcceptedRevision...main"
        if ([string]$compare.status -notin @('ahead', 'identical')) {
            throw 'ARCHIVED_ACCEPTANCE_BLOCKED: original accepted revision is not a canonical main ancestor'
        }
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
    if ($LASTEXITCODE -ne 0 -and -not $Offline) { throw "Windows diagnostic failed for $State" }
    $values = @{}
    foreach ($line in $output) {
        $parts = ([string]$line).Split("=", 2)
        if ($parts.Count -eq 2) { $values[$parts[0]] = $parts[1] }
    }
    if ($Offline) {
        if ([string]$values["exact_release_files"] -cne "PASS" -or
            [string]$values["scm_state"] -cne "Stopped" -or
            [string]$values["managed_tun_present"] -cne "false") {
            throw "OFFLINE_HANDOFF_BLOCKED: diagnostic cannot attest exact files and stopped no-TUN host"
        }
    } elseif ($values["status"] -ne "PASS" -or $values["exact_release_files"] -ne "PASS") {
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

# Resolve current published authority BEFORE any creation, SCM, task or marker.
# This branch reuses this same immutable verified installer, not a new agent.
if ($ConnectWindows) {
    if ($Repository -cne 'iamaman11/sing-box' -or
        $InstallRoot -cne 'C:\sing-box' -or
        $ReleaseSetSha256 -or $AcceptedRevision -or $Offline -or $BootstrapNow -or
        $StageOnly -or $EnrollReceipt -or $ForceRematerialize -or
        $ArchivedAcceptanceSourceRunId -ne 0 -or $RetainedIntentSha256 -or
        $ExpectedCurrentReleaseSetSha256) {
        throw 'WINDOWS_CONNECT_INVALID_SCOPE: only canonical local first-use, no SHA inputs'
    }
    # Reuse the already proven direct HTTPS GitHub policy of offline W4:
    # never silently select a different ambient Windows proxy path.
    $Offline = $true
    $currentPath = Join-Path $InstallRoot 'current.pb'
    $stableDiagnostic = Join-Path $InstallRoot 'bin\edge-diagnostic.exe'
    $hasCurrent = Test-Path -LiteralPath $currentPath -PathType Leaf
    $hasStable = Test-Path -LiteralPath $stableDiagnostic -PathType Leaf
    if ($hasCurrent -ne $hasStable) {
        throw 'WINDOWS_CONNECT_PARTIAL_INITIAL_INSTALL_NO_REPLAY'
    }
    $branch = Invoke-GitHubJsonGet -Uri 'https://api.github.com/repos/iamaman11/sing-box/branches/main'
    if (-not [bool]$branch.protected -or [string]$branch.commit.sha -notmatch '^[0-9a-f]{40}$') {
        throw 'WINDOWS_CONNECT_CANONICAL_MAIN_UNPROVEN'
    }
    $release = Invoke-GitHubJsonGet -Uri 'https://api.github.com/repos/iamaman11/sing-box/releases/latest'
    $tagName = [string]$release.tag_name
    if ($tagName -cnotmatch '^edge-release-([0-9a-f]{64})$' -or
        [string]$release.target_commitish -cne [string]$branch.commit.sha -or
        [bool]$release.draft -or [bool]$release.prerelease -or
        [string]::IsNullOrWhiteSpace([string]$release.published_at)) {
        throw 'WINDOWS_CONNECT_AWAITING_EXACT_PROTECTED_MAIN_RELEASE: no eligible published ReleaseSet'
    }
    $selectedDigest = $tagName.Substring('edge-release-'.Length)
    # The ordinary installer independently re-verifies the exact immutable
    # release tag, candidate source/tree, ZIP and files before native BEGIN.
    Assert-AcceptedReleaseAuthority -AcceptedRevision ([string]$branch.commit.sha) -Tag $tagName
    if (-not $hasCurrent) {
        # A clean host has no installed controller or scheduled owner yet.
        # Never overwrite an existing/partial root or foreign service.
        if (Test-Path -LiteralPath $InstallRoot) {
            throw 'WINDOWS_CONNECT_PARTIAL_ROOT_NO_REPLAY'
        }
        $argsInitial = @(
            '-AcceptedRevision', [string]$branch.commit.sha,
            '-ReleaseSetSha256', $selectedDigest,
            '-InstallRoot', $InstallRoot, '-Offline'
        )
        $global:LASTEXITCODE = 0
        & $PSCommandPath @argsInitial
        if ($LASTEXITCODE -ne 0) {
            throw 'WINDOWS_CONNECT_INITIAL_RELEASE_OUTCOME_UNKNOWN_NO_REPLAY'
        }
        $console = Join-Path $InstallRoot "releases\$selectedDigest\bin\edge-console.exe"
        if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
            throw 'WINDOWS_CONNECT_INITIAL_CONSOLE_UNPROVEN'
        }
        $global:LASTEXITCODE = 0
        & $console offline-clean-install --install-root $InstallRoot
        if ($LASTEXITCODE -ne 0) {
            throw 'WINDOWS_CONNECT_INITIAL_SCM_OR_TASK_UNKNOWN_NO_REPLAY'
        }
        Write-Output 'windows_connect=INITIAL_INSTALL_AND_IDENTITY_TRUST_INTENTS_DURABLE'
        Write-Output 'windows_connect_next=EXISTING_SYSTEM_TASK'
        exit 0
    }
    $installed = Invoke-Diagnostic -Diagnostic $stableDiagnostic -State $currentPath
    if ([string]$installed['release_set_sha256'] -ceq $selectedDigest) {
        if ($ApproveRetainedBegin) {
            throw 'WINDOWS_CONNECT_SUPERSESSION_NOT_APPLICABLE: installed release already current'
        }
        $console = [string]$installed['console_path']
        if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
            throw 'WINDOWS_CONNECT_INSTALLED_CONSOLE_MISSING'
        }
        $global:LASTEXITCODE = 0
        $stateText = & $console offline-first-use-status --install-root $InstallRoot
        if ($LASTEXITCODE -ne 0) {
            throw 'WINDOWS_CONNECT_FIRST_USE_STATE_UNPROVEN: no replay'
        }
        $state = ($stateText | Out-String | ConvertFrom-Json -ErrorAction Stop)
        if ([string]$state.schema -cne 'sing-box.windows-first-use-status/v1' -or
            [string]$state.machine_id -cne 'sing-box-windows-lab' -or
            [string]$state.installed_release_set_sha256 -cne $selectedDigest -or
            [int]$state.mutations -ne 0) {
            throw 'WINDOWS_CONNECT_FIRST_USE_STATE_NOT_CANONICAL'
        }
        # Historical offline BEGIN may remain after an uncertain handoff.
        # Status/NOOP is safe, but never authorize another identity/trust
        # mutation from this result without independent adjudication.
        $retainedBegin = Test-Path -LiteralPath (Join-Path $InstallRoot 'offline-bootstrap-intent-v1')
        if ($retainedBegin -and [string]$state.stage -in @(
            'NOT_STARTED', 'RECEIPT_READY_TRUST_NOT_REQUESTED'
        )) {
            throw 'WINDOWS_CONNECT_RETAINED_BEGIN_BLOCKS_NEW_ENROLLMENT_NO_REPLAY'
        }
        switch ([string]$state.stage) {
            'NOT_STARTED' {
                $global:LASTEXITCODE = 0
                & $console offline-receipt-identity-prepare --install-root $InstallRoot
                if ($LASTEXITCODE -ne 0) {
                    throw 'WINDOWS_CONNECT_IDENTITY_RESULT_UNKNOWN_NO_REPLAY'
                }
                Write-Output 'windows_connect=IDENTITY_AND_TRUST_REQUESTED'
                exit 0
            }
            'RECEIPT_READY_TRUST_NOT_REQUESTED' {
                $global:LASTEXITCODE = 0
                & $console offline-host-trust-prepare --install-root $InstallRoot
                if ($LASTEXITCODE -ne 0) {
                    throw 'WINDOWS_CONNECT_TRUST_RESULT_UNKNOWN_NO_REPLAY'
                }
                Write-Output 'windows_connect=TRUST_REQUESTED'
                exit 0
            }
            'SYSTEM_PENDING' {
                Write-Output 'windows_connect=SYSTEM_PENDING_NOOP'
                exit 0
            }
            'AWAITING_GIT_AUTHORITY_OR_SYSTEM' {
                Write-Output 'windows_connect=AWAITING_GIT_AUTHORITY_NOOP'
                exit 0
            }
            'TRUST_RECORDED_UNVERIFIED' {
                Write-Output 'windows_connect=TRUST_RECORDED_NOOP'
                Write-Output 'independent_worker_acceptance=NOT_PROVEN'
                exit 0
            }
            default {
                throw 'WINDOWS_CONNECT_FIRST_USE_UNKNOWN_STAGE_NO_REPLAY'
            }
        }
    }
    $argsExact = @(
        '-AcceptedRevision', [string]$branch.commit.sha,
        '-ReleaseSetSha256', $selectedDigest,
        '-InstallRoot', $InstallRoot,
        '-Offline', '-BootstrapNow', '-EnrollReceipt'
    )
    $oldBegin = Join-Path $InstallRoot 'offline-bootstrap-intent-v1'
    if (Test-Path -LiteralPath $oldBegin) {
        if (-not $ApproveRetainedBegin) {
            throw 'WINDOWS_CONNECT_RETAINED_BEGIN_REQUIRES_EXPLICIT_APPROVAL: no automatic supersession'
        }
        $entry = Get-Item -LiteralPath $oldBegin -Force -ErrorAction Stop
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $entry.Length -lt 1 -or $entry.Length -gt 512) {
            throw 'WINDOWS_CONNECT_RETAINED_BEGIN_NOT_BOUNDED_REGULAR: no replay'
        }
        $oldDigest = (Get-FileHash -LiteralPath $oldBegin -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $argsExact += @(
            '-RetainedIntentSha256', $oldDigest,
            '-ExpectedCurrentReleaseSetSha256', [string]$installed['release_set_sha256']
        )
    } elseif ($ApproveRetainedBegin) {
        throw 'WINDOWS_CONNECT_SUPERSESSION_REQUEST_WITHOUT_RETAINED_BEGIN'
    }
    $global:LASTEXITCODE = 0
    & $PSCommandPath @argsExact
    if ($LASTEXITCODE -ne 0) {
        throw 'WINDOWS_CONNECT_NATIVE_OUTCOME_UNKNOWN_NO_REPLAY: inspect installed release and journal'
    }
    Write-Output 'windows_connect=INSTALL_AND_IDENTITY_REQUEST_DURABLE'
    Write-Output 'windows_connect_next=EXISTING_SYSTEM_TASK'
    exit 0
}
if ($ApproveRetainedBegin) {
    throw 'WINDOWS_CONNECT_APPROVAL_REQUIRES_CONNECT_WINDOWS'
}
if (($StageOnly -or $BootstrapNow) -and (-not $Offline -or $ForceRematerialize -or $ArchivedAcceptanceSourceRunId -ne 0 -or ($StageOnly -and $BootstrapNow))) {
    throw 'OFFLINE_BOOTSTRAP_BLOCKED: StageOnly requires exact ordinary offline candidate'
}
if ($EnrollReceipt -and (-not $Offline -or -not $BootstrapNow -or $StageOnly -or $ForceRematerialize -or $ArchivedAcceptanceSourceRunId -ne 0)) {
    throw 'OFFLINE_BOOTSTRAP_ENROLL_BLOCKED: explicit Offline BootstrapNow required'
}
if (($StageOnly -or $BootstrapNow) -and $Repository -cne 'iamaman11/sing-box') {
    throw 'OFFLINE_BOOTSTRAP_BLOCKED: only canonical protected GitHub repository is allowed'
}
# Both independent pins are mandatory together and permitted ONLY with
# the existing explicit offline first-use. No StageOnly/online downgrade.
$hasRetained = -not [string]::IsNullOrEmpty($RetainedIntentSha256)
$hasCurrent = -not [string]::IsNullOrEmpty($ExpectedCurrentReleaseSetSha256)
if ($hasRetained -ne $hasCurrent) {
    throw 'OFFLINE_BOOTSTRAP_SUPERSESSION_BOTH_PINS_REQUIRED'
}
if ($hasRetained) {
    if (-not $Offline -or -not $BootstrapNow -or $StageOnly -or $ForceRematerialize) {
        throw 'OFFLINE_BOOTSTRAP_SUPERSESSION_ONLY_EXACT_OFFLINE_BOOTSTRAP_NOW'
    }
    Assert-HexSha256 -Value $RetainedIntentSha256 -Name 'RetainedIntentSha256'
    Assert-HexSha256 -Value $ExpectedCurrentReleaseSetSha256 -Name 'ExpectedCurrentReleaseSetSha256'
}
Assert-OfflineWindow

$binDir = Join-Path $InstallRoot "bin"
$releasesDir = Join-Path $InstallRoot "releases"
$currentPath = Join-Path $InstallRoot "current.pb"
$previousPath = Join-Path $InstallRoot "previous.pb"
New-Item -ItemType Directory -Force -Path $binDir, $releasesDir | Out-Null

Assert-HexSha256 -Value $ReleaseSetSha256 -Name "ReleaseSetSha256"
$tag = "edge-release-$ReleaseSetSha256"
Assert-AcceptedReleaseAuthority -AcceptedRevision $AcceptedRevision -Tag $tag -ArchivedAcceptanceSourceRunId $ArchivedAcceptanceSourceRunId
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

if ($StageOnly -or $BootstrapNow) {
    # Does not touch current/previous authority or stable binaries/tasks/SCM.
    $stable = Join-Path $InstallRoot "bin\edge-diagnostic.exe"
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $stable -PathType Leaf)) {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: installed stable authority absent'
    }
    $old = Invoke-Diagnostic -Diagnostic $stable -State $currentPath
    # Both stopped immutable sources are valid. ProxyOnly must already be
    # OnDemand: staging never authorizes switching an auto-start owner.
    if ([string]$old['release_set_sha256'] -ceq $ReleaseSetSha256 -or
        [string]$old['windows_datapath_mode'] -notin @('ManagedTun', 'ProxyOnly') -or
        [string]$old['scm_state'] -cne 'Stopped' -or
        [string]$old['managed_tun_present'] -cne 'false' -or
        ([string]$old['windows_datapath_mode'] -ceq 'ProxyOnly' -and
         [string]$old['scm_start_type'] -cne 'OnDemand')) {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: exact stopped ProxyOnly/ManagedTun source required'
    }
    # Re-observe the ONLY existing SYSTEM/Highest dispatcher before calling
    # the native one-shot owner. Never retarget an unrelated task.
    $dispatch = Get-ScheduledTask -TaskName 'EdgePlatformPrivilegedDispatch' -ErrorAction Stop
    # UserId is localized (e.g. 'СИСТЕМА' on Russian Windows).
    # Resolve to the immutable well-known LocalSystem SID; never trust a name.
    if ($null -eq $dispatch) {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: existing SYSTEM task missing'
    }
    $principalName = [string]$dispatch.Principal.UserId
    try {
        $principalSid = if ($principalName -ceq 'S-1-5-18') {
            'S-1-5-18'
        } else {
            ([System.Security.Principal.NTAccount]::new($principalName)).Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }
    } catch {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: task principal SID cannot be resolved'
    }
    if ($principalSid -cne 'S-1-5-18' -or
        [string]$dispatch.State -cne 'Ready' -or
        [string]$dispatch.Principal.RunLevel -cne 'Highest' -or
        [string]$dispatch.Principal.LogonType -cne 'ServiceAccount' -or
        @($dispatch.Actions).Count -ne 1 -or
        [string]@($dispatch.Actions)[0].Execute.Trim('"') -cne [string]$old['console_path'] -or
        [string]@($dispatch.Actions)[0].Arguments -notmatch '^privileged-dispatch --install-root "?C:\\sing-box"?$') {
        throw 'OFFLINE_BOOTSTRAP_BLOCKED: old exact SYSTEM task not proven'
    }
    Write-Output 'offline_bootstrap_task=EXACT_SYSTEM_OWNER'
    Write-Output 'offline_bootstrap_candidate=VERIFIED_STAGE_ONLY'
    Write-Output "offline_bootstrap_console=$console"
    if ($BootstrapNow) {
        $bootstrapArgs = @("offline-bootstrap", $AcceptedRevision, $ReleaseSetSha256, "--install-root", $InstallRoot)
        if ($EnrollReceipt) { $bootstrapArgs += "--enroll-receipt" }
        if ($hasRetained) {
            $bootstrapArgs += @(
                "--retained-intent-sha256", $RetainedIntentSha256,
                "--expected-current-release-set-sha256", $ExpectedCurrentReleaseSetSha256
            )
        }
        & $console @bootstrapArgs
        if ($LASTEXITCODE -ne 0) { throw 'OFFLINE_BOOTSTRAP_UNKNOWN: native result uncertain, DO NOT REPLAY' }
        Write-Output 'offline_bootstrap=RETURNED_FROM_NATIVE_OWNER'
        if ($EnrollReceipt) {
            Write-Output 'w4_receipt_identity=LOCAL_ADMIN_REQUEST_DURABLE'
            Write-Output 'w4_next=EXISTING_SYSTEM_TASK_ONLY'
        }
        exit 0
    }
    Write-Output 'windows_service_mutations=0'
    Write-Output 'windows_authority_mutations=0'
    exit 0
}

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

Assert-OfflineWindow

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
