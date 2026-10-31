# Tests canonical installer network error handling WITHOUT running its installer.
# The only executable code imported is the four selected function ASTs.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'install-windows-release.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $installer, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) { throw 'Canonical installer has PowerShell parse errors' }

$functionNames = @(
    'Test-TransientGitHubReadFailure',
    'Get-ConnectWindowsGitHubHttpCode',
    'Resolve-ConnectWindowsGitHubToken',
    'Assert-ConnectWindowsGitHubBudget',
    'Invoke-AuthenticatedNativeBootstrap',
    'Get-GitHubHeaders',
    'Get-GitHubTransportOptions',
    'Invoke-GitHubJsonGet',
    'Invoke-GitHubAssetGet'
)
$functions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true))
foreach ($name in $functionNames) {
    $found = @($functions | Where-Object { $_.Name -ceq $name })
    if ($found.Count -ne 1) { throw "Missing or duplicate installer function: $name" }
    . ([ScriptBlock]::Create($found[0].Extent.Text))
}

function New-ProbeError {
    param([System.Exception]$Exception)
    return [System.Management.Automation.ErrorRecord]::new(
        $Exception, 'installer-http-error-test',
        [System.Management.Automation.ErrorCategory]::ConnectionError, $null
    )
}

# Windows PowerShell 7's IOException/HttpRequestException often lack Response.
$transport = [System.IO.IOException]::new('ORIGINAL_TRANSPORT_CONNECTION_RESET')
$noResponse = New-ProbeError -Exception $transport
if (-not (Test-TransientGitHubReadFailure -ErrorRecord $noResponse)) {
    throw 'Missing Response must use the existing bounded transient-read path'
}
if ($noResponse.Exception.Message -cne 'ORIGINAL_TRANSPORT_CONNECTION_RESET') {
    throw 'Original transport exception was replaced'
}
$httpUnavailable = [System.Exception]::new('NO_HTTP_RESPONSE')
$httpUnavailable | Add-Member -NotePropertyName Response -NotePropertyValue $null
if (-not (Test-TransientGitHubReadFailure -ErrorRecord (New-ProbeError -Exception $httpUnavailable))) {
    throw 'Null HTTP Response must use the bounded transient-read path'
}

foreach ($case in @(
    @{ Status = 503; Expected = $true },
    @{ Status = 429; Expected = $true },
    @{ Status = 408; Expected = $true },
    @{ Status = 403; Expected = $false },
    @{ Status = 404; Expected = $false }
)) {
    $httpError = [System.Exception]::new("HTTP_$($case.Status)")
    $httpError | Add-Member -NotePropertyName Response -NotePropertyValue (
        [pscustomobject]@{ StatusCode = [int]$case.Status }
    )
    $actual = Test-TransientGitHubReadFailure -ErrorRecord (New-ProbeError -Exception $httpError)
    if ([bool]$actual -ne [bool]$case.Expected) {
        throw "HTTP $($case.Status) transient classification mismatch"
    }
}

# A response-less GET failure must preserve the actual transport exception
# after the existing bounded attempt is exhausted, not throw a property error.
$GitHubReadAttempts = 1
$GitHubReadTimeoutSec = 1
$GitHubAssetTimeoutSec = 1
$GitHubRetryDelaySec = 0
$GitHubToken = ''
$Offline = $false
$global:SingBoxConnectReadCache = $null
$script:metadataCalls = 0
$script:assetCalls = 0
$script:metadataNoProxy = $null
$script:assetNoProxy = $null
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec, [switch]$NoProxy)
    $script:metadataCalls++
    $script:metadataNoProxy = [bool]$NoProxy
    throw [System.IO.IOException]::new('ORIGINAL_METADATA_CONNECTION_RESET')
}
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, $Method, $Uri, $Headers, $OutFile, $TimeoutSec, [switch]$NoProxy)
    $script:assetCalls++
    $script:assetNoProxy = [bool]$NoProxy
    throw [System.IO.IOException]::new('ORIGINAL_ASSET_CONNECTION_RESET')
}
$metadataResult = 'NOT_THROWN'
try {
    $null = Invoke-GitHubJsonGet -Uri 'https://api.github.com/example-negative-test'
} catch {
    $metadataResult = $_.Exception.Message
}
if ($metadataResult -cne 'ORIGINAL_METADATA_CONNECTION_RESET' -or $script:metadataCalls -ne 1) {
    throw "Original metadata transport failure was masked: $metadataResult"
}
$assetResult = 'NOT_THROWN'
$assetPath = Join-Path ([System.IO.Path]::GetTempPath()) 'singbox-negative-test-nonexistent-asset'
try {
    Invoke-GitHubAssetGet -Uri 'https://api.github.com/asset-negative-test' -Destination $assetPath
} catch {
    $assetResult = $_.Exception.Message
}
if ($assetResult -cne 'ORIGINAL_ASSET_CONNECTION_RESET' -or $script:assetCalls -ne 1) {
    throw "Original asset transport failure was masked: $assetResult"
}
if ($script:metadataNoProxy -or $script:assetNoProxy) {
    throw 'Normal installer unexpectedly bypassed configured proxy'
}
# Simulate the real blocked host: ambient proxy must not control offline
# GitHub metadata or asset downloads; no actual network is performed.
$Offline = $true
$oldHttpProxy = $env:HTTP_PROXY
$oldHttpsProxy = $env:HTTPS_PROXY
try {
    $env:HTTP_PROXY = 'http://unavailable-proxy.example:4128'
    $env:HTTPS_PROXY = 'http://unavailable-proxy.example:4128'
    foreach ($case in @(
        @{ Uri = 'https://api.github.com/repos/iamaman11/sing-box/branches/main'; Operation = 'metadata' },
        @{ Uri = 'https://api.github.com/repos/iamaman11/sing-box/releases/assets/12345'; Operation = 'asset' }
    )) {
        try {
            if ($case.Operation -eq 'metadata') {
                $null = Invoke-GitHubJsonGet -Uri $case.Uri
            } else {
                Invoke-GitHubAssetGet -Uri $case.Uri -Destination $assetPath
            }
        } catch {
            if ($_.Exception.Message -notlike 'ORIGINAL_*_CONNECTION_RESET') { throw }
        }
    }
    if (-not $script:metadataNoProxy -or -not $script:assetNoProxy) {
        throw 'Offline GitHub metadata and asset calls must both enforce -NoProxy'
    }
    foreach ($url in @('http://api.github.com/unsafe', 'https://other.example/file', 'https://api.github.com:444/unsafe')) {
        $denied = $false
        try { $null = Get-GitHubTransportOptions -Uri $url } catch { $denied = $true }
        if (-not $denied) { throw "Offline GitHub transport permitted $url" }
    }
} finally {
    $env:HTTP_PROXY = $oldHttpProxy
    $env:HTTPS_PROXY = $oldHttpsProxy
}
# Exercise actual ConnectWindows argument constructors from the canonical
# installer AST, never the installer itself. No host/network side effects.
$source = Get-Content -LiteralPath $installer -Raw
$probe = {
    param(
        [string]$AcceptedRevision,
        [string]$ReleaseSetSha256,
        [string]$InstallRoot,
        [switch]$Offline,
        [string]$GitHubToken,
        [switch]$BootstrapNow,
        [switch]$EnrollReceipt,
        [string]$RetainedIntentSha256,
        [string]$ExpectedCurrentReleaseSetSha256,
        [UInt64]$ArchivedAcceptanceSourceRunId = 0
    )
    [pscustomobject]@{
        revision = $AcceptedRevision
        digest = $ReleaseSetSha256
        root = $InstallRoot
        offline = [bool]$Offline
        auth = $GitHubToken
        bootstrap = [bool]$BootstrapNow
        enroll = [bool]$EnrollReceipt
        old = $RetainedIntentSha256
        installed = $ExpectedCurrentReleaseSetSha256
        archive_id = $ArchivedAcceptanceSourceRunId
    }
}
$GitHubToken = 'github_pat_' + ('A' * 44)
$branch = [pscustomobject]@{ commit = [pscustomobject]@{ sha = ('a' * 40) } }
$selectedDigest = 'b' * 64
$InstallRoot = 'C:\sing-box'
$installed = @{ release_set_sha256 = 'c' * 64 }
$oldDigest = 'd' * 64
foreach ($kind in @('argsInitial', 'argsExact')) {
    $all = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq ('$' + $kind) -and
        $node.Operator -eq [System.Management.Automation.Language.TokenKind]::Equals
    }, $true))
    if ($all.Count -ne 1) { throw "Expected ONE $kind constructor" }
    $expression = $all[0].Right.Extent.Text
    if (-not $expression.TrimStart().StartsWith('@{')) {
        throw "$kind must use named hashtable splatting, never string arrays"
    }
    # Evaluate only the hashtable expression from the real installer.
    $bound = & ([ScriptBlock]::Create($expression))
    if ($bound -isnot [hashtable]) { throw "$kind constructor not a hashtable" }
    if ($kind -eq 'argsExact') {
        if ($source -cnotmatch [regex]::Escape('$argsExact[' + "'RetainedIntentSha256']") -or
            $source -cnotmatch [regex]::Escape('$argsExact[' + "'ExpectedCurrentReleaseSetSha256']")) {
            throw 'Canonical retained-BEGIN keys missing'
        }
        $bound['RetainedIntentSha256'] = $oldDigest
        $bound['ExpectedCurrentReleaseSetSha256'] = [string]$installed['release_set_sha256']
    }
    $actual = & $probe @bound
    if ($actual.revision -cne $branch.commit.sha -or $actual.digest -cne $selectedDigest -or
        $actual.root -cne $InstallRoot -or -not $actual.offline -or
        $actual.auth -cne $GitHubToken -or $actual.archive_id -ne 0) {
        throw "$kind PowerShell named binding mismatch"
    }
    if ($kind -eq 'argsExact') {
        if (-not $actual.bootstrap -or -not $actual.enroll -or
            $actual.old -cne $oldDigest -or
            $actual.installed -cne $installed['release_set_sha256']) {
            throw 'Retained BEGIN bound to wrong named parameter'
        }
    } elseif ($actual.bootstrap -or $actual.enroll -or $actual.old -or $actual.installed) {
        throw 'Initial install must not receive bootstrap/supersession flags'
    }
}
if ($source -cnotmatch [regex]::Escape('& $PSCommandPath @argsInitial') -or
    $source -cnotmatch [regex]::Escape('& $PSCommandPath @argsExact')) {
    throw 'Canonical installer is not invoking the verified named argument maps'
}
# Regression: -cnotmatch populates the automatic $Matches hash when the
# digest regex matches. The old variable name $matches was overwritten, and
# the next .digest access raised PropertyNotFoundException on a string.
function Invoke-LegacyPublishedDigestCollision {
    $matches = @([pscustomobject]@{ digest = ('sha256:' + ('a' * 64)) })
    if ([string]$matches[0].digest -cnotmatch '^sha256:[0-9a-f]{64}$') {
        throw 'Expected valid legacy digest'
    }
    return $matches[0].digest
}
$oldFailure = 'NO_ERROR'
try { $null = Invoke-LegacyPublishedDigestCollision } catch { $oldFailure = $_.Exception.Message }
if ($oldFailure -notmatch "digest") {
    throw "Pre-fix PowerShell automatic Matches collision not reproduced: $oldFailure"
}

# Import only the canonical pure metadata helper, never execute installer top-level.
$digestFns = @($functions | Where-Object { $_.Name -ceq 'Get-RequiredPublishedAssetSha256' })
$oldVerifiers = @($functions | Where-Object { $_.Name -ceq 'Assert-ExistingNativeReleaseFromProtectedGit' })
if ($digestFns.Count -ne 1 -or $oldVerifiers.Count -ne 1) {
    throw 'Canonical published asset digest helper or old EXE verifier not unique'
}
. ([ScriptBlock]::Create($digestFns[0].Extent.Text))
$oldVerifierText = $oldVerifiers[0].Extent.Text
if ($oldVerifierText -cnotmatch 'Get-RequiredPublishedAssetSha256 -Release' -or
    $oldVerifierText -match '\$matches\b' -or
    $oldVerifierText -cnotmatch '\(Get-ExactHash -Path \$file\) -cne \$publishedDigest') {
    throw 'Old published EXE must compare actual bytes to exact digest, without automatic Matches collision'
}
$goodAssets = [pscustomobject]@{ assets = @(
    [pscustomobject]@{ name = 'edge-platform-windows.zip'; digest = ('sha256:' + ('a' * 64)) },
    [pscustomobject]@{ name = 'release-set.pb'; digest = ('sha256:' + ('b' * 64)) }
) }
foreach ($entry in @(
    @{ name = 'edge-platform-windows.zip'; expected = ('a' * 64) },
    @{ name = 'release-set.pb'; expected = ('b' * 64) }
)) {
    $actual = Get-RequiredPublishedAssetSha256 -Release $goodAssets -Name $entry.name
    if ($actual -cne $entry.expected) { throw "Valid published digest mismatch: $($entry.name)" }
}

# Missing, malformed, duplicate or absent immutable metadata always fails closed
# with an owner-specific error (never raw 'property digest not found').
$negativeAssets = @(
    @{ release = [pscustomobject]@{ assets = @([pscustomobject]@{ name = 'release-set.pb' }) }; reason = 'WINDOWS_INSTALL_OLD_RELEASE_PUBLISHED_DIGEST_UNAVAILABLE' },
    @{ release = [pscustomobject]@{ assets = @([pscustomobject]@{ name = 'release-set.pb'; digest = 'sha256:bad' }) }; reason = 'WINDOWS_INSTALL_OLD_RELEASE_PUBLISHED_DIGEST_UNAVAILABLE' },
    @{ release = [pscustomobject]@{ assets = @([pscustomobject]@{ name = 'release-set.pb'; digest = ('sha256:' + ('A' * 64)) }) }; reason = 'WINDOWS_INSTALL_OLD_RELEASE_PUBLISHED_DIGEST_UNAVAILABLE' },
    @{ release = [pscustomobject]@{ assets = @(
        [pscustomobject]@{ name = 'release-set.pb'; digest = ('sha256:' + ('a' * 64)) },
        [pscustomobject]@{ name = 'release-set.pb'; digest = ('sha256:' + ('b' * 64)) }
    ) }; reason = 'WINDOWS_INSTALL_OLD_RELEASE_ASSET_NOT_UNIQUE' },
    @{ release = [pscustomobject]@{ assets = @() }; reason = 'WINDOWS_INSTALL_OLD_RELEASE_ASSET_NOT_UNIQUE' }
)
foreach ($case in $negativeAssets) {
    $caught = 'NO_ERROR'
    try {
        $null = Get-RequiredPublishedAssetSha256 -Release $case.release -Name 'release-set.pb'
    } catch {
        $caught = $_.Exception.Message
    }
    if (-not $caught.StartsWith($case.reason, [StringComparison]::Ordinal)) {
        throw "Expected $($case.reason), got $caught"
    }
}
Write-Output 'windows_installer_published_digest_matches_collision=PASS'
Write-Output 'windows_installer_published_digest_missing_and_malformed_fail_closed=PASS'

# Import ONLY the pure disabled-successor predicate from the canonical
# installer AST. No staging, SCM, SYSTEM task or network effect is executed.
$successorFunctions = @($functions | Where-Object {
    $_.Name -ceq 'Assert-DisabledOfflineSuccessorIdentity'
})
if ($successorFunctions.Count -ne 1) { throw 'Canonical disabled successor predicate missing' }
. ([ScriptBlock]::Create($successorFunctions[0].Extent.Text))
$oldFrom = 'a' * 64
$oldTo = 'b' * 64
$oldRevision = 'c' * 40
$newTarget = 'e' * 64
$newRevision = 'd' * 40
$successorArgs = @{
    RetainedFrom = $oldFrom
    RetainedTo = $oldTo
    RetainedRevision = $oldRevision
    InstalledRelease = $oldTo
    NextRelease = $newTarget
    NextRevision = $newRevision
}
# Both legitimate physical states: old source still installed, or retained to
# already installed. Neither claims historical terminal success.
foreach ($installedCase in @($oldFrom, $oldTo)) {
    $successorArgs.InstalledRelease = $installedCase
    Assert-DisabledOfflineSuccessorIdentity @successorArgs
}
$negativeSuccessorCases = @(
    @{ InstalledRelease = ('f' * 64) },
    @{ InstalledRelease = $oldFrom; NextRelease = $oldFrom },
    @{ InstalledRelease = $oldFrom; NextRelease = $oldTo },
    @{ InstalledRelease = $oldTo; NextRelease = $oldFrom },
    @{ InstalledRelease = $oldTo; NextRelease = $oldTo },
    @{ InstalledRelease = $oldTo; NextRevision = $oldRevision },
    @{ RetainedFrom = $oldTo; InstalledRelease = $oldTo }
)
foreach ($case in $negativeSuccessorCases) {
    $bound = $successorArgs.Clone()
    foreach ($key in $case.Keys) { $bound[$key] = $case[$key] }
    $observed = 'NO_ERROR'
    try { Assert-DisabledOfflineSuccessorIdentity @bound } catch {
        $observed = $_.Exception.Message
    }
    if ($observed -cne 'OFFLINE_BOOTSTRAP_DISABLED_PREDECESSOR_NOT_DISTINCT_NO_REPLAY') {
        throw "Retained disabled successor negative case was admitted: $observed"
    }
}
# The production disabled-task path MUST invoke the same tested predicate.
$nativeGate = @($functions | Where-Object {
    $_.Name -ceq 'Assert-DisabledOfflineSuccessorIdentity'
})
if ($source -cnotmatch [regex]::Escape('Assert-DisabledOfflineSuccessorIdentity `') -or
    $nativeGate.Count -ne 1) {
    throw 'Disabled-task canonical installed-to predicate not wired into installer'
}
Write-Output 'windows_installer_retained_begin_installed_to_successor=PASS'
Write-Output 'windows_installer_retained_begin_distinct_negative_matrix=PASS'


# ConnectWindows must authenticate before any native BEGIN. These tests use
# only imported function ASTs and mocked web calls (NO network or host effect).
if ((Resolve-ConnectWindowsGitHubToken -Supplied $GitHubToken) -cne $GitHubToken) {
    throw 'Explicit ConnectWindows token not passed through unchanged'
}
$invalidToken = 'NOT_REJECTED'
try { $null = Resolve-ConnectWindowsGitHubToken -Supplied 'bad' }
catch { $invalidToken = $_.Exception.Message }
if ($invalidToken -cne 'WINDOWS_CONNECT_GITHUB_AUTH_INVALID') {
    throw "Invalid GitHub token was admitted: $invalidToken"
}
$global:SingBoxConnectReadCache = @{}
$GitHubReadAttempts = 1
$script:metadataCalls = 0
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec, [switch]$NoProxy)
    $script:metadataCalls++
    if ($Headers['Authorization'] -cne "Bearer $GitHubToken") {
        throw 'INSTALLER_AUTH_HEADER_MISSING'
    }
    if ($Uri -ceq 'https://api.github.com/rate_limit') {
        return [pscustomobject]@{
            resources = [pscustomobject]@{ core = [pscustomobject]@{ remaining = 250 } }
        }
    }
    return [pscustomobject]@{ sha = 'a' * 40 }
}
Assert-ConnectWindowsGitHubBudget
$uri = 'https://api.github.com/repos/iamaman11/sing-box/branches/main'
$first = Invoke-GitHubJsonGet -Uri $uri
$second = Invoke-GitHubJsonGet -Uri $uri
if ($script:metadataCalls -ne 2 -or $first.sha -cne $second.sha) {
    throw 'Nested ConnectWindows repeatedly fetched the same GitHub metadata'
}
$global:SingBoxConnectReadCache = @{}
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec, [switch]$NoProxy)
    if ($Uri -ceq 'https://api.github.com/rate_limit') {
        return [pscustomobject]@{
            resources = [pscustomobject]@{ core = [pscustomobject]@{ remaining = 0 } }
        }
    }
    throw 'UNEXPECTED_NETWORK_CALL'
}
$rateError = 'NO_ERROR'
try { Assert-ConnectWindowsGitHubBudget } catch { $rateError = $_.Exception.Message }
if ($rateError -cne 'WINDOWS_CONNECT_GITHUB_RATE_LIMIT_EXCEEDED_BEFORE_BEGIN') {
    throw "Rate-limited GitHub budget was not rejected before BEGIN: $rateError"
}
foreach ($status in @(401,403,429)) {
    $exception = [System.Exception]::new("HTTP_$status")
    $exception | Add-Member -NotePropertyName Response -NotePropertyValue (
        [pscustomobject]@{ StatusCode = $status }
    )
    $code = Get-ConnectWindowsGitHubHttpCode -ErrorRecord (New-ProbeError -Exception $exception)
    $expected = switch ($status) {
        401 { 'WINDOWS_CONNECT_GITHUB_AUTH_REJECTED' }
        403 { 'WINDOWS_CONNECT_GITHUB_PERMISSION_DENIED' }
        429 { 'WINDOWS_CONNECT_GITHUB_RATE_LIMIT_EXCEEDED_BEFORE_BEGIN' }
    }
    if ($code -cne $expected) { throw "HTTP $status classified as $code, expected $expected" }
}
$rate403 = [System.Exception]::new('API rate limit exceeded')
$rate403 | Add-Member -NotePropertyName Response -NotePropertyValue (
    [pscustomobject]@{ StatusCode = 403 }
)
if ((Get-ConnectWindowsGitHubHttpCode -ErrorRecord (New-ProbeError -Exception $rate403)) -cne
    'WINDOWS_CONNECT_GITHUB_RATE_LIMIT_EXCEEDED_BEFORE_BEGIN') {
    throw 'GitHub HTTP 403 rate limit not classified'
}
if ((Get-ConnectWindowsGitHubHttpCode -ErrorRecord $noResponse) -ne '') {
    throw 'Response-less error must retain original diagnostic'
}
if ($source -cnotmatch [regex]::Escape('$global:SingBoxConnectReadCache = @{}') -or
    $source -cnotmatch [regex]::Escape('Assert-ConnectWindowsGitHubBudget') -or
    @($source -split [regex]::Escape('GitHubToken = $GitHubToken')).Count -ne 3) {
    throw 'ConnectWindows does not propagate authenticated context to both nested paths'
}
$global:SingBoxConnectReadCache = $null
Write-Output 'windows_connect_authenticated_snapshot=PASS'
Write-Output 'windows_connect_github_rate_and_auth_negative_matrix=PASS'


# Full missed process boundary: the native console starts a NEW pwsh process.
# Only synthetic credential values; no GitHub, SCM, key, journal or network.
$previousProcessToken = [Environment]::GetEnvironmentVariable('EDGE_GITHUB_TOKEN','Process')
try {
    [Environment]::SetEnvironmentVariable('EDGE_GITHUB_TOKEN', 'fixture-existing', 'Process')
    $fixtureToken = 'github_pat_' + ('Z' * 44)
    function Invoke-MockedNativeBootstrap {
        param([string]$Mode)
        if ($env:EDGE_GITHUB_TOKEN -cne $fixtureToken) {
            throw 'NATIVE_BOOTSTRAP_DID_NOT_INHERIT_AUTH'
        }
        $nested = @(& ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -NoProfile -NonInteractive -Command @'
if ($env:EDGE_GITHUB_TOKEN -cmatch '^github_pat_Z{44}

Write-Output 'windows_installer_offline_direct_github_transport=PASS'
Write-Output 'windows_installer_missing_response=PASS'
Write-Output 'windows_installer_http_status_classification=PASS'
Write-Output 'windows_installer_original_transport_error=PASS'
Write-Output 'windows_installer_no_network_mutation=PASS'
) {
    Write-Output 'NESTED_AUTH_PASS'
} else {
    exit 17
}
'@)
        if ($LASTEXITCODE -ne 0 -or $nested.Count -ne 1 -or
            [string]$nested[0] -cne 'NESTED_AUTH_PASS') {
            throw 'FRESH_PWSH_CHILD_DID_NOT_INHERIT_AUTH'
        }
        if ($Mode -ceq 'fail') { $global:LASTEXITCODE = 1 }
        else { $global:LASTEXITCODE = 0 }
    }
    Invoke-AuthenticatedNativeBootstrap -Console 'Invoke-MockedNativeBootstrap' -Arguments @('success') -GitHubAuthToken $fixtureToken
    if ($env:EDGE_GITHUB_TOKEN -cne 'fixture-existing') {
        throw 'AUTH_ENV_NOT_RESTORED_AFTER_NATIVE_SUCCESS'
    }
    $failure = 'NONE'
    try {
        Invoke-AuthenticatedNativeBootstrap -Console 'Invoke-MockedNativeBootstrap' -Arguments @('fail') -GitHubAuthToken $fixtureToken
    } catch {
        $failure = $_.Exception.Message
    }
    if ($failure -cne 'OFFLINE_BOOTSTRAP_UNKNOWN: native result uncertain, DO NOT REPLAY') {
        throw "NATIVE_EXIT_NOT_REJECTED: $failure"
    }
    if ($env:EDGE_GITHUB_TOKEN -cne 'fixture-existing') {
        throw 'AUTH_ENV_NOT_RESTORED_AFTER_NATIVE_FAILURE'
    }
    $invalid = 'NONE'
    try {
        Invoke-AuthenticatedNativeBootstrap -Console 'Invoke-MockedNativeBootstrap' -Arguments @('success') -GitHubAuthToken 'bad'
    } catch { $invalid = $_.Exception.Message }
    if ($invalid -cne 'OFFLINE_BOOTSTRAP_GITHUB_AUTH_REQUIRED_BEFORE_NATIVE_BEGIN' -or
        $env:EDGE_GITHUB_TOKEN -cne 'fixture-existing') {
        throw 'INVALID_NATIVE_GITHUB_AUTH_ADMITTED'
    }
    if ($source -cnotmatch [regex]::Escape('Invoke-AuthenticatedNativeBootstrap -Console $console -Arguments $bootstrapArgs -GitHubAuthToken $GitHubToken')) {
        throw 'NATIVE_AUTH_SCOPE_NOT_CONNECTED_TO_CANONICAL_INSTALLER'
    }
} finally {
    [Environment]::SetEnvironmentVariable('EDGE_GITHUB_TOKEN', $previousProcessToken, 'Process')
}
Write-Output 'windows_connect_native_child_authenticated_process_boundary=PASS'
Write-Output 'windows_connect_native_auth_restoration_success_failure_invalid=PASS'

Write-Output 'windows_connect_powershell_named_binding=PASS'

Write-Output 'windows_installer_offline_direct_github_transport=PASS'
Write-Output 'windows_installer_missing_response=PASS'
Write-Output 'windows_installer_http_status_classification=PASS'
Write-Output 'windows_installer_original_transport_error=PASS'
Write-Output 'windows_installer_no_network_mutation=PASS'
