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
        bootstrap = [bool]$BootstrapNow
        enroll = [bool]$EnrollReceipt
        old = $RetainedIntentSha256
        installed = $ExpectedCurrentReleaseSetSha256
        archive_id = $ArchivedAcceptanceSourceRunId
    }
}
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
        $actual.root -cne $InstallRoot -or -not $actual.offline -or $actual.archive_id -ne 0) {
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
Write-Output 'windows_connect_powershell_named_binding=PASS'

Write-Output 'windows_installer_offline_direct_github_transport=PASS'
Write-Output 'windows_installer_missing_response=PASS'
Write-Output 'windows_installer_http_status_classification=PASS'
Write-Output 'windows_installer_original_transport_error=PASS'
Write-Output 'windows_installer_no_network_mutation=PASS'
