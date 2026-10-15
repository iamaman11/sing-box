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
$script:metadataCalls = 0
$script:assetCalls = 0
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec)
    $script:metadataCalls++
    throw [System.IO.IOException]::new('ORIGINAL_METADATA_CONNECTION_RESET')
}
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, $Method, $Uri, $Headers, $OutFile, $TimeoutSec)
    $script:assetCalls++
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
Write-Output 'windows_installer_missing_response=PASS'
Write-Output 'windows_installer_http_status_classification=PASS'
Write-Output 'windows_installer_original_transport_error=PASS'
Write-Output 'windows_installer_no_network_mutation=PASS'
