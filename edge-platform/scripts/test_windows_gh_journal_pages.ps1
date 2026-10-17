# Exercise the one actual Windows production journal reader with negative fixtures.
# Never call any credential or release mutation; only its two GH GET methods.
[CmdletBinding()]
param([switch]$Live)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$reader = Join-Path $PSScriptRoot 'read-complete-gh-journal.ps1'
if (-not (Test-Path -LiteralPath $reader -PathType Leaf)) {
    throw 'Missing canonical read-only journal reader'
}
function Read-DurableJournal { & $reader }
$names = @('Read-DurableJournal')
$repository = 'iamaman11/sing-box'
if ($Live -and $env:GITHUB_REPOSITORY -and $env:GITHUB_REPOSITORY -cne $repository) {
    throw 'Live journal test is canonical-repository-only'
}
$oldRepository = $env:GITHUB_REPOSITORY
$env:GITHUB_REPOSITORY = $repository
$url = "repos/$repository/issues/26/comments?per_page=100"
$metadataUrl = "repos/$repository/issues/26"
$liveRaw = $null; $liveMetadata = $null
try {
    if ($Live) {
        $nativeGh = (Get-Command gh -CommandType Application -ErrorAction Stop).Source
        # Exactly one paginated fetch, no --jq and no POST. Never print bodies.
        $liveRaw = (& $nativeGh api --paginate --slurp $url) -join "`n"
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($liveRaw)) {
            throw 'Live gh paginated read failed'
        }
        $liveMetadata = (& $nativeGh api $metadataUrl) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'Live journal count read failed' }
    }
    # The production reader runs unchanged. Only its transport is replaced
    # with the already fetched response or a negative fixture, avoiding re-fetch.
    function gh {
        param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
        $global:LASTEXITCODE = $global:FixtureExit
        if (($Arguments -join ' ') -ceq "api --paginate --slurp $url") {
            return $global:FixtureRaw
        }
        if (($Arguments -join ' ') -ceq "api $metadataUrl") {
            return $global:FixtureMetadata
        }
        throw 'Unexpected gh operation in production read-only reader'
    }
    $global:FixtureExit = 0
    $global:FixtureRaw = '[[{"id":1,"body":"first"}],[{"id":2,"body":"second"}]]'
    $global:FixtureMetadata = '{"comments":2}'
    foreach ($name in $names) {
        $entries = @(& $name)
        if ($entries.Count -ne 2 -or $entries[0].id -ne 1 -or $entries[1].id -ne 2) {
            throw "Page boundary/order regression: $name"
        }
    }
    $negative = @(
        '', 'not-json', '{}', '[]', '[[]]', '[{}]', '[[null]]',
        '[[{"id":1}]]', '[[{"body":"missing-id"}]]',
        '[[{"id":1,"body":"first"}],{}]',
        '[[{"id":1,"body":"first"}]]', # valid but missing a complete page
        '[[{"id":1,"body":"first"}],[', # truncated transport JSON
        '[{"id":1,"body":"flattened-not-pages"}]'
    )
    $rejected = 0
    foreach ($fixture in $negative) {
        $global:FixtureRaw = $fixture
        foreach ($name in $names) {
            $failed = $false
            try { $null = @(& $name) } catch { $failed = $true }
            if (-not $failed) { throw "Reader accepted incomplete/malformed fixture: $name" }
            $rejected++
        }
    }
    $global:FixtureRaw = '[[{"id":1,"body":"first"}],[{"id":2,"body":"second"}]]'
    foreach ($badMetadata in @('', 'not-json', '{}', '{"comments":3}')) {
        $global:FixtureMetadata = $badMetadata
        foreach ($name in $names) {
            $failed = $false
            try { $null = @(& $name) } catch { $failed = $true }
            if (-not $failed) { throw "Reader accepted missing/count-mismatched authority: $name" }
            $rejected++
        }
    }
    $global:FixtureMetadata = '{"comments":2}'
    $global:FixtureExit = 1
    foreach ($name in $names) {
        $failed = $false
        try { $null = @(& $name) } catch { $failed = $true }
        if (-not $failed) { throw "Reader accepted failed gh exit: $name" }
        $rejected++
    }
    "journal_negative_cases_rejected=$rejected"
    if ($Live) {
        $global:FixtureExit = 0
        $global:FixtureRaw = $liveRaw
        $global:FixtureMetadata = $liveMetadata
        $pages = ConvertFrom-Json -InputObject $liveRaw -NoEnumerate
        $metadata = ConvertFrom-Json -InputObject $liveMetadata
        $first = @(Read-DurableJournal)
        if ($first.Count -ne [long]$metadata.comments) {
            throw 'Production reader disagrees with authoritative issue count'
        }
        if (@($first | Group-Object id | Where-Object Count -ne 1).Count -ne 0) {
            throw 'Journal has duplicate comment IDs'
        }
        $intents = @($first | Where-Object { [string]$_.body -like '*<!-- sing-box-windows-active-release-apply/v1 -->*' })
        'journal_integration=PASS'
        'journal_transport=gh_api_paginate_slurp_unfiltered'
        "journal_page_count=$($pages.Count)"
        "journal_entry_count=$($first.Count)"
        "journal_api_comment_count=$($metadata.comments)"
        'journal_all_entries_id_body=PASS'
        "journal_active_apply_intent_count=$($intents.Count)"
    }
    'journal_production_reader_tests=PASS'
} finally {
    $env:GITHUB_REPOSITORY = $oldRepository
}
