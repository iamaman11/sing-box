# Shared strictly read-only Issue #26 journal reader for Windows lifecycle.
# The physical mutation owner never treats failed reads as empty history.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_REPOSITORY -cne 'iamaman11/sing-box') {
  throw 'JOURNAL_READ_BLOCKED: wrong canonical repository'
}
$url = "repos/$env:GITHUB_REPOSITORY/issues/26/comments?per_page=100"
$raw = (& gh api --paginate --slurp $url) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
  throw 'JOURNAL_READ_BLOCKED: complete GitHub journal unavailable'
}
$pages = ConvertFrom-Json -InputObject $raw -NoEnumerate
if ($pages -isnot [array]) {
  throw 'JOURNAL_READ_BLOCKED: malformed paginated journal'
}
$entries = [Collections.Generic.List[object]]::new()
foreach ($page in $pages) {
  if ($page -isnot [array]) {
    throw 'JOURNAL_READ_BLOCKED: malformed journal page'
  }
  foreach ($entry in $page) {
    if ($null -eq $entry -or $null -eq $entry.id -or $null -eq $entry.body) {
      throw 'JOURNAL_READ_BLOCKED: incomplete journal entry'
    }
    [void]$entries.Add($entry)
  }
}
if ($entries.Count -eq 0) {
  throw 'JOURNAL_READ_BLOCKED: empty or incomplete durable journal'
}
$issueRaw = (& gh api "repos/$env:GITHUB_REPOSITORY/issues/26") -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($issueRaw)) {
  throw 'JOURNAL_READ_BLOCKED: GitHub issue count unavailable'
}
$issue = ConvertFrom-Json -InputObject $issueRaw
if ($null -eq $issue -or [string]$issue.comments -notmatch '^[0-9]+$' -or
    [long]$issue.comments -ne $entries.Count) {
  throw 'JOURNAL_READ_BLOCKED: incomplete or concurrently modified journal'
}
$entries.ToArray()
