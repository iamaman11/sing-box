# Shared same-run and aborted-run Windows first-use cleanup.
# This is an isolated filesystem-only owner: no SCM, DNS, TUN, credentials,
# controller or foreign CloudflareWARP mutations. Never retry an unknown delete.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[1-9][0-9]{7,18}$')]
  [string]$SourceRunId,

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-f]{64}$')]
  [string]$ReleaseSetSha256,

  [switch]$RemoveOwned,

  # Only a GH-verified failed first-use materialization may authorize this.
  # An absent sentinel is recoverable solely when the isolated root is empty.
  [switch]$RecoverEmptyPreMarker
)

$ErrorActionPreference = 'Stop'
$root = 'C:\sing-box-acceptance'
$serving = 'C:\sing-box'
if ([IO.Path]::GetFullPath($root).TrimEnd('\') -cne $root -or
    [IO.Path]::GetFullPath($serving).TrimEnd('\') -cne $serving -or
    $root.StartsWith($serving + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'FIRST_USE_SCOPE_INVALID: expected isolated Windows root'
}
if (-not (Test-Path -LiteralPath $root)) {
  Write-Host 'WINDOWS_FIRST_USE_ROOT=ABSENT'
  Write-Host 'WINDOWS_ISOLATED_CLEANUP=ALREADY_ABSENT'
  Write-Host 'WINDOWS_SERVING_INSTALL_ROOT=UNTOUCHED'
  return
}
$item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
if (-not $item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'FIRST_USE_SCOPE_UNKNOWN: non-directory or reparse root'
}
$sentinel = Join-Path $root '.first-use-run'
$preMarkerEmpty = $false
if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
  if (-not $RecoverEmptyPreMarker -or -not $RemoveOwned) {
    throw 'FIRST_USE_SCOPE_UNKNOWN: durable owner marker missing'
  }
  # No ownership can be inferred from directory name alone. The caller must
  # independently authorize the exact failed GitHub run and materialize step.
  # Before deletion, prove an empty, non-reparse directory owned by the
  # current runner identity, SYSTEM, or the built-in Administrators SID.
  $entries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
  if ($entries.Count -ne 0) {
    throw 'FIRST_USE_PREMARKER_UNKNOWN: unmarked directory is not empty'
  }
  $ownerSid = (Get-Acl -LiteralPath $root -ErrorAction Stop).GetOwner(
    [Security.Principal.SecurityIdentifier]).Value
  $runnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($ownerSid -notin @($runnerSid, 'S-1-5-18', 'S-1-5-32-544')) {
    throw 'FIRST_USE_PREMARKER_UNKNOWN: unmarked directory owner is foreign'
  }
  $preMarkerEmpty = $true
} else {
  $markerItem = Get-Item -LiteralPath $sentinel -Force
  if ($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'FIRST_USE_SCOPE_UNKNOWN: marker is a reparse point'
  }
  $actual = [IO.File]::ReadAllText($sentinel)
  $expected = "$SourceRunId|$ReleaseSetSha256"
  if ($actual -cne $expected) {
    throw 'FIRST_USE_SCOPE_UNKNOWN: run/ReleaseSet identity mismatch'
  }
}
if (@(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop |
    Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -ne 0) {
  throw 'FIRST_USE_SCOPE_UNKNOWN: nested link to potentially foreign files'
}
# Read-only serving-owner guard. Acceptance never starts the main service or TUN.
$svc = Get-Service -Name EdgePlatformController -ErrorAction Stop
if ($svc.Status -ne 'Stopped') {
  throw 'FIRST_USE_SERVING_OWNER_CHANGED: EdgePlatformController is not stopped'
}
if (Get-NetAdapter -Name 'sing-box-tun' -ErrorAction SilentlyContinue) {
  throw 'FIRST_USE_SERVING_OWNER_CHANGED: managed TUN present'
}
$singBoxProcesses = @(Get-CimInstance Win32_Process -Filter "name='sing-box.exe'" -ErrorAction Stop)
if ($singBoxProcesses.Count -ne 0) {
  throw 'FIRST_USE_RUNTIME_BUSY: sing-box process still running'
}
if ($preMarkerEmpty) {
  Write-Host 'WINDOWS_FIRST_USE_ROOT=EXACT_EMPTY_PREMARKER'
  Write-Host "WINDOWS_FIRST_USE_SOURCE_RUN=$SourceRunId"
  Write-Host "WINDOWS_FIRST_USE_RELEASE=$ReleaseSetSha256"
  Write-Host 'WINDOWS_SERVING_OWNER=STOPPED_NO_TUN'
  # .NET nonrecursive delete fails if anything appears in the directory,
  # rather than risking removal of a newly created foreign file.
  [IO.Directory]::Delete($root, $false)
  if (Test-Path -LiteralPath $root) {
    throw 'FIRST_USE_PREMARKER_REMOVE_UNKNOWN: root still exists; no retry'
  }
  Write-Host 'WINDOWS_ISOLATED_EMPTY_PREMARKER_CLEANUP=PASS'
  Write-Host 'WINDOWS_SERVING_INSTALL_ROOT=UNTOUCHED'
  Write-Host 'WINDOWS_SCM_MUTATIONS=0'
  Write-Host 'WINDOWS_TUN_MUTATIONS=0'
  Write-Host 'WINDOWS_DNS_MUTATIONS=0'
  Write-Host 'WINDOWS_CREDENTIAL_MUTATIONS=0'
  return
}
Write-Host 'WINDOWS_FIRST_USE_ROOT=EXACT_OWNED'
Write-Host "WINDOWS_FIRST_USE_SOURCE_RUN=$SourceRunId"
Write-Host "WINDOWS_FIRST_USE_RELEASE=$ReleaseSetSha256"
Write-Host 'WINDOWS_SERVING_OWNER=STOPPED_NO_TUN'
if (-not $RemoveOwned) {
  Write-Host 'WINDOWS_ISOLATED_CLEANUP=READ_ONLY_RECONCILED'
  return
}
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
if (Test-Path -LiteralPath $root) {
  throw 'FIRST_USE_REMOVE_UNKNOWN: root still exists, no implicit retry'
}
Write-Host 'WINDOWS_ISOLATED_OWNED_CLEANUP=PASS'
Write-Host 'WINDOWS_SERVING_INSTALL_ROOT=UNTOUCHED'
Write-Host 'WINDOWS_SCM_MUTATIONS=0'
Write-Host 'WINDOWS_TUN_MUTATIONS=0'
Write-Host 'WINDOWS_DNS_MUTATIONS=0'
Write-Host 'WINDOWS_CREDENTIAL_MUTATIONS=0'
