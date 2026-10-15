# One SYSTEM-owned persistent first-use candidate: store only, never serve.
# Called exclusively by the canonical GitHub Windows lifecycle after reading
# the exact original immutable first-use BEGIN. No secret arrives in argv.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$Generation,
  [Parameter(Mandatory)][ValidateSet('A','B')][string]$Slot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\sing-box'
if ($env:GITHUB_RUN_ATTEMPT -cne '1' -or
    $env:GITHUB_REPOSITORY -cne 'iamaman11/sing-box' -or
    $env:GITHUB_REF -cne 'refs/heads/main' -or
    $env:EDGE_FIRST_USE_EXPECTED_MODE -cne 'ProxyOnly') {
  throw 'FIRST_USE_STAGE_BLOCKED: protected single-run ProxyOnly authority required'
}
$workspace = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
if ($workspace.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'FIRST_USE_STAGE_BLOCKED: GitHub runner workspace inside managed root'
}
function Observe-Owner {
  $current = Join-Path $root 'current.pb'
  $stable = Join-Path $root 'bin\edge-diagnostic.exe'
  if (-not (Test-Path -LiteralPath $stable -PathType Leaf)) {
    throw 'FIRST_USE_STAGE_BLOCKED: native installed diagnostic absent'
  }
  $output = @(& $stable doctor $current)
  $values = @{}
  foreach ($line in $output) {
    $parts = ([string]$line).Split('=',2)
    if ($parts.Count -eq 2) { $values[$parts[0]] = $parts[1] }
  }
  if ([string]$values['exact_release_files'] -cne 'PASS' -or
      [string]$values['release_set_sha256'] -notmatch '^[0-9a-f]{64}$' -or
      [string]$values['windows_datapath_mode'] -notin @('ManagedTun','ProxyOnly') -or
      [string]$values['scm_state'] -cne 'Stopped' -or
      [string]$values['managed_tun_present'] -cne 'false') {
    throw 'FIRST_USE_STAGE_BLOCKED: exact stopped release without TUN required'
  }
  foreach ($field in @('managed_singbox_process_count','orphan_singbox_process_count',
      'conflicting_singbox_process_count','unknown_singbox_process_count')) {
    if ([string]$values[$field] -cne '0') {
      throw 'FIRST_USE_STAGE_BLOCKED: managed or foreign sing-box process exists'
    }
  }
  $service = Get-CimInstance Win32_Service -Filter "Name='EdgePlatformController'" -ErrorAction Stop
  if ($null -eq $service -or [string]$service.State -cne 'Stopped') {
    throw 'FIRST_USE_STAGE_BLOCKED: SCM owner state changed'
  }
  return $values
}
function Read-SystemCursor([string]$console) {
  $output = @(& $console privileged-runtime-evidence --install-root $root)
  if ($LASTEXITCODE -ne 0) {
    throw 'FIRST_USE_STAGE_BLOCKED: existing SYSTEM read-only task unavailable'
  }
  $details = @($output | Where-Object { [string]$_ -like 'detail=*' })
  if ($details.Count -ne 1 -or
      [string]$details[0] -notmatch '^detail=runtime_evidence=BOUNDED_READ_ONLY;' -or
      [string]$details[0] -notmatch ';process_classification=ABSENT;process_evidence_complete=true;') {
    throw 'FIRST_USE_STAGE_BLOCKED: incomplete independent SYSTEM process evidence'
  }
  return [string]$details[0]
}
$before = Observe-Owner
$console = [string]$before['console_path']
$diagnostic = [string]$before['diagnostic_path']
if (-not (Test-Path -LiteralPath $console -PathType Leaf) -or
    -not (Test-Path -LiteralPath $diagnostic -PathType Leaf)) {
  throw 'FIRST_USE_STAGE_BLOCKED: immutable Windows binaries missing'
}
$independent = @(& $diagnostic doctor (Join-Path $root 'current.pb'))
$independentValues = @{}
foreach ($line in $independent) {
  $parts = ([string]$line).Split('=',2)
  if ($parts.Count -eq 2) { $independentValues[$parts[0]] = $parts[1] }
}
foreach ($field in @('release_set_sha256','windows_datapath_mode','scm_state',
    'managed_tun_present','managed_singbox_process_count','orphan_singbox_process_count',
    'conflicting_singbox_process_count','unknown_singbox_process_count')) {
  if ([string]$before[$field] -cne [string]$independentValues[$field]) {
    throw 'FIRST_USE_STAGE_BLOCKED: stable/immutable Windows owner drift'
  }
}
foreach ($dir in @('state','runtime','logs')) {
  $denied = $false
  try { [IO.Directory]::GetFileSystemEntries((Join-Path $root $dir)) | Out-Null }
  catch [UnauthorizedAccessException] { $denied = $true }
  if (-not $denied) {
    throw 'FIRST_USE_STAGE_BLOCKED: runner unexpectedly reads SYSTEM private state'
  }
}
$cursorBefore = Read-SystemCursor $console
if ($cursorBefore -notmatch ';credential_cursor=ABSENT(?:;|$)') {
  throw 'FIRST_USE_STAGE_BLOCKED: previous or incomplete candidate; no replay'
}
$second = Observe-Owner
if ([string]$before['release_set_sha256'] -cne [string]$second['release_set_sha256']) {
  throw 'FIRST_USE_STAGE_BLOCKED: Windows release changed during preflight'
}
# Existing privilege boundary fetches one exact Worker generation and creates
# the private cursor once. The GitHub runner never reads its payload or folder.
& $console privileged-stage-credential ([UInt64]$Generation) --install-root $root
if ($LASTEXITCODE -ne 0) {
  throw 'FIRST_USE_STAGE_UNKNOWN: stage outcome failed or uncertain, do not replay'
}
$expected = ';credential_cursor=VALID;credential_active_present=false;credential_candidate_present=true;credential_candidate_generation=' + $Generation + ';credential_previous_present=false'
if (-not (Read-SystemCursor $console).Contains($expected)) {
  throw 'FIRST_USE_STAGE_UNKNOWN: candidate readback incomplete, do not replay'
}
$after = Observe-Owner
if ([string]$after['release_set_sha256'] -cne [string]$before['release_set_sha256']) {
  throw 'FIRST_USE_STAGE_UNKNOWN: release changed, do not replay'
}
# Local native config validation only. No SCM/TUN, selector or network service.
& $console credential-transition validate-candidate --install-root $root
if ($LASTEXITCODE -ne 0) {
  throw 'FIRST_USE_STAGE_NOT_ACCEPTED: candidate stored, sing-box config invalid; never restage'
}
if (-not (Read-SystemCursor $console).Contains($expected)) {
  throw 'FIRST_USE_STAGE_UNKNOWN: candidate drifted after validation, do not replay'
}
$final = Observe-Owner
if ([string]$final['release_set_sha256'] -cne [string]$before['release_set_sha256']) {
  throw 'FIRST_USE_STAGE_UNKNOWN: offline source changed, do not replay'
}
Write-Host 'credential_initial_persistent_stage=PASS_CANDIDATE_ONLY'
Write-Host "credential_candidate_generation=$Generation"
Write-Host "credential_candidate_slot=$Slot"
Write-Host 'windows_scm_state=Stopped'
Write-Host 'windows_tun_mutations=0'
Write-Host 'windows_dns_mutations=0'
Write-Host 'windows_routes_mutations=0'
Write-Host 'windows_release_mutations=0'
Write-Host 'vm_credential_mutations=0'
Write-Host 'credential_pair_committed=false'
Write-Host 'windows_proxyonly_serving=NOT_STARTED'
