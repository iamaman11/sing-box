# Exact immutable stopped owner -> stopped ProxyOnly handoff, no SCM start.
# This pre-BEGIN preflight must accept exactly the source states the subsequent
# one-shot stage can handle: stopped ProxyOnly or stopped former ManagedTun.
# SCM, routes, TUN, DNS and unrelated Cloudflare One remain untouched.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$AcceptedRevision,
  [Parameter(Mandatory)][string]$ReleaseSetSha256,
  [switch]$Preflight,
  [switch]$RequireCurrentRelease,
  [switch]$ExistingActive,
  [string]$ExpectedSourceReleaseSet = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\sing-box'
if ($ExistingActive -and $RequireCurrentRelease) { throw 'WINDOWS_APPLY_BLOCKED: incompatible guards' }
if ($RequireCurrentRelease -and -not $Preflight) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: exact-current guard is read-only preflight only'
}
if ($env:GITHUB_REPOSITORY -cne 'iamaman11/sing-box' -or
    $env:GITHUB_REF -cne 'refs/heads/main' -or
    $env:GITHUB_RUN_ATTEMPT -cne '1' -or
    $env:EDGE_FIRST_USE_EXPECTED_MODE -cne 'ProxyOnly' -or
    $AcceptedRevision -notmatch '^[0-9a-f]{40}$' -or
    $ReleaseSetSha256 -notmatch '^[0-9a-f]{64}$') {
  throw 'FIRST_USE_OFFLINE_BLOCKED: exact protected immutable single-run authority missing'
}
if ($ExistingActive -and ($env:EDGE_WINDOWS_APPLY_POLICY -cne 'EXISTING_ACTIVE_RELEASE_ONLY' -or
    (-not $Preflight -and $ExpectedSourceReleaseSet -notmatch '^[0-9a-f]{64}$'))) {
  throw 'WINDOWS_APPLY_BLOCKED: exact existing ACTIVE program-only authority required'
}
function Read-Owner {
  $stable = Join-Path $root 'bin\edge-diagnostic.exe'
  if (-not (Test-Path -LiteralPath $stable -PathType Leaf)) {
    throw 'FIRST_USE_OFFLINE_BLOCKED: stable native diagnostic missing'
  }
  $raw = @(& $stable doctor (Join-Path $root 'current.pb'))
  $v = @{}
  foreach ($line in $raw) {
    $parts = ([string]$line).Split('=',2)
    if ($parts.Count -eq 2) { $v[$parts[0]] = $parts[1] }
  }
  if ([string]$v['exact_release_files'] -cne 'PASS' -or
      [string]$v['release_set_sha256'] -notmatch '^[0-9a-f]{64}$' -or
      [string]$v['windows_datapath_mode'] -notin @('ManagedTun','ProxyOnly') -or
      [string]$v['scm_state'] -cne 'Stopped' -or
      [string]$v['managed_tun_present'] -cne 'false') {
    throw 'FIRST_USE_OFFLINE_BLOCKED: exact stopped release/no-TUN evidence absent'
  }
  foreach ($key in @('managed_singbox_process_count','orphan_singbox_process_count',
      'conflicting_singbox_process_count','unknown_singbox_process_count')) {
    if ([string]$v[$key] -cne '0') {
      throw 'FIRST_USE_OFFLINE_BLOCKED: managed or external sing-box process present'
    }
  }
  $service = Get-CimInstance Win32_Service -Filter "Name='EdgePlatformController'" -ErrorAction Stop
  if ($null -eq $service -or [string]$service.State -cne 'Stopped') {
    throw 'FIRST_USE_OFFLINE_BLOCKED: service state unknown/changed'
  }
  # ProxyOnly must already be manual-start. A staged first-use candidate must
  # never consume its one-time BEGIN while the old service can autostart.
  if ([string]$v['windows_datapath_mode'] -ceq 'ProxyOnly' -and
      ([string]$v['scm_start_type'] -cne 'OnDemand' -or
       [string]$service.StartMode -cne 'Manual')) {
    throw 'FIRST_USE_OFFLINE_BLOCKED: stopped ProxyOnly must be manual-start before BEGIN'
  }
  return $v
}
function Require-DirectNetwork {
  $dns = @(Resolve-DnsName 'www.gstatic.com' -Type A -DnsOnly -ErrorAction Stop |
    Where-Object { $_.IPAddress })
  if ($dns.Count -eq 0) { throw 'FIRST_USE_OFFLINE_BLOCKED: independent direct DNS unproven' }
  $http = (& "$env:SystemRoot\System32\curl.exe" -q --noproxy '*' --silent --show-error --fail --connect-timeout 8 --max-time 15 --output NUL --write-out '%{http_code}' 'https://www.gstatic.com/generate_204').Trim()
  if ($LASTEXITCODE -ne 0 -or $http -cne '204') {
    throw 'FIRST_USE_OFFLINE_BLOCKED: independent no-proxy HTTPS unproven'
  }
}
function Read-NetworkOwner {
  # No changes to an independently owned WARP client or direct DNS route.
  $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
    Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1
  if ($null -eq $route) { throw 'WINDOWS_APPLY_BLOCKED: default IPv4 route missing' }
  $dns = @(Get-DnsClientServerAddress -InterfaceIndex ([int]$route.InterfaceIndex) -AddressFamily IPv4 -ErrorAction Stop |
    ForEach-Object ServerAddresses)
  if ($dns.Count -eq 0) { throw 'WINDOWS_APPLY_BLOCKED: direct IPv4 resolver absent' }
  $warp = Get-CimInstance Win32_Service -Filter "Name='CloudflareWARP'" -ErrorAction Stop
  if ($null -eq $warp) { throw 'WINDOWS_APPLY_BLOCKED: Cloudflare One service unobservable' }
  return ('{0}|{1}|{2}|{3}|{4}' -f $route.InterfaceIndex,$route.NextHop,($dns -join ','),$warp.State,$warp.StartMode)
}
$before = Read-Owner
if ($ExistingActive -and [string]$before['windows_datapath_mode'] -cne 'ProxyOnly') {
  throw 'WINDOWS_APPLY_BLOCKED: stopped ProxyOnly required'
}
if ($ExistingActive -and -not $Preflight -and [string]$before['release_set_sha256'] -cne $ExpectedSourceReleaseSet) {
  throw 'WINDOWS_APPLY_BLOCKED: old ReleaseSet drift after BEGIN'
}
Require-DirectNetwork
$networkBefore = if ($ExistingActive) { Read-NetworkOwner } else { '' }
$console = [string]$before['console_path']
if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: exact installed native console missing'
}
# Prove the actual installed SYSTEM task before any one-shot release BEGIN.
# Task identity and executable must match the immutable native doctor, not
# merely an expected Task Scheduler name from Git workflow text.
$task = Get-ScheduledTask -TaskName 'EdgePlatformPrivilegedDispatch' -ErrorAction Stop
try {
  $principal = [string]$task.Principal.UserId
  $systemSid = if ($principal -ceq 'S-1-5-18') { 'S-1-5-18' } else {
    ([Security.Principal.NTAccount]::new($principal)).Translate(
      [Security.Principal.SecurityIdentifier]).Value
  }
  $taskAction = @($task.Actions)[0]
  $taskConsole = [IO.Path]::GetFullPath(([string]$taskAction.Execute).Trim('"'))
  $installedConsole = [IO.Path]::GetFullPath($console)
} catch {
  throw 'FIRST_USE_OFFLINE_BLOCKED: SYSTEM task identity not provable'
}
if ($systemSid -cne 'S-1-5-18' -or
    [string]$task.Principal.RunLevel -cne 'Highest' -or
    [string]$task.Principal.LogonType -cne 'ServiceAccount' -or
    $task.State -cnotin @('Ready','Running') -or
    @($task.Actions).Count -ne 1 -or
    $taskConsole -ine $installedConsole -or
    [string]$taskAction.Arguments -cnotmatch '^privileged-dispatch --install-root "?C:\\sing-box"?
if ($LASTEXITCODE -ne 0 -or -not ($commands | Where-Object { $_ -match '\bprivileged-offline-activate\b' })) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: installed owner has no native offline capability; BEGIN forbidden'
}
if ([string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
  # This is the exact installer path consumed by the installed Rust offline
  # owner. Refuse a missing/reparse prerequisite BEFORE writing the one-shot
  # GitHub BEGIN rather than discovering it after a VM/Windows transaction.
  $bootstrap = Join-Path $root 'bootstrap\install-windows-release.ps1'
  if (-not (Test-Path -LiteralPath $bootstrap -PathType Leaf) -or
      ((Get-Item -LiteralPath $bootstrap -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'FIRST_USE_OFFLINE_BLOCKED: protected native offline installer prerequisite missing before BEGIN'
  }
}
function Read-SystemCredential([string]$native) {
  # The installed SYSTEM owner reads the private store; GitHub never does.
  $output = @(& $native privileged-runtime-evidence --install-root $root)
  if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_APPLY_BLOCKED: SYSTEM evidence unavailable' }
  $rows = @($output | Where-Object { [string]$_ -like 'detail=runtime_evidence=BOUNDED_READ_ONLY;*' })
  if ($rows.Count -ne 1) { throw 'WINDOWS_APPLY_BLOCKED: ambiguous SYSTEM evidence' }
  $proof = [string]$rows[0]
  if ($ExistingActive) {
    foreach ($field in @('credential_cursor=VALID','credential_active_present=true',
        'credential_candidate_present=false','credential_previous_present=false',
        'first_use_runtime=PRESENT','first_use_config=PRESENT')) {
      if ([regex]::Matches($proof,'(?:^|;)' + [regex]::Escape($field) + '(?:;|$)').Count -ne 1) {
        throw 'WINDOWS_APPLY_BLOCKED: ACTIVE cursor/runtime not exact'
      }
    }
  } elseif ($proof -notmatch ';credential_cursor=ABSENT(?:;|$)' -or
      $proof -notmatch ';first_use_runtime=ABSENT(?:;|$)' -or
      $proof -notmatch ';first_use_config=ABSENT(?:;|$)' -or
      $proof -notmatch ';first_use_access_identity=PRESENT_NONEMPTY_UNVERIFIED(?:;|$)') {
    throw 'FIRST_USE_OFFLINE_BLOCKED: credential cursor, runtime or Access identity unproven'
  }
  return $proof
}
$credentialBefore = Read-SystemCredential $console
if ($Preflight) {
  # A once-only credential BEGIN may be written only after native offline
  # ReleaseSet upgrade already completed and exact owner readback is stable.
  if ($RequireCurrentRelease -and [string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
    throw 'FIRST_USE_PREBEGIN_BLOCKED: exact accepted Windows ReleaseSet must be installed BEFORE durable BEGIN'
  }
  Write-Output "windows_credential_policy=$(if ($ExistingActive) { 'EXISTING_ACTIVE_RELEASE_ONLY' } else { 'FRESH_FIRST_USE' })"
  Write-Host 'windows_first_use_prebegin_preflight=PASS_READ_ONLY'
  Write-Host "windows_offline_source_mode=$([string]$before['windows_datapath_mode'])"
  Write-Output "windows_offline_source_release=$([string]$before['release_set_sha256'])"
  Write-Output "windows_offline_transition_needed=$([string]$before['release_set_sha256'] -cne $ReleaseSetSha256)"
  Write-Host "windows_installed_release=$([string]$before['release_set_sha256'])"
  Write-Host 'windows_scm_state=Stopped'
  Write-Host 'windows_credential_mutations=0'
  return
}
if ([string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
  # Rust's existing offline owner owns the journal, exact ReleaseSet download,
  # SCM manual-start retarget and compensation for BOTH stopped source modes.
  # Do not introduce another installer/privilege path or reattempt on unknown.
  $console = [string]$before['console_path']
  if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
    throw 'FIRST_USE_OFFLINE_BLOCKED: immutable installed native console missing'
  }
  # Single existing SYSTEM operation owns exact release download, journalled
  # pointers, task/SCM handoff and rollback. Never perform native file writes
  # or invoke this twice after a lost/uncertain ACK.
  & $console privileged-offline-activate $AcceptedRevision $ReleaseSetSha256 --install-root $root
  if ($LASTEXITCODE -ne 0) {
    throw 'FIRST_USE_OFFLINE_UNKNOWN: native release handoff unconfirmed; no replay'
  }
}
$after = Read-Owner
if ($ExistingActive) {
  $credentialAfter = Read-SystemCredential ([string]$after['console_path'])
  foreach ($field in @('credential_active_generation','credential_active_slot','credential_active_sha256')) {
    $old = [regex]::Match($credentialBefore,'(?:^|;)' + $field + '=([^;]*)')
    $new = [regex]::Match($credentialAfter,'(?:^|;)' + $field + '=([^;]*)')
    if ($old.Success -and $old.Groups[1].Value -notin @('UNKNOWN','UNKNOWN_NOT_EXPORTED') -and
        (-not $new.Success -or $old.Groups[1].Value -cne $new.Groups[1].Value)) {
      throw 'WINDOWS_APPLY_UNKNOWN: credential metadata changed; no replay'
    }
  }
  if ($networkBefore -cne (Read-NetworkOwner)) {
    throw 'WINDOWS_APPLY_UNKNOWN: route, DNS or Cloudflare One owner drift; no replay'
  }
}
if ([string]$after['release_set_sha256'] -cne $ReleaseSetSha256 -or
    [string]$after['windows_datapath_mode'] -cne 'ProxyOnly') {
  throw 'FIRST_USE_OFFLINE_UNKNOWN: exact stopped ProxyOnly target not proven; no replay'
}
Require-DirectNetwork
Write-Host "windows_release_only_result=$(if ($ExistingActive) { 'PASS_ACTIVE_CURSOR_AND_NETWORK_PARITY_ORIGIN_UNPROVEN' } else { 'NOT_APPLICABLE_FIRST_USE' })"
Write-Host 'windows_first_use_offline_release=PASS_STOPPED_PROXY_ONLY'
Write-Host "windows_release_set_sha256=$ReleaseSetSha256"
Write-Host 'windows_scm_state=Stopped'
Write-Host 'managed_tun_present=false'
Write-Host 'windows_dns_mutations=0'
Write-Host 'windows_routes_mutations=0'
Write-Host 'windows_tun_mutations=0'
Write-Host 'credential_pair_committed=false'
) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: installed SYSTEM task or immutable action mismatched'
}
$commands = @(& $console --help)
if ($LASTEXITCODE -ne 0 -or -not ($commands | Where-Object { $_ -match '\bprivileged-offline-activate\b' })) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: installed owner has no native offline capability; BEGIN forbidden'
}
if ([string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
  # This is the exact installer path consumed by the installed Rust offline
  # owner. Refuse a missing/reparse prerequisite BEFORE writing the one-shot
  # GitHub BEGIN rather than discovering it after a VM/Windows transaction.
  $bootstrap = Join-Path $root 'bootstrap\install-windows-release.ps1'
  if (-not (Test-Path -LiteralPath $bootstrap -PathType Leaf) -or
      ((Get-Item -LiteralPath $bootstrap -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'FIRST_USE_OFFLINE_BLOCKED: protected native offline installer prerequisite missing before BEGIN'
  }
}
function Read-SystemCredential([string]$native) {
  # The installed SYSTEM owner reads the private store; GitHub never does.
  $output = @(& $native privileged-runtime-evidence --install-root $root)
  if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_APPLY_BLOCKED: SYSTEM evidence unavailable' }
  $rows = @($output | Where-Object { [string]$_ -like 'detail=runtime_evidence=BOUNDED_READ_ONLY;*' })
  if ($rows.Count -ne 1) { throw 'WINDOWS_APPLY_BLOCKED: ambiguous SYSTEM evidence' }
  $proof = [string]$rows[0]
  if ($ExistingActive) {
    foreach ($field in @('credential_cursor=VALID','credential_active_present=true',
        'credential_candidate_present=false','credential_previous_present=false',
        'first_use_runtime=PRESENT','first_use_config=PRESENT')) {
      if ([regex]::Matches($proof,'(?:^|;)' + [regex]::Escape($field) + '(?:;|$)').Count -ne 1) {
        throw 'WINDOWS_APPLY_BLOCKED: ACTIVE cursor/runtime not exact'
      }
    }
  } elseif ($proof -notmatch ';credential_cursor=ABSENT(?:;|$)' -or
      $proof -notmatch ';first_use_runtime=ABSENT(?:;|$)' -or
      $proof -notmatch ';first_use_config=ABSENT(?:;|$)' -or
      $proof -notmatch ';first_use_access_identity=PRESENT_NONEMPTY_UNVERIFIED(?:;|$)') {
    throw 'FIRST_USE_OFFLINE_BLOCKED: credential cursor, runtime or Access identity unproven'
  }
  return $proof
}
$credentialBefore = Read-SystemCredential $console
if ($Preflight) {
  # A once-only credential BEGIN may be written only after native offline
  # ReleaseSet upgrade already completed and exact owner readback is stable.
  if ($RequireCurrentRelease -and [string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
    throw 'FIRST_USE_PREBEGIN_BLOCKED: exact accepted Windows ReleaseSet must be installed BEFORE durable BEGIN'
  }
  Write-Output "windows_credential_policy=$(if ($ExistingActive) { 'EXISTING_ACTIVE_RELEASE_ONLY' } else { 'FRESH_FIRST_USE' })"
  Write-Host 'windows_first_use_prebegin_preflight=PASS_READ_ONLY'
  Write-Host "windows_offline_source_mode=$([string]$before['windows_datapath_mode'])"
  Write-Output "windows_offline_source_release=$([string]$before['release_set_sha256'])"
  Write-Output "windows_offline_transition_needed=$([string]$before['release_set_sha256'] -cne $ReleaseSetSha256)"
  Write-Host "windows_installed_release=$([string]$before['release_set_sha256'])"
  Write-Host 'windows_scm_state=Stopped'
  Write-Host 'windows_credential_mutations=0'
  return
}
if ([string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
  # Rust's existing offline owner owns the journal, exact ReleaseSet download,
  # SCM manual-start retarget and compensation for BOTH stopped source modes.
  # Do not introduce another installer/privilege path or reattempt on unknown.
  $console = [string]$before['console_path']
  if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
    throw 'FIRST_USE_OFFLINE_BLOCKED: immutable installed native console missing'
  }
  # Single existing SYSTEM operation owns exact release download, journalled
  # pointers, task/SCM handoff and rollback. Never perform native file writes
  # or invoke this twice after a lost/uncertain ACK.
  & $console privileged-offline-activate $AcceptedRevision $ReleaseSetSha256 --install-root $root
  if ($LASTEXITCODE -ne 0) {
    throw 'FIRST_USE_OFFLINE_UNKNOWN: native release handoff unconfirmed; no replay'
  }
}
$after = Read-Owner
if ($ExistingActive) {
  $credentialAfter = Read-SystemCredential ([string]$after['console_path'])
  foreach ($field in @('credential_active_generation','credential_active_slot','credential_active_sha256')) {
    $old = [regex]::Match($credentialBefore,'(?:^|;)' + $field + '=([^;]*)')
    $new = [regex]::Match($credentialAfter,'(?:^|;)' + $field + '=([^;]*)')
    if ($old.Success -and $old.Groups[1].Value -notin @('UNKNOWN','UNKNOWN_NOT_EXPORTED') -and
        (-not $new.Success -or $old.Groups[1].Value -cne $new.Groups[1].Value)) {
      throw 'WINDOWS_APPLY_UNKNOWN: credential metadata changed; no replay'
    }
  }
  if ($networkBefore -cne (Read-NetworkOwner)) {
    throw 'WINDOWS_APPLY_UNKNOWN: route, DNS or Cloudflare One owner drift; no replay'
  }
}
if ([string]$after['release_set_sha256'] -cne $ReleaseSetSha256 -or
    [string]$after['windows_datapath_mode'] -cne 'ProxyOnly') {
  throw 'FIRST_USE_OFFLINE_UNKNOWN: exact stopped ProxyOnly target not proven; no replay'
}
Require-DirectNetwork
Write-Host "windows_release_only_result=$(if ($ExistingActive) { 'PASS_ACTIVE_CURSOR_AND_NETWORK_PARITY_ORIGIN_UNPROVEN' } else { 'NOT_APPLICABLE_FIRST_USE' })"
Write-Host 'windows_first_use_offline_release=PASS_STOPPED_PROXY_ONLY'
Write-Host "windows_release_set_sha256=$ReleaseSetSha256"
Write-Host 'windows_scm_state=Stopped'
Write-Host 'managed_tun_present=false'
Write-Host 'windows_dns_mutations=0'
Write-Host 'windows_routes_mutations=0'
Write-Host 'windows_tun_mutations=0'
Write-Host 'credential_pair_committed=false'
