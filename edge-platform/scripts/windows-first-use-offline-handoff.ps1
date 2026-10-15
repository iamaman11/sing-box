# Exact immutable offline ManagedTun -> ProxyOnly handoff, no SCM start.
# Called only once from the canonical protected GitHub first-use Windows job.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$AcceptedRevision,
  [Parameter(Mandatory)][string]$ReleaseSetSha256,
  [switch]$Preflight
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\sing-box'
if ($env:GITHUB_REPOSITORY -cne 'iamaman11/sing-box' -or
    $env:GITHUB_REF -cne 'refs/heads/main' -or
    $env:GITHUB_RUN_ATTEMPT -cne '1' -or
    $env:EDGE_FIRST_USE_EXPECTED_MODE -cne 'ProxyOnly' -or
    $AcceptedRevision -notmatch '^[0-9a-f]{40}$' -or
    $ReleaseSetSha256 -notmatch '^[0-9a-f]{64}$') {
  throw 'FIRST_USE_OFFLINE_BLOCKED: exact protected immutable single-run authority missing'
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
$before = Read-Owner
Require-DirectNetwork
$console = [string]$before['console_path']
if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: exact installed native console missing'
}
$commands = @(& $console --help)
if ($LASTEXITCODE -ne 0 -or -not ($commands | Where-Object { $_ -match '\\bprivileged-offline-activate\\b' })) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: installed owner has no native offline capability; BEGIN forbidden'
}
$evidence = @(& $console privileged-runtime-evidence --install-root $root)
if ($LASTEXITCODE -ne 0) {
  throw 'FIRST_USE_OFFLINE_BLOCKED: installed SYSTEM readonly evidence unavailable'
}
$details = @($evidence | Where-Object { [string]$_ -like 'detail=*' })
if ($details.Count -ne 1 -or
    [string]$details[0] -notmatch ';credential_cursor=ABSENT;' -or
    [string]$details[0] -notmatch ';first_use_runtime=ABSENT;' -or
    [string]$details[0] -notmatch ';first_use_config=ABSENT;' -or
    [string]$details[0] -notmatch ';first_use_access_identity=PRESENT_NONEMPTY_UNVERIFIED(?:;|$)') {
  throw 'FIRST_USE_OFFLINE_BLOCKED: credential cursor, runtime or permanent Access identity is unproven'
}
if ($Preflight) {
  Write-Host 'windows_first_use_prebegin_preflight=PASS_READ_ONLY'
  Write-Host "windows_installed_release=$([string]$before['release_set_sha256'])"
  Write-Host 'windows_scm_state=Stopped'
  Write-Host 'windows_credential_mutations=0'
  return
}
if ([string]$before['release_set_sha256'] -cne $ReleaseSetSha256) {
  if ([string]$before['windows_datapath_mode'] -cne 'ManagedTun') {
    throw 'FIRST_USE_OFFLINE_BLOCKED: only stopped former ManagedTun may switch to ProxyOnly'
  }
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
if ([string]$after['release_set_sha256'] -cne $ReleaseSetSha256 -or
    [string]$after['windows_datapath_mode'] -cne 'ProxyOnly') {
  throw 'FIRST_USE_OFFLINE_UNKNOWN: exact stopped ProxyOnly target not proven; no replay'
}
Require-DirectNetwork
Write-Host 'windows_first_use_offline_release=PASS_STOPPED_PROXY_ONLY'
Write-Host "windows_release_set_sha256=$ReleaseSetSha256"
Write-Host 'windows_scm_state=Stopped'
Write-Host 'managed_tun_present=false'
Write-Host 'windows_dns_mutations=0'
Write-Host 'windows_routes_mutations=0'
Write-Host 'windows_tun_mutations=0'
Write-Host 'credential_pair_committed=false'
