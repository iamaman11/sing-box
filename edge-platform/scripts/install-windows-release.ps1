[CmdletBinding()]
param(
    [string]$Repository = "iamaman11/sing-box",
    [string]$ReleaseSetSha256 = "",
    [string]$AcceptedRevision = "",
    # One operator entrypoint: select exact published main ReleaseSet, no SHA
    # hand-copied from GitHub. Retained old BEGIN needs separate explicit scope.
    [switch]$ConnectWindows,
    [switch]$ApproveRetainedBegin,
    # Explicit local approval to harden the old unsafe EXE chain before running it.
    [switch]$ApproveAclRepair,
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


# Trusted-entry repair is intentionally bounded to the application executable
# chain. Never traverse native-host/, journals, sealed private keys, or C:\.
# This is local Administrator first-use authority, not runner/remote authority.
function Get-ProtectedAppAclReadback {
    param([Parameter(Mandatory)] [string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'WINDOWS_INSTALL_PRELAUNCH_REPARSE_PATH_BLOCKED'
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = ([Security.Principal.NTAccount]::new([string]$acl.Owner)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw 'WINDOWS_INSTALL_PRELAUNCH_OWNER_NOT_PRIVILEGED'
    }
    # Same effective mutation mask as the native SYSTEM journal verifier.
    [long]$write = 0x00000002 -bor 0x00000004 -bor 0x00000010 -bor
        0x00000040 -bor 0x00000100 -bor 0x00010000 -bor
        0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
    $writers = @()
    foreach ($ace in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sid = $ace.IdentityReference.Value
        if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $sid -in @('S-1-5-18', 'S-1-5-32-544')) {
            continue
        }
        if (([long]$ace.FileSystemRights -band $write) -ne 0) {
            $writers += $sid
        }
    }
    return @($writers | Sort-Object -Unique)
}

function Assert-RootExecutionChain {
    param([switch]$CreateFresh, [switch]$ApproveRepair)
    if ($InstallRoot -cne 'C:\sing-box') {
        throw 'WINDOWS_INSTALL_PRELAUNCH_EXACT_ROOT_REQUIRED'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'WINDOWS_INSTALL_PRELAUNCH_ELEVATED_ADMIN_REQUIRED'
    }
    $exists = Test-Path -LiteralPath $InstallRoot -PathType Container
    if (-not $exists -and -not $CreateFresh) {
        throw 'WINDOWS_INSTALL_PRELAUNCH_ROOT_MISSING'
    }
    if (-not $exists) {
        if (Test-Path -LiteralPath $InstallRoot) {
            throw 'WINDOWS_INSTALL_PRELAUNCH_ROOT_WRONG_TYPE'
        }
        New-Item -ItemType Directory -Path $InstallRoot -ErrorAction Stop | Out-Null
        $ApproveRepair = $true
    }
    if ($exists -and $ApproveRepair) {
        # A periodic SYSTEM dispatch may run old bytes while the root DACL is
        # being normalized. Explicit ACL approval does NOT grant authority to
        # disable/restart it. Only a separate proven offline handoff may leave
        # the existing task Disabled before this change.
        $task = Get-ScheduledTask -TaskName 'EdgePlatformPrivilegedDispatch' -ErrorAction Stop
        if ($null -eq $task -or [string]$task.State -cne 'Disabled' -or
            @($task.Actions).Count -ne 1 -or
            [string]$task.Principal.LogonType -cne 'ServiceAccount' -or
            [string]$task.Principal.RunLevel -cne 'Highest') {
            throw 'WINDOWS_INSTALL_ACL_REPAIR_REQUIRES_EXACT_DISABLED_SYSTEM_TASK'
        }
        $principal = [string]$task.Principal.UserId
        $systemSid = if ($principal -ceq 'S-1-5-18') { $principal } else {
            ([Security.Principal.NTAccount]::new($principal)).Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        }
        if ($systemSid -cne 'S-1-5-18' -or
            [string]$task.Actions[0].Arguments -cnotmatch '^privileged-dispatch --install-root "?C:\\sing-box"?$' -or
            ([string]$task.Actions[0].Execute).Trim('"') -cnotmatch '^C:\\sing-box\\releases\\[0-9a-f]{64}\\bin\\edge-console\.exe$') {
            throw 'WINDOWS_INSTALL_ACL_REPAIR_SYSTEM_TASK_IDENTITY_MISMATCH'
        }
        $runningConsole = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='edge-console.exe'" -ErrorAction Stop)
        if ($runningConsole.Count -ne 0) {
            throw 'WINDOWS_INSTALL_ACL_REPAIR_OLD_CONSOLE_RUNNING'
        }
        $controller = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='EdgePlatformController'" -ErrorAction Stop)
        if ($controller.Count -ne 1 -or [string]$controller[0].State -cne 'Stopped') {
            throw 'WINDOWS_INSTALL_ACL_REPAIR_CONTROLLER_NOT_STOPPED'
        }
        $tuns = @(Get-NetAdapter -Name 'sing-box-tun' -ErrorAction SilentlyContinue)
        if ($tuns.Count -ne 0) {
            throw 'WINDOWS_INSTALL_ACL_REPAIR_MANAGED_TUN_PRESENT'
        }
    }
    $scopes = @($InstallRoot)
    foreach ($name in @('releases', 'bin', 'bootstrap')) {
        $path = Join-Path $InstallRoot $name
        if (Test-Path -LiteralPath $path) {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                throw 'WINDOWS_INSTALL_PRELAUNCH_EXECUTABLE_DIR_WRONG_TYPE'
            }
            $scopes += $path
        }
    }
    # Reparse points and unprivileged OWNERS are checked before any mutation.
    # A recursive icacls /reset must never traverse an unknown junction or
    # rewrite a sealed private-key/journal tree through a hidden link.
    foreach ($path in $scopes) {
        $objects = @(Get-Item -LiteralPath $path -Force -ErrorAction Stop)
        if ($path -cne $InstallRoot) {
            $objects += @(Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction Stop)
        }
        if ($objects.Count -gt 12000) {
            throw 'WINDOWS_INSTALL_PRELAUNCH_EXECUTABLE_TREE_TOO_LARGE'
        }
        foreach ($entry in $objects) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'WINDOWS_INSTALL_PRELAUNCH_DESCENDANT_REPARSE_BLOCKED'
            }
            # Fails if the owner is neither SYSTEM nor Administrators. An
            # unsafe owner cannot be silently normalized during repair.
            $null = Get-ProtectedAppAclReadback -Path $entry.FullName
        }
    }
    if ($ApproveRepair) {
        foreach ($path in $scopes) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'WINDOWS_INSTALL_PRELAUNCH_REPARSE_PATH_BLOCKED'
            }
            # A root/EXE write grant may be EXPLICIT even when its owner is
            # Administrators. /inheritance:r alone does not remove that grant.
            & icacls.exe $path /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-20:(OI)(CI)RX' /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_PRELAUNCH_GRANT_FAILED_NO_EXECUTION' }
            & icacls.exe $path /inheritance:r /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_PRELAUNCH_INHERITANCE_FAILED_NO_EXECUTION' }
            # Read every explicit writer SID from the exact directory ACL.
            # This scope never includes native-host or its sealed identity.
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            [long]$write = 0x00000002 -bor 0x00000004 -bor 0x00000010 -bor
                0x00000040 -bor 0x00000100 -bor 0x00010000 -bor
                0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
            $unsafe = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                    $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and
                    (([long]$_.FileSystemRights -band $write) -ne 0) } |
                ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
            foreach ($sid in $unsafe) {
                & icacls.exe $path /remove:g "*$sid" /Q | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_PRELAUNCH_WRITER_REMOVAL_FAILED_NO_EXECUTION' }
            }
            & icacls.exe $path /setowner '*S-1-5-32-544' /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_PRELAUNCH_OWNER_FAILED_NO_EXECUTION' }
            if ($path -cne $InstallRoot) {
                # Only immutable executable trees. A reset on C:\sing-box or
                # native-host would destroy the sealed key's intended DACL.
                & icacls.exe (Join-Path $path '*') /reset /T /Q | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_PRELAUNCH_EXECUTABLE_RESET_FAILED_NO_EXECUTION' }
                & icacls.exe $path /setowner '*S-1-5-32-544' /T /Q | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_PRELAUNCH_EXECUTABLE_OWNER_FAILED_NO_EXECUTION' }
            }
        }
    }
    foreach ($path in $scopes) {
        $objects = @($path)
        if ($path -cne $InstallRoot) {
            $objects += @(Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction Stop |
                Select-Object -ExpandProperty FullName)
        }
        if ($objects.Count -gt 12000) { throw 'WINDOWS_INSTALL_PRELAUNCH_EXECUTABLE_TREE_TOO_LARGE' }
        foreach ($object in $objects) {
            if (@(Get-ProtectedAppAclReadback -Path $object).Count -ne 0) {
                throw 'WINDOWS_INSTALL_PRELAUNCH_UNPRIVILEGED_WRITER_BLOCKED'
            }
        }
    }
}


function Protect-ReleaseStageBeforeExecution {
    param([Parameter(Mandatory)] [string]$Stage)
    $expectedPrefix = Join-Path $InstallRoot '.release-stage-'
    $isReleaseStage = $Stage -cmatch '^C:\\sing-box\\releases\\[0-9a-f]{64}\.new$'
    if (-not $Stage.StartsWith($expectedPrefix, [StringComparison]::Ordinal) -and
        -not $isReleaseStage) {
        throw 'WINDOWS_INSTALL_STAGE_SCOPE_INVALID'
    }
    # No extracted binary may be run while owned or writable by an ordinary
    # SID, even when its verified source archive came from protected Git.
    $items = @(Get-Item -LiteralPath $Stage -Force -ErrorAction Stop)
    $items += @(Get-ChildItem -LiteralPath $Stage -Force -Recurse -ErrorAction Stop)
    if ($items.Count -gt 12000) { throw 'WINDOWS_INSTALL_STAGE_TOO_LARGE' }
    foreach ($entry in $items) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'WINDOWS_INSTALL_STAGE_REPARSE_BLOCKED'
        }
    }
    & icacls.exe $Stage /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-20:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_STAGE_ACL_FAILED' }
    & icacls.exe $Stage /inheritance:r /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_STAGE_INHERITANCE_FAILED' }
    & icacls.exe (Join-Path $Stage '*') /reset /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_STAGE_RESET_FAILED' }
    & icacls.exe $Stage /setowner '*S-1-5-32-544' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_INSTALL_STAGE_OWNER_FAILED' }
    foreach ($entry in $items) {
        if (@(Get-ProtectedAppAclReadback -Path $entry.FullName).Count -ne 0) {
            throw 'WINDOWS_INSTALL_STAGE_UNPRIVILEGED_WRITER'
        }
    }
}


# Avoid $matches (PowerShell's automatic regex capture variable).
# Missing/malformed published digests fail closed, not as a property exception.
function Get-RequiredPublishedAssetSha256 {
    param([Parameter(Mandatory)] $Release, [Parameter(Mandatory)] [string]$Name)
    $namedAssets = @($Release.assets | Where-Object { [string]$_.name -ceq $Name })
    if ($namedAssets.Count -ne 1) {
        throw "WINDOWS_INSTALL_OLD_RELEASE_ASSET_NOT_UNIQUE: $Name"
    }
    $digestMember = $namedAssets[0].PSObject.Properties['digest']
    if ($null -eq $digestMember -or
        [string]$digestMember.Value -cnotmatch '^sha256:[0-9a-f]{64}$') {
        throw "WINDOWS_INSTALL_OLD_RELEASE_PUBLISHED_DIGEST_UNAVAILABLE: $Name"
    }
    return ([string]$digestMember.Value).Substring(7)
}

# A repaired DACL does not establish authenticity of code that previously
# was replaceable. Bind the old SYSTEM EXE to the exact published Git release
# BEFORE executing the installed diagnostic/console from that directory.
function Assert-ExistingNativeReleaseFromProtectedGit {
    $task = Get-ScheduledTask -TaskName 'EdgePlatformPrivilegedDispatch' -ErrorAction Stop
    if ($null -eq $task -or @($task.Actions).Count -ne 1 -or
        [string]$task.Principal.LogonType -cne 'ServiceAccount' -or
        [string]$task.Principal.RunLevel -cne 'Highest') {
        throw 'WINDOWS_INSTALL_OLD_SYSTEM_OWNER_UNPROVEN'
    }
    $owner = [string]$task.Principal.UserId
    $sid = if ($owner -ceq 'S-1-5-18') { $owner } else {
        ([Security.Principal.NTAccount]::new($owner)).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    $taskArgs = [string]$task.Actions[0].Arguments
    $taskExe = ([string]$task.Actions[0].Execute).Trim('"')
    $exact = [regex]::Match(
        $taskExe,
        '\AC:\\sing-box\\releases\\(?<sha>[0-9a-f]{64})\\bin\\edge-console\.exe\z'
    )
    if ($sid -cne 'S-1-5-18' -or
        $taskArgs -cnotmatch '^privileged-dispatch --install-root "?C:\\sing-box"?$' -or
        -not $exact.Success) {
        throw 'WINDOWS_INSTALL_OLD_SYSTEM_OWNER_UNPROVEN'
    }
    $releaseSha = $exact.Groups['sha'].Value
    $tag = "edge-release-$releaseSha"
    $release = Get-DurableRelease -Tag $tag
    $head = Invoke-GitHubJsonGet -Uri "https://api.github.com/repos/$Repository/branches/main"
    $revision = [string]$release.target_commitish
    if (-not [bool]$head.protected -or
        [string]$head.commit.sha -cnotmatch '^[0-9a-f]{40}$' -or
        $revision -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$release.tag_name -cne $tag -or
        [bool]$release.draft -or [bool]$release.prerelease -or
        [string]::IsNullOrEmpty([string]$release.published_at)) {
        throw 'WINDOWS_INSTALL_OLD_RELEASE_GIT_AUTHORITY_UNPROVEN'
    }
    $ref = Invoke-GitHubJsonGet -Uri "https://api.github.com/repos/$Repository/git/ref/tags/$tag"
    $compareUri = "https://api.github.com/repos/$Repository/compare/" +
        $revision + "..." + [string]$head.commit.sha + "?per_page=1&page=2"
    $compare = Invoke-GitHubJsonGet -Uri $compareUri
    if ([string]$ref.object.type -cne 'commit' -or
        [string]$ref.object.sha -cne $revision -or
        [string]$compare.status -notin @('ahead', 'identical') -or
        [string]$compare.base_commit.sha -cne $revision -or
        [string]$compare.merge_base_commit.sha -cne $revision) {
        throw 'WINDOWS_INSTALL_OLD_RELEASE_NOT_PROTECTED_MAIN_ANCESTOR'
    }
    $oldDir = Join-Path $InstallRoot "releases\$releaseSha"
    foreach ($asset in @('edge-platform-windows.zip', 'release-set.pb')) {
        $publishedDigest = Get-RequiredPublishedAssetSha256 -Release $release -Name $asset
        $file = Join-Path $oldDir $asset
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
            (Get-ExactHash -Path $file) -cne $publishedDigest) {
            throw 'WINDOWS_INSTALL_OLD_RELEASE_BYTES_NOT_PUBLISHED_NO_EXECUTION'
        }
    }
    if ((Get-ExactHash -Path (Join-Path $oldDir 'release-set.pb')) -cne $releaseSha) {
        throw 'WINDOWS_INSTALL_OLD_RELEASE_MANIFEST_SHA_MISMATCH'
    }
    $stage = Join-Path $InstallRoot ('.release-verify-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
    try {
        # Decompress as data; never execute an untrusted existing EXE.
        Expand-Archive -LiteralPath (Join-Path $oldDir 'edge-platform-windows.zip') -DestinationPath $stage
        foreach ($exe in @('edge-console.exe','edge-diagnostic.exe','edge-controller.exe','sing-box.exe','edge-release-set.exe')) {
            $published = Join-Path $stage "bin\$exe"
            $installed = Join-Path $oldDir "bin\$exe"
            if (-not (Test-Path -LiteralPath $published -PathType Leaf) -or
                -not (Test-Path -LiteralPath $installed -PathType Leaf) -or
                (Get-ExactHash -Path $published) -cne (Get-ExactHash -Path $installed)) {
                throw 'WINDOWS_INSTALL_OLD_EXECUTABLE_NOT_PUBLISHED_NO_EXECUTION'
            }
        }
        foreach ($exe in @('edge-console.exe','edge-diagnostic.exe')) {
            if ((Get-ExactHash -Path (Join-Path $InstallRoot "bin\$exe")) -cne
                (Get-ExactHash -Path (Join-Path $stage "bin\$exe"))) {
                throw 'WINDOWS_INSTALL_OLD_STABLE_BINARY_NOT_PUBLISHED_NO_EXECUTION'
            }
        }
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'windows_old_executables=PUBLISHED_RELEASE_VERIFIED_BEFORE_EXECUTION'
}

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


# One authenticated read session per ConnectWindows, including the existing
# nested installer call. No new service, journal, or persistent token.
function Resolve-ConnectWindowsGitHubToken {
    param([string]$Supplied)
    if (-not [string]::IsNullOrWhiteSpace($Supplied)) {
        $token = $Supplied.Trim()
    } else {
        # Never execute gh.exe from a user-writable PATH as Administrator.
        $gh = if ([string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
            ''
        } else { Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe' }
        if (-not $gh -or -not (Test-Path -LiteralPath $gh -PathType Leaf)) {
            throw 'WINDOWS_CONNECT_GITHUB_AUTH_REQUIRED'
        }
        $meta = Get-Item -LiteralPath $gh -Force -ErrorAction Stop
        if ($meta.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'WINDOWS_CONNECT_GITHUB_CLI_REPARSE_FORBIDDEN'
        }
        try {
            $values = @(& $gh auth token --hostname github.com 2>$null)
            if ($LASTEXITCODE -ne 0 -or $values.Count -ne 1) {
                throw 'GitHub CLI authentication unavailable'
            }
            $token = [string]$values[0]
        } catch { throw 'WINDOWS_CONNECT_GITHUB_AUTH_REQUIRED' }
    }
    if ($token.Length -lt 16 -or $token.Length -gt 512 -or
        $token -cnotmatch '^[A-Za-z0-9_-]+$') {
        throw 'WINDOWS_CONNECT_GITHUB_AUTH_INVALID'
    }
    return $token
}
function Assert-ConnectWindowsGitHubBudget {
    $rate = Invoke-GitHubJsonGet -Uri 'https://api.github.com/rate_limit'
    try { $remaining = [long]$rate.resources.core.remaining }
    catch { throw 'WINDOWS_CONNECT_GITHUB_RATE_BUDGET_UNPROVEN' }
    if ($remaining -lt 0) { throw 'WINDOWS_CONNECT_GITHUB_RATE_BUDGET_UNPROVEN' }
    if ($remaining -lt 24) { throw 'WINDOWS_CONNECT_GITHUB_RATE_LIMIT_EXCEEDED_BEFORE_BEGIN' }
}
function Get-ConnectWindowsGitHubHttpCode {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)
    $property = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    try { $status = [int]$property.Value.StatusCode } catch { return '' }
    $message = [string]$ErrorRecord.Exception.Message
    if ($null -ne $ErrorRecord.ErrorDetails) {
        $message += ' ' + [string]$ErrorRecord.ErrorDetails.Message
    }
    $remainingZero = $false
    try {
        $values = $null
        if ($property.Value.Headers.TryGetValues('X-RateLimit-Remaining', [ref]$values)) {
            $remainingZero = @($values) -contains '0'
        }
    } catch {}
    if ($status -eq 429 -or ($status -eq 403 -and
        ($remainingZero -or $message -match '(?i)rate.?limit|abuse.?detection'))) {
        return 'WINDOWS_CONNECT_GITHUB_RATE_LIMIT_EXCEEDED_BEFORE_BEGIN'
    }
    if ($status -eq 401) { return 'WINDOWS_CONNECT_GITHUB_AUTH_REJECTED' }
    if ($status -eq 403) { return 'WINDOWS_CONNECT_GITHUB_PERMISSION_DENIED' }
    return ''
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
    # Global *memory* only because & $PSCommandPath nests in the same pwsh.
    # ConnectWindows resets it before the first authenticated GitHub GET.
    $v = Get-Variable -Name 'SingBoxConnectReadCache' -Scope Global -ErrorAction SilentlyContinue
    $cache = if ($null -ne $v -and $v.Value -is [hashtable]) { $v.Value } else { $null }
    if ($null -ne $cache -and $cache.ContainsKey($Uri)) { return $cache[$Uri] }
    for ($attempt = 1; $attempt -le $GitHubReadAttempts; $attempt++) {
        try {
            $result = Invoke-RestMethod @transport -Method Get -Uri $Uri -Headers (Get-GitHubHeaders) -TimeoutSec $GitHubReadTimeoutSec
            if ($null -ne $cache) { $cache[$Uri] = $result }
            return $result
        } catch {
            $code = Get-ConnectWindowsGitHubHttpCode -ErrorRecord $_
            if ($code) { throw $code }
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
            $code = Get-ConnectWindowsGitHubHttpCode -ErrorRecord $_
            if ($code) { throw $code }
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
    & icacls.exe $currentTemp /setowner '*S-1-5-32-544' /Q | Out-Null
    if ($LASTEXITCODE -ne 0 -or @(Get-ProtectedAppAclReadback -Path $currentTemp).Count -ne 0) {
        throw 'WINDOWS_INSTALL_ACTIVATION_POINTER_ACL_NOT_PROTECTED'
    }
    [void](Invoke-Diagnostic -Diagnostic $Diagnostic -State $currentTemp)

    $stableConsole = Join-Path $binDir "edge-console.exe"
    $stableDiagnostic = Join-Path $binDir "edge-diagnostic.exe"
    Copy-StableBinary -Source $Console -Target $stableConsole
    Copy-StableBinary -Source $Diagnostic -Target $stableDiagnostic
    foreach ($binary in @($stableConsole, $stableDiagnostic)) {
        & icacls.exe $binary /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0 -or @(Get-ProtectedAppAclReadback -Path $binary).Count -ne 0) {
            throw 'WINDOWS_INSTALL_STABLE_BINARY_ACL_NOT_PROTECTED'
        }
    }

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

# The retained BEGIN records a historical from -> to transaction, not
# necessarily the current installed predecessor. After a compensated UNKNOWN,
# the installed release may be either endpoint. The old operation stays
# UNKNOWN; only an explicitly approved THIRD release/revision is admissible.
function Assert-DisabledOfflineSuccessorIdentity {
    param(
        [Parameter(Mandatory)] [string]$RetainedFrom,
        [Parameter(Mandatory)] [string]$RetainedTo,
        [Parameter(Mandatory)] [string]$RetainedRevision,
        [Parameter(Mandatory)] [string]$InstalledRelease,
        [Parameter(Mandatory)] [string]$NextRelease,
        [Parameter(Mandatory)] [string]$NextRevision
    )
    if ($RetainedFrom -ceq $RetainedTo -or
        ($RetainedFrom -cne $InstalledRelease -and
         $RetainedTo -cne $InstalledRelease) -or
        $NextRelease -ceq $RetainedFrom -or
        $NextRelease -ceq $RetainedTo -or
        $NextRelease -ceq $InstalledRelease -or
        $NextRevision -ceq $RetainedRevision) {
        throw 'OFFLINE_BOOTSTRAP_DISABLED_PREDECESSOR_NOT_DISTINCT_NO_REPLAY'
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
    # GitHub authorization/budget are PREPARE: no local stage or native BEGIN.
    $GitHubToken = Resolve-ConnectWindowsGitHubToken -Supplied $GitHubToken
    $global:SingBoxConnectReadCache = @{}
    Assert-ConnectWindowsGitHubBudget
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
    # Exact Git merge and candidate tree are reused by nested verification.
    $mergeCommit = Invoke-GitHubJsonGet -Uri ("https://api.github.com/repos/iamaman11/sing-box/git/commits/" + [string]$branch.commit.sha)
    $parents = @($mergeCommit.parents)
    if ($parents.Count -ne 2 -or [string]$parents[1].sha -cnotmatch '^[0-9a-f]{40}$') {
        throw 'WINDOWS_CONNECT_GITHUB_CANDIDATE_SOURCE_UNPROVEN'
    }
    $null = Invoke-GitHubJsonGet -Uri ("https://api.github.com/repos/iamaman11/sing-box/git/commits/" + [string]$parents[1].sha)
    # The ordinary installer independently re-verifies the exact immutable
    # release tag, candidate source/tree, ZIP and files before native BEGIN.
    Assert-AcceptedReleaseAuthority -AcceptedRevision ([string]$branch.commit.sha) -Tag $tagName
    if (-not $hasCurrent) {
        # A clean host has no installed controller or scheduled owner yet.
        # Never overwrite an existing/partial root or foreign service.
        if (Test-Path -LiteralPath $InstallRoot) {
            throw 'WINDOWS_CONNECT_PARTIAL_ROOT_NO_REPLAY'
        }
        # Explicit named binding: an array of strings is POSITIONAL splatting
        # in PowerShell and can bind InstallRoot to a UInt64 parameter.
        $argsInitial = @{
            AcceptedRevision = [string]$branch.commit.sha
            ReleaseSetSha256 = $selectedDigest
            InstallRoot = $InstallRoot
            Offline = $true
            GitHubToken = $GitHubToken
        }
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
    Assert-RootExecutionChain -ApproveRepair:$ApproveAclRepair
    Assert-ExistingNativeReleaseFromProtectedGit
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
            [string]$state.machine_id -cnotmatch '^(UNREGISTERED|[a-z][a-z0-9-]{0,39})$' -or
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
    $argsExact = @{
        AcceptedRevision = [string]$branch.commit.sha
        ReleaseSetSha256 = $selectedDigest
        InstallRoot = $InstallRoot
        Offline = $true
        BootstrapNow = $true
        EnrollReceipt = $true
        GitHubToken = $GitHubToken
    }
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
        $argsExact['RetainedIntentSha256'] = $oldDigest
        $argsExact['ExpectedCurrentReleaseSetSha256'] = [string]$installed['release_set_sha256']
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
if ($ApproveAclRepair) {
    throw 'WINDOWS_INSTALL_ACL_REPAIR_APPROVAL_REQUIRES_CONNECT_WINDOWS'
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
    # Both read-only StageOnly and the final BootstrapNow must carry the
    # SAME exact pins; a disabled task never bypasses the stage proof.
    if (-not $Offline -or (-not $BootstrapNow -and -not $StageOnly) -or
        $ForceRematerialize -or $InstallRoot -cne 'C:\sing-box') {
        throw 'OFFLINE_BOOTSTRAP_SUPERSESSION_ONLY_EXACT_OFFLINE_FIRST_USE'
    }
    Assert-HexSha256 -Value $RetainedIntentSha256 -Name 'RetainedIntentSha256'
    Assert-HexSha256 -Value $ExpectedCurrentReleaseSetSha256 -Name 'ExpectedCurrentReleaseSetSha256'
}
Assert-OfflineWindow

$binDir = Join-Path $InstallRoot "bin"
$releasesDir = Join-Path $InstallRoot "releases"
$currentPath = Join-Path $InstallRoot "current.pb"
$previousPath = Join-Path $InstallRoot "previous.pb"
Assert-HexSha256 -Value $ReleaseSetSha256 -Name "ReleaseSetSha256"
$tag = "edge-release-$ReleaseSetSha256"
Assert-AcceptedReleaseAuthority -AcceptedRevision $AcceptedRevision -Tag $tag -ArchivedAcceptanceSourceRunId $ArchivedAcceptanceSourceRunId
# Before any downloaded verifier or installed console is executed: the root
# must be protected. Existing unsafe roots require the explicit ConnectWindows
# repair scope; fresh roots are protected before materializing release files.
if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Assert-RootExecutionChain -CreateFresh
} else {
    Assert-RootExecutionChain
}
# Directories are created only after the protected root has been proven or
# provisioned. Creating them first could inherit writable volume-root ACEs.
New-Item -ItemType Directory -Force -Path $binDir, $releasesDir | Out-Null
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
    # Never execute downloaded verifier binaries from a user-writable TEMP.
        $stage = Join-Path $InstallRoot (".release-stage-" + [guid]::NewGuid().ToString("N"))
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

        Protect-ReleaseStageBeforeExecution -Stage $stage
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
        # The new immutable release tree must be protected before native code
        # is executed from it, even if the old root was previously unsafe.
        Protect-ReleaseStageBeforeExecution -Stage $releaseStage
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
    # For one separately approved distinct successor, a compensated UNKNOWN
    # may have left this SAME exact LocalSystem task Disabled. The old BEGIN
    # must be pinned, canonical and bound to this installed owner; neither
    # the same attempted ReleaseSet nor the same revision may be replayed.
    $disabledSuccessorProven = $false
    if ($hasRetained -and [string]$dispatch.State -ceq 'Disabled') {
        if ([string]$old['release_set_sha256'] -cne $ExpectedCurrentReleaseSetSha256) {
            throw 'OFFLINE_BOOTSTRAP_DISABLED_PREDECESSOR_RELEASE_MISMATCH'
        }
        $retainedPath = Join-Path $InstallRoot 'offline-bootstrap-intent-v1'
        $retainedFile = Get-Item -LiteralPath $retainedPath -Force -ErrorAction Stop
        if ($retainedFile.PSIsContainer -or
            ($retainedFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $retainedFile.Length -lt 1 -or $retainedFile.Length -gt 512) {
            throw 'OFFLINE_BOOTSTRAP_DISABLED_PREDECESSOR_NOT_REGULAR'
        }
        $retainedBytes = [IO.File]::ReadAllBytes($retainedPath)
        if ($retainedBytes.Length -ne $retainedFile.Length -or
            (Get-FileHash -LiteralPath $retainedPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $RetainedIntentSha256) {
            throw 'OFFLINE_BOOTSTRAP_DISABLED_PREDECESSOR_SHA_MISMATCH'
        }
        $retainedText = [Text.UTF8Encoding]::new($false, $true).GetString($retainedBytes)
        $retainedMatch = [regex]::Match(
            $retainedText,
            '\Aschema=sing-box\.windows-offline-bootstrap/v1\nfrom=(?<from>[0-9a-f]{64})\nto=(?<to>[0-9a-f]{64})\naccepted_revision=(?<revision>[0-9a-f]{40})\n\z'
        )
        if (-not $retainedMatch.Success) {
            throw 'OFFLINE_BOOTSTRAP_DISABLED_PREDECESSOR_NOT_DISTINCT_NO_REPLAY'
        }
        Assert-DisabledOfflineSuccessorIdentity `
            -RetainedFrom $retainedMatch.Groups['from'].Value `
            -RetainedTo $retainedMatch.Groups['to'].Value `
            -RetainedRevision $retainedMatch.Groups['revision'].Value `
            -InstalledRelease ([string]$old['release_set_sha256']) `
            -NextRelease $ReleaseSetSha256 `
            -NextRevision $AcceptedRevision
        $disabledSuccessorProven = $true
    }
    if ($principalSid -cne 'S-1-5-18' -or
        ([string]$dispatch.State -cne 'Ready' -and -not $disabledSuccessorProven) -or
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
