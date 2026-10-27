[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AcceptedRevision,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseSetSha256,
    [string]$RunnerRoot = "C:\sing-box-runner",
    [string]$ApplicationRoot = "C:\sing-box",
    [string]$RunnerName = "",
    [string]$HostId = "",
    # Narrow one-time SYSTEM task repair on an ALREADY INSTALLED exact release.
    # Requires local interactive Administrator; does not install or update
    # application, credential identity, GitHub runner, SCM, TUN or network.
    [switch]$RepairPrivilegedTaskOnly,
    [string]$ExpectedInstalledReleaseSetSha256 = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$Repository = "iamaman11/sing-box"
$RunnerVersion = "2.337.0"
$RunnerAsset = "actions-runner-win-x64-$RunnerVersion.zip"
$RunnerSha256 = "1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc"
$RunnerUrl = "https://github.com/actions/runner/releases/download/v$RunnerVersion/$RunnerAsset"
$RunnerLabel = "sing-box-windows-lab"
if ($HostId) {
    if ($HostId -cnotmatch '^[a-z][a-z0-9-]{0,39}$') {
        throw "HostId must be a stable Git-owned lower-case host identifier"
    }
    $RunnerLabel = "$RunnerLabel,sing-box-host-$HostId"
}
$PrivilegedTaskName = "EdgePlatformPrivilegedDispatch"
$SystemSid = "S-1-5-18"
$NetworkServiceSid = "S-1-5-20"
$RunnerServiceAccount = ([Security.Principal.SecurityIdentifier]::new($NetworkServiceSid)).Translate([Security.Principal.NTAccount]).Value

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this bootstrap once from an elevated PowerShell session"
    }
}

function Resolve-IdentitySid {
    param([Parameter(Mandatory)] [string]$Identity)
    if ($Identity -match "^S-1-") {
        return [Security.Principal.SecurityIdentifier]::new($Identity).Value
    }
    return ([Security.Principal.NTAccount]::new($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-IsolatedRoots {
    $runner = [IO.Path]::GetFullPath($RunnerRoot).TrimEnd("\")
    $application = [IO.Path]::GetFullPath($ApplicationRoot).TrimEnd("\")
    if ($runner -ieq $application) { throw "Runner root and application root must be different" }
    if ($runner.StartsWith($application + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Runner transport must not live inside the application root"
    }
    if ($application.StartsWith($runner + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Application root must not live inside the runner root"
    }
    if ($application -ine "C:\sing-box") {
        throw "Application root must be exactly C:\sing-box during Slice 2"
    }
}

function Assert-MainProtected {
    if ($AcceptedRevision -notmatch "^[0-9a-f]{40}$") {
        throw "AcceptedRevision must be an exact lowercase Git commit"
    }
    if ($ReleaseSetSha256 -notmatch "^[0-9a-f]{64}$") {
        throw "ReleaseSetSha256 must be an exact lowercase SHA-256 digest"
    }
    $headers = @{
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent" = "sing-box-windows-runner-bootstrap"
    }
    $branch = Invoke-RestMethod -Method Get -Uri "https://api.github.com/repos/$Repository/branches/main" -Headers $headers
    if (-not [bool]$branch.protected) {
        throw "Refusing physical runner registration: GitHub main is not protected"
    }
    if ([string]$branch.commit.sha -ne $AcceptedRevision) {
        throw "AcceptedRevision is not the current protected main"
    }
}

function Install-InitialApplicationAuthority {
    $tempRoot = Join-Path $env:TEMP ("sing-box-trust-anchor-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    try {
        $installer = Join-Path $tempRoot "install-windows-release.ps1"
        $uri = "https://raw.githubusercontent.com/$Repository/$AcceptedRevision/edge-platform/scripts/install-windows-release.ps1"
        Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $installer
        & $installer `
            -AcceptedRevision $AcceptedRevision `
            -ReleaseSetSha256 $ReleaseSetSha256 `
            -InstallRoot $ApplicationRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Initial exact ReleaseSet activation failed"
        }

        $bootstrapDir = Join-Path $ApplicationRoot "bootstrap"
        New-Item -ItemType Directory -Force -Path $bootstrapDir | Out-Null
        Copy-Item -LiteralPath $installer -Destination (Join-Path $bootstrapDir "install-windows-release.ps1") -Force
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-CredentialAccessIdentity {
    $secretDir = Join-Path $ApplicationRoot "state\secrets"
    $identityPath = Join-Path $secretDir "credential-access-v1.env"
    if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
        return
    }

    $clientId = (Read-Host "Cloudflare Access host client ID").Trim()
    if (-not $clientId -or $clientId -match "\s") {
        throw "Cloudflare Access host client ID is empty or malformed"
    }
    $secureSecret = Read-Host "Cloudflare Access host client secret" -AsSecureString
    if ($secureSecret.Length -eq 0) {
        throw "Cloudflare Access host client secret is required"
    }

    $bstr = [IntPtr]::Zero
    $plainSecret = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
        $plainSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if (-not $plainSecret -or $plainSecret -match "\s") {
            throw "Cloudflare Access host client secret is malformed"
        }
        if (-not (Test-Path -LiteralPath $secretDir -PathType Container)) {
            throw "Controller-owned Windows secret directory is not converged"
        }

        $stage = "$identityPath.new"
        [IO.File]::WriteAllText(
            $stage,
            "CF_ACCESS_CLIENT_ID=$clientId`nCF_ACCESS_CLIENT_SECRET=$plainSecret`n",
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $stage -Destination $identityPath -Force
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainSecret = $null
        $secureSecret.Dispose()
    }
}

function Converge-ControllerService {
    $console = Join-Path $ApplicationRoot "releases\$ReleaseSetSha256\bin\edge-console.exe"
    if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
        throw "Exact immutable controller authority console is missing: $console"
    }
    & $console privileged-converge-controller-service --install-root $ApplicationRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Native Windows controller service convergence failed"
    }
}


function Assert-ExactPrivilegedDispatcher {
    param([Parameter(Mandatory)][string]$Console)
    $task = Get-ScheduledTask -TaskName $PrivilegedTaskName -ErrorAction Stop
    $sid = Resolve-IdentitySid -Identity ([string]$task.Principal.UserId)
    if ($sid -cne $SystemSid -or
        [string]$task.Principal.LogonType -cne 'ServiceAccount' -or
        [string]$task.Principal.RunLevel -cne 'Highest' -or
        $task.State -cnotin @('Ready','Running') -or
        @($task.Actions).Count -ne 1 -or
        [string]@($task.Actions)[0].Execute.Trim('"') -ine $Console -or
        [string]@($task.Actions)[0].Arguments -cnotmatch '^privileged-dispatch --install-root "?C:\\sing-box"?$') {
        throw 'WINDOWS_FIRST_USE_SYSTEM_TASK_IDENTITY_INVALID'
    }
}
function Register-PrivilegedDispatcher {
    param(
        [string]$ExactInstalledReleaseSetSha256 = $ReleaseSetSha256,
        [switch]$CreateOnly
    )
    $console = Join-Path $ApplicationRoot "releases\$ExactInstalledReleaseSetSha256\bin\edge-console.exe"
    if (-not (Test-Path -LiteralPath $console -PathType Leaf)) {
        throw "Exact immutable privileged console is missing: $console"
    }

    $action = New-ScheduledTaskAction `
        -Execute $console `
        -Argument ('privileged-dispatch --install-root "' + $ApplicationRoot + '"')
    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At ((Get-Date).AddMinutes(1)) `
        -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal `
        -UserId $SystemSid `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -StartWhenAvailable

    $register = @{
        TaskName = $PrivilegedTaskName
        Action = $action
        Trigger = $trigger
        Principal = $principal
        Settings = $settings
        ErrorAction = 'Stop'
    }
    # This first-use repair NEVER overwrites an existing SYSTEM task. If the
    # task appears between preflight and registration, fail closed.
    if (-not $CreateOnly) { $register.Force = $true }
    Register-ScheduledTask @register | Out-Null
    Assert-ExactPrivilegedDispatcher -Console $console
}
function Get-RunnerService {
    $serviceMarker = Join-Path $RunnerRoot ".service"
    $runnerMarker = Join-Path $RunnerRoot ".runner"
    $hasService = Test-Path -LiteralPath $serviceMarker -PathType Leaf
    $hasRunner = Test-Path -LiteralPath $runnerMarker -PathType Leaf
    if ($hasService -ne $hasRunner) {
        throw "Runner configuration markers are inconsistent; refusing implicit repair"
    }
    if (-not $hasService) { return $null }
    $serviceName = (Get-Content -LiteralPath $serviceMarker -Raw).Trim()
    if (-not $serviceName) { throw "Runner service marker is empty" }
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $service) { throw "Configured runner service was not found: $serviceName" }
    if ((Resolve-IdentitySid -Identity ([string]$service.StartName)) -ne $NetworkServiceSid) {
        throw "Configured runner service must run as NetworkService SID"
    }
    return $service
}

function Install-RunnerFiles {
    New-Item -ItemType Directory -Force -Path $RunnerRoot | Out-Null
    $config = Join-Path $RunnerRoot "config.cmd"
    if (Test-Path -LiteralPath $config -PathType Leaf) { return }

    $tempRoot = Join-Path $env:TEMP ("sing-box-runner-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    try {
        $archive = Join-Path $tempRoot $RunnerAsset
        Invoke-WebRequest -UseBasicParsing -Uri $RunnerUrl -OutFile $archive
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
        if ($actual -ne $RunnerSha256) { throw "GitHub Actions Runner SHA-256 mismatch" }
        Expand-Archive -LiteralPath $archive -DestinationPath $RunnerRoot -Force
        if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
            throw "Runner archive did not provide config.cmd"
        }
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Register-Runner {
    $config = Join-Path $RunnerRoot "config.cmd"
    if (-not $RunnerName) { $script:RunnerName = "sing-box-" + $env:COMPUTERNAME.ToLowerInvariant() }

    Write-Host "Open GitHub repository Settings > Actions > Runners > New self-hosted runner."
    Write-Host "Paste only the short-lived registration token. It is not stored."
    $secureToken = Read-Host "GitHub runner registration token" -AsSecureString
    if ($secureToken.Length -eq 0) { throw "Runner registration token is required" }

    $bstr = [IntPtr]::Zero
    $plainToken = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        Push-Location $RunnerRoot
        try {
            & $config `
                --unattended `
                --url "https://github.com/$Repository" `
                --token $plainToken `
                --name $RunnerName `
                --labels $RunnerLabel `
                --work "_work" `
                --runasservice `
                --windowslogonaccount $RunnerServiceAccount
            if ($LASTEXITCODE -ne 0) { throw "GitHub Actions Runner registration failed" }
        } finally {
            Pop-Location
        }
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainToken = $null
        $secureToken.Dispose()
    }
}

Assert-Administrator
Assert-IsolatedRoots
Assert-MainProtected
if ($RepairPrivilegedTaskOnly) {
    # Reuse the existing bootstrap function, but constrain it to the ONLY
    # missing privileged task. No installed ReleaseSet is replaced.
    if ($ExpectedInstalledReleaseSetSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'WINDOWS_FIRST_USE_INSTALLED_RELEASE_REQUIRED'
    }
    $headers = @{
        Accept = 'application/vnd.github+json'
        'User-Agent' = 'sing-box-windows-task-first-use'
    }
    $published = Invoke-RestMethod -Method Get `
        -Uri "https://api.github.com/repos/$Repository/releases/tags/edge-release-$ReleaseSetSha256" `
        -Headers $headers -ErrorAction Stop
    if ([string]$published.target_commitish -cne $AcceptedRevision -or
        [bool]$published.draft -or [bool]$published.prerelease -or
        @($published.assets | Where-Object { $_.name -eq 'release-set.pb' }).Count -ne 1) {
        throw 'WINDOWS_FIRST_USE_CANONICAL_RELEASE_UNPROVEN'
    }
    $root = [IO.Path]::GetFullPath($ApplicationRoot).TrimEnd('\')
    $doctor = Join-Path $root 'bin\edge-diagnostic.exe'
    $current = Join-Path $root 'current.pb'
    if (-not (Test-Path -LiteralPath $doctor -PathType Leaf) -or
        -not (Test-Path -LiteralPath $current -PathType Leaf)) {
        throw 'WINDOWS_FIRST_USE_INSTALLED_DOCTOR_MISSING'
    }
    $v = @{}
    $raw = @(& $doctor doctor $current)
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_FIRST_USE_INSTALLED_DOCTOR_FAILED' }
    foreach ($row in $raw) {
        $pair = ([string]$row).Split('=',2)
        if ($pair.Count -eq 2) { $v[$pair[0]] = $pair[1] }
    }
    if ([string]$v['exact_release_files'] -cne 'PASS' -or
        [string]$v['release_set_sha256'] -cne $ExpectedInstalledReleaseSetSha256 -or
        [string]$v['windows_datapath_mode'] -cne 'ProxyOnly' -or
        [string]$v['scm_state'] -cne 'Stopped' -or
        [string]$v['scm_start_type'] -cne 'OnDemand' -or
        [string]$v['managed_tun_present'] -cne 'false' -or
        [string]$v['managed_singbox_process_count'] -cne '0' -or
        [string]$v['orphan_singbox_process_count'] -cne '0' -or
        [string]$v['conflicting_singbox_process_count'] -cne '0' -or
        [string]$v['unknown_singbox_process_count'] -cne '0') {
        throw 'WINDOWS_FIRST_USE_STABLE_STOPPED_OWNER_REQUIRED'
    }
    $console = Join-Path $root "releases\$ExpectedInstalledReleaseSetSha256\bin\edge-console.exe"
    if ([string]$v['console_path'] -ine $console -or
        -not (Test-Path -LiteralPath $console -PathType Leaf) -or
        ((Get-Item -LiteralPath $console).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'WINDOWS_FIRST_USE_IMMUTABLE_CONSOLE_UNPROVEN'
    }
    $bootstrapInstaller = Join-Path $root 'bootstrap\install-windows-release.ps1'
    if (-not (Test-Path -LiteralPath $bootstrapInstaller -PathType Leaf) -or
        ((Get-Item -LiteralPath $bootstrapInstaller).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'WINDOWS_FIRST_USE_OFFLINE_INSTALLER_PREREQUISITE_MISSING'
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='EdgePlatformController'" -ErrorAction Stop
    if ($null -eq $service -or [string]$service.State -cne 'Stopped' -or
        [string]$service.StartMode -cne 'Manual') {
        throw 'WINDOWS_FIRST_USE_SCM_STOPPED_MANUAL_REQUIRED'
    }
    $runnerService = Get-RunnerService
    if ($null -eq $runnerService -or [string]$runnerService.State -cne 'Running') {
        throw 'WINDOWS_FIRST_USE_NETWORKSERVICE_RUNNER_UNPROVEN'
    }

    $existing = Get-ScheduledTask -TaskName $PrivilegedTaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Assert-ExactPrivilegedDispatcher -Console $console
        Write-Output 'windows_privileged_task_first_use=NOOP_EXISTING_EXACT'
    } else {
        Register-PrivilegedDispatcher -ExactInstalledReleaseSetSha256 $ExpectedInstalledReleaseSetSha256 -CreateOnly
        Write-Output 'windows_privileged_task_first_use=CREATED_SYSTEM_OWNER_ONLY'
    }
    # Physical native re-observation; unknown poststate is NOT retried.
    $after = @{}
    foreach ($row in @(& $doctor doctor $current)) {
        $pair = ([string]$row).Split('=',2)
        if ($pair.Count -eq 2) { $after[$pair[0]] = $pair[1] }
    }
    if ($LASTEXITCODE -ne 0 -or
        [string]$after['release_set_sha256'] -cne $ExpectedInstalledReleaseSetSha256 -or
        [string]$after['scm_state'] -cne 'Stopped' -or
        [string]$after['managed_tun_present'] -cne 'false') {
        throw 'WINDOWS_FIRST_USE_TASK_POSTSTATE_UNKNOWN_NO_REPLAY'
    }
    Assert-ExactPrivilegedDispatcher -Console $console
    Write-Output 'windows_privileged_task_authority=LOCALSYSTEM_SID_18'
    Write-Output 'windows_privileged_task_release_unchanged=true'
    Write-Output 'windows_privileged_task_scm_unchanged=Stopped'
    Write-Output 'windows_privileged_task_tun_dns_route_mutations=0'
    return
}
if ($ExpectedInstalledReleaseSetSha256) {
    throw 'WINDOWS_FIRST_USE_INSTALLED_RELEASE_ONLY_VALID_FOR_TASK_REPAIR'
}
Install-InitialApplicationAuthority
Converge-ControllerService
Install-CredentialAccessIdentity
Register-PrivilegedDispatcher

$service = Get-RunnerService
if (-not $service) {
    Install-RunnerFiles
    Register-Runner
    $service = Get-RunnerService
}
if (-not $service) { throw "Runner registration completed without a valid service" }

$serviceName = [string]$service.Name
Set-Service -Name $serviceName -StartupType Automatic
Start-Service -Name $serviceName
$started = Get-Service -Name $serviceName
if ($started.Status -ne "Running") {
    throw "GitHub Actions Runner service did not enter Running state"
}

Write-Output "status=PASS"
Write-Output "runner_root=$RunnerRoot"
Write-Output "application_root=$ApplicationRoot"
Write-Output "runner_label=$RunnerLabel"
Write-Output "windows_host_id=$HostId"
Write-Output "runner_service=$serviceName"
Write-Output "runner_identity_sid=$NetworkServiceSid"
Write-Output "runner_update_policy=github_auto"
Write-Output "accepted_revision=$AcceptedRevision"
Write-Output "release_set_sha256=$ReleaseSetSha256"
Write-Output "privileged_task=$PrivilegedTaskName"
Write-Output "privileged_identity=SYSTEM"
Write-Output "runner_application_access=TRANSPORT_ONLY"
Write-Output "controller_service=EdgePlatformController"
Write-Output "controller_start_owner=windows_scm"
Write-Output "secret_authority=controller_service"
Write-Output "local_build_toolchain_installed=false"
Write-Output "provider_credentials_installed=false"
Write-Output "credential_access_identity_installed=true"
Write-Output "runner_credential_access=false"
