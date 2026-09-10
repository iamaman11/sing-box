param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [Parameter(Mandatory = $true)]
    [string]$DeploymentLabel,
    [string]$VaultRecord = "edge.proxy-credentials-v1",
    [string]$WslDistribution = "Ubuntu",
    [string]$VaultPath = "/home/bose/projects/secret-vault/bin/secret-vault"
)

$ErrorActionPreference = "Stop"
$source = Join-Path $RepoRoot "edge-platform\.runtime\generated\$DeploymentLabel\stack\.env.runtime"
if (-not (Test-Path -LiteralPath $source)) { throw "Runtime credential source is absent: $source" }

$values = @{}
Get-Content -LiteralPath $source | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $values[$Matches[1]] = $Matches[2] }
}
$username = [string]$values['PROXY_USERNAME']
$password = [string]$values['PROXY_PASSWORD']
if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
    throw "Runtime credential source lacks PROXY_USERNAME or PROXY_PASSWORD"
}

# The file exists only for the transfer from Windows to the WSL Vault. Its ACL
# permits the current Windows SID only, it is overwritten, and removed in
# finally. It is never created under the repository.
$temporary = [IO.Path]::GetTempFileName()
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($sid)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, "FullControl", "Allow")))
Set-Acl -LiteralPath $temporary -AclObject $acl
try {
    $document = [ordered]@{
        schema_version = 1
        username = $username
        password = $password
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        source = "active-deployment:$DeploymentLabel"
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($temporary, $document, [Text.UTF8Encoding]::new($false))
    if ($temporary -notmatch '^([A-Za-z]):\\(.*)$') { throw "Unsupported temporary path: $temporary" }
    $wslTemporary = "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2] -replace '\\', '/')"
    & wsl.exe -d $WslDistribution -- $VaultPath put $VaultRecord `
        --provider local `
        --scope "sing-box proxy client credentials; six HTTP/SOCKS5/HTTPS profiles" `
        --expires-at "2027-09-08T23:59:59Z" `
        --note "authoritative record; mirror is DPAPI-protected on Windows" `
        --replace --file $wslTemporary
    if ($LASTEXITCODE -ne 0) { throw "Vault write failed (exit $LASTEXITCODE)" }
} finally {
    if (Test-Path -LiteralPath $temporary) {
        $length = (Get-Item -LiteralPath $temporary).Length
        if ($length -gt 0) { [IO.File]::WriteAllBytes($temporary, (New-Object byte[] $length)) }
        Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue
    }
}

Write-Output "Current proxy credentials are stored in Vault"
