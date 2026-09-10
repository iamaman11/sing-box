param(
    [string]$RepoRoot = "C:\Users\Bose\temp\sing-box",
    [string]$VaultRecord = "edge.proxy-credentials-v1",
    [string]$WslDistribution = "Ubuntu",
    [string]$VaultPath = "/home/bose/projects/secret-vault/bin/secret-vault"
)

$ErrorActionPreference = "Stop"
$writer = Join-Path $PSScriptRoot "write-proxy-credentials-dpapi.ps1"
if (-not (Test-Path -LiteralPath $writer)) { throw "DPAPI writer is missing: $writer" }

# WSL standard input/interoperability is disabled on this host. Use a unique
# temporary file protected by an ACL for the current Windows SID, then erase
# it in finally. No plaintext is placed in the repository or command args.
$temporary = Join-Path $env:TEMP "edge-platform-proxy-vault-transfer.tmp"
Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue
New-Item -ItemType File -Path $temporary -Force | Out-Null
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($sid)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, "FullControl", "Allow")))
Set-Acl -LiteralPath $temporary -AclObject $acl
try {
    if ($temporary -ne "C:\Users\Bose\AppData\Local\Temp\edge-platform-proxy-vault-transfer.tmp") {
        throw "The protected WSL transfer path is unavailable on this machine: $temporary"
    }
    & wsl.exe -d $WslDistribution -- $VaultPath run $VaultRecord EDGE_PROXY_CREDENTIALS -- `
        python3 -c 'import os; open("/mnt/c/Users/Bose/AppData/Local/Temp/edge-platform-proxy-vault-transfer.tmp", "w", encoding="utf-8").write(os.environ["EDGE_PROXY_CREDENTIALS"])'
    if ($LASTEXITCODE -ne 0) { throw "Vault read failed (exit $LASTEXITCODE)" }
    if ((Get-Item -LiteralPath $temporary).Length -eq 0) { throw "Vault returned an empty proxy credential record" }
    & $writer -RepoRoot $RepoRoot -InputPath $temporary
} finally {
    if (Test-Path -LiteralPath $temporary) {
        $length = (Get-Item -LiteralPath $temporary).Length
        if ($length -gt 0) { [IO.File]::WriteAllBytes($temporary, (New-Object byte[] $length)) }
        Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue
    }
}
