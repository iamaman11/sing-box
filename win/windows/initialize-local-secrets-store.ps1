[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$VultrApiKey,
    [Parameter(Mandatory)] [string]$CloudflareApiToken,
    [string]$StorePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $StorePath) {
    $StorePath = Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA 'sing-box-vultr-dual') 'secrets') 'local-secrets.clixml'
}

$payload = [pscustomobject]@{
    VULTR_API_KEY = ConvertTo-SecureString $VultrApiKey -AsPlainText -Force
    CLOUDFLARE_API_TOKEN = ConvertTo-SecureString $CloudflareApiToken -AsPlainText -Force
}

$directory = Split-Path -Parent $StorePath
if (-not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$payload | Export-Clixml -LiteralPath $StorePath
Write-Host "Secret store written: $StorePath"
