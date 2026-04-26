[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ProcessName,
    [string]$ConfigPath = '',
    [string]$SingBoxPath = 'V:\code\sing-box-cl\auto-route-sing-box\sing-box.exe',
    [switch]$RestartSingBox
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'edge-dns-clean-vultr-dual.json' }

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}

$json = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

$processRule = $json.route.rules | Where-Object {
    $_.process_name -and ($_.outbound -eq 'proxy-selector')
} | Select-Object -First 1

if (-not $processRule) {
    throw 'Could not find process_name rule for proxy-selector.'
}

$names = [System.Collections.Generic.List[string]]::new()
foreach ($name in $processRule.process_name) {
    [void]$names.Add([string]$name)
}

if ($names -contains $ProcessName) {
    Write-Host "Already present: $ProcessName"
} else {
    [void]$names.Add($ProcessName)
    $processRule.process_name = $names.ToArray()
    [System.IO.File]::WriteAllText($ConfigPath, ($json | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
    Write-Host "Added: $ProcessName"
}

if ($RestartSingBox) {
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -ieq 'sing-box.exe' -and
            $_.ExecutablePath -eq $SingBoxPath
        } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force
        }

    Start-Process -FilePath $SingBoxPath -ArgumentList @('run', '-c', $ConfigPath)
    Write-Host 'sing-box restarted'
}
