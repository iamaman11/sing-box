param(
    [string]$LogPath = "C:\Users\Bose\temp\sing-box.log",
    [string]$StatePath = "C:\Users\Bose\temp\sing-box\edge-platform\.runtime\singbox-log-cleanup.json",
    [switch]$IfDue
)

$ErrorActionPreference = "Stop"

# sing-box opens this output in append mode. Truncating the active file keeps
# the same handle usable and avoids a restart, archive growth, or packet loss.
if ($IfDue -and (Test-Path -LiteralPath $StatePath)) {
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    $rawLast = [string]$state.cleared_at_utc
    $last = [DateTimeOffset]::MinValue
    $parsed = [DateTimeOffset]::TryParse(
        $rawLast,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$last
    )
    if (!$parsed) {
        $parsed = [DateTimeOffset]::TryParse(
            $rawLast,
            [Globalization.CultureInfo]::GetCultureInfo("en-US"),
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$last
        )
    }
    if ($parsed -and ([DateTimeOffset]::UtcNow - $last).TotalHours -lt 48) { exit 0 }
}
if (Test-Path -LiteralPath $LogPath) {
    Clear-Content -LiteralPath $LogPath -Force
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $StatePath) | Out-Null
@{ cleared_at_utc = [DateTimeOffset]::UtcNow.ToString("o") } | ConvertTo-Json -Compress | Set-Content -LiteralPath $StatePath -NoNewline
