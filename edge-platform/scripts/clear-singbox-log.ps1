param(
    [string]$LogPath = "C:\Users\Bose\temp\sing-box.log"
)

$ErrorActionPreference = "Stop"

# sing-box opens this output in append mode. Truncating the active file keeps
# the same handle usable and avoids a restart, archive growth, or packet loss.
if (Test-Path -LiteralPath $LogPath) {
    Clear-Content -LiteralPath $LogPath -Force
}
