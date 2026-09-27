# WSL historical reference

This directory contains historical material from the older Ubuntu-side sing-box/transparent-routing
model.

It is **not** a current runbook and does not define supported Windows/WSL production behavior.

## Historical scope

Material here may describe:
- Linux-side sing-box;
- Linux-side TUN/systemd routing;
- the earlier Windows WSL mixed-proxy bridge;
- old selector names/ports;
- old debug binary paths.

Keep it only for migration archaeology until the corresponding legacy files are deleted.

## Current authority

For current Windows architecture and operational commands use:
- GitHub Issue #26 — execution cursor;
- `edge-platform/ARCHITECTURE.md`;
- `win/docs/LOCAL-ARCHITECTURE.md`;
- `win/docs/RUNBOOK.md`;
- Issue #154 when #26 returns to the Windows implementation slice.

Do not copy commands or paths from this directory into the new `C:\sing-box` runtime without an
explicit current design decision and acceptance test.
