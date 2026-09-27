# Historical architecture assessment

> **ARCHIVED — NOT CURRENT PROJECT STATUS OR PLAN**
>
> The former numerical “ultimate-level” ratings and recommendations in this file were snapshots of
> an earlier PowerShell/DPAPI/workstation-owned architecture. They are intentionally removed because
> they no longer describe the accepted system and encouraged comparison against retired ownership
> boundaries.

Current sources:
- GitHub Issue #26 — sole execution cursor;
- `edge-platform/ARCHITECTURE.md` — current architecture;
- GitHub Issue #169 — Cloudflare/credential convergence;
- Issue #154 — Windows Slice 2 implementation/evidence;
- Issue #60 — Windows diagnostics specification.

Current quality criteria are concrete invariants, not a subjective numeric score:
- one owner per mutable resource class;
- build once / promote exact bytes without rebuild;
- typed desired state and lifecycle authority;
- fail closed on drift/ambiguity;
- bounded mutation + re-observation;
- independent read-only diagnostics;
- no runtime plaintext secrets in Git/GitHub evidence;
- no provider authority in installed Windows controller;
- autonomous active runtime during Cloudflare/control-plane outage;
- full typed deploy/update/rollback/recovery/cleanup lifecycle;
- deletion-first removal of legacy paths after replacement proof.

Use those criteria and live acceptance evidence rather than historical ratings.
