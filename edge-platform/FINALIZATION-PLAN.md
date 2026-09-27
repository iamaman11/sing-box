# edge-platform Finalization Plan — historical

> **SUPERSEDED / DO NOT EXECUTE**
>
> This file is retained only so old links fail safely. Its original finalization model is no longer
> current and must not be used as an implementation checklist.

Current authority:
- GitHub Issue #26 — sole living execution cursor;
- `edge-platform/ARCHITECTURE.md` — current ownership/invariant model;
- GitHub Issue #169 — active bounded Cloudflare/credential convergence plan when selected by #26;
- GitHub Issue #154 — Windows Slice 2 implementation/evidence record;
- GitHub Issue #60 — Windows diagnostics specification.

In particular, do **not** restore the historical model in which the installed Windows
`edge-controller` owns Vultr/Cloudflare deployment, remote agent trust, SecretRef storage or
global production orchestration.

The current direction is deletion-first: provider/production ownership belongs to the GitHub-only
`edge-orchestrator`; Windows owns only Windows-local runtime; VM `edge-agent` is bounded and
loopback-only in canonical production.
