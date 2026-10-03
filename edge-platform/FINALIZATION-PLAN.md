# edge-platform Finalization Plan — historical tombstone

> **SUPERSEDED / DO NOT EXECUTE**
>
> This file intentionally contains no executable plan. It exists only so historical links fail safe.

## Current authority

Use this order and nothing else:

1. fresh protected `main`, open PRs and latest Actions;
2. GitHub Issue #26 — **sole living execution cursor**;
3. latest comments/evidence on #26 when newer than its body;
4. `edge-platform/ARCHITECTURE.md` — stable target ownership and invariants, not execution order;
5. issue #169 — historical Cloudflare convergence/retirement evidence only; it is no longer a
   current Stage-3 execution dependency;
6. issue #154 — Windows implementation/evidence record;
7. issue #60 — Windows diagnostics specification;
8. issue #1 — canonical operator command channel.

No historical issue or document may become a competing execution cursor.

## Direction

The target architecture is deletion-first:

- GitHub-only `edge-orchestrator` owns provider composition;
- Windows owns only Windows-local runtime through SCM `EdgePlatformController`;
- the production VM uses one bounded local Linux runtime owner;
- self-hosted runners are outbound transport only;
- credential delivery is fixed A/B least-privilege projection with host-local acquisition;
- duplicate operator namespaces, remote-agent trust/transport, obsolete provider responsibilities,
  legacy persistence and migration proof glue are removed after their exact last consumer disappears.

Do not restore historical designs in which Windows owns Vultr/Cloudflare deployment, a network
`edge-agent` is routine production control, secrets are copied through runners, or old JSON/state
contracts become authority.

For the current macro stage and exact next action, read #26.
