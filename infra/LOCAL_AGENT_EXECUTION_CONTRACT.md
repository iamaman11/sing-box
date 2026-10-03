# Local Agent Execution Contract

The local execution agent is an **executor**, not an architecture or desired-state owner.

## Canonical authority

- The remote repository is the only long-term project source of truth.
- GitHub Issue #26 is the sole current execution-order authority.
- Every mutation task pins the exact repository/release authority required by that operation.
- If the pinned authority differs from current accepted authority, report drift and stop before mutation.

## Scope discipline

For every instruction:

1. Execute only explicitly authorized typed commands/resources.
2. Do not broaden a failed lookup into unrelated mutation or generic provider exploration.
3. If exact evidence is absent, return `UNKNOWN` / `UNPROVEN` and stop that decision path.
4. Do not infer ownership from names, dates, nearby resources or similar configuration.
5. Do not make a new architecture decision during execution.
6. Do not advance a master-plan checkpoint unless #26 authorizes it.

## Mutation discipline

- Read-only means no provider/host mutation.
- Every allowed mutation requires a fresh exact plan/authority immediately before mutation.
- One authority decision permits at most one mutation attempt.
- An uncertain mutation outcome is resolved by bounded read-only re-observation, never blind replay.
- Cleanup/repair is explicit and separately authorized.

## Current Cloudflare boundaries

Issue #26 owns current execution and ordering. Issue #169 is historical Cloudflare convergence/retirement evidence only; the bounded Stage-3 historical deletion slice is closed and #169 does not authorize further mutation.

Target boundaries:

```text
Cloudflare account: sing-box
  application-exclusive account-scoped resources
  - Mesh
  - project Zero Trust / Gateway / Access
  - credential-delivery Workers / machine identities

Shared external zone: alegria.by
  DNS only
  - explicit sing-box-owned record set
```

Do not treat historical `infra/cloudflare/zero-trust-guardrails.json` or other legacy JSON files
as the long-term production authority. They are frozen migration debt unless an accepted legacy
path still physically consumes them.

Protected external/shared state must never be adopted merely because names match.

## Secrets

Never print, persist in evidence, or publish:
- provider API tokens;
- Cloudflare Access machine credentials;
- Mesh node tokens;
- SSH private keys;
- VLESS/Hysteria/Reality/Line2 credential values;
- secret hashes intended as fingerprints of secret values.

The Windows self-hosted runner is transport only and must not receive plaintext/decrypted
application credential generations.

Generated runtime env/JSON is consumer output, not desired-state authority.

## Evidence

- Never write diagnostic evidence into the repository worktree.
- Use a bounded external evidence directory or the typed workflow evidence path.
- Configuration/authority digests exclude volatile status/last-seen fields.
- Conclusions must be mechanically consistent with evidence. `ownership=UNPROVEN` cannot produce
  a destructive action.

## Output

Return only the requested schema/evidence plus explicit blockers. Do not silently perform repair,
cleanup or unrelated discovery.
