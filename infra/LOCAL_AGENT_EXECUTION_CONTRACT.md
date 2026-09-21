# Local Agent Execution Contract

The local agent is an **executor**, not a researcher or architect.

## Canonical authority

- The only project source of truth is this repository.
- Every task must pin the exact repository revision before execution.
- If the pinned revision differs from current `origin/main`, report `MAIN_DRIFT` and stop before mutation.

## Scope discipline

For every instruction:

1. Execute only the explicitly listed commands, API endpoints, files and object identifiers.
2. Do not broaden a failed lookup into generic repository, issue, commit, provider or internet research.
3. If exact evidence is absent, return `UNKNOWN` or `UNPROVEN` and stop that line of investigation.
4. Do not infer ownership from names, dates, nearby history, similar resources or keyword matches.
5. Do not make architectural decisions.
6. Do not advance to a later checkpoint without a separate instruction.

## Mutation discipline

- Read-only means no POST, PUT, PATCH, DELETE or equivalent provider mutation.
- Every allowed mutation requires an exact current plan/authority immediately before the mutation.
- One authority decision permits at most one mutation attempt.
- An uncertain outcome is resolved only by bounded read-only re-observation. Never replay a mutation because its response was lost.
- Never perform emergency cleanup unless explicitly authorized.

## Protected external state

Existing Zero Trust user devices, registrations, default/custom device profiles and pre-existing WARP Connectors are external protected state unless a canonical project spec explicitly owns them.

The current Cloudflare boundary is defined by:

`infra/cloudflare/zero-trust-guardrails.json`

The agent must not modify protected Zero Trust state merely to make the current project pass.

## Evidence

- Never write diagnostic evidence into the repository worktree.
- Use an external bounded evidence directory.
- Never print or persist provider tokens, Mesh node tokens, SSH private keys, application credentials or secret hashes.
- Configuration digests must exclude volatile observations such as status and last-seen timestamps.
- Final conclusions must be mechanically consistent with the reported fields. `ownership=UNPROVEN` cannot produce `classified=YES`.

## Output

Return only the requested schema plus explicit blockers. Do not append exploratory research, recommendations or unrelated findings unless the instruction asks for them.
