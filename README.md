# sing-box

Production edge networking/control-plane project.

## Canonical authority

The remote repository `https://github.com/iamaman11/sing-box` is the only long-term source of truth.

Read authority in this order:

1. **GitHub Issue #26** — sole living execution cursor and ordering authority.
2. **`edge-platform/ARCHITECTURE.md`** — current stable ownership/invariant model.
3. **GitHub Issue #169** — bounded Cloudflare account/credential convergence vertical.
4. **GitHub Issue #154** — Windows Slice 2 implementation/evidence record. It does not schedule current work.
5. **GitHub Issue #60** — bounded Windows diagnostics specification.
6. **GitHub Issue #1** — Vultr lifecycle architecture reference.
7. **Issues #2/#3/#4** — functional acceptance scopes for Lines 1/2/3.

Historical plans are never execution authority. If any document conflicts with #26, #26 wins after live repository state is re-read.

## Current architecture

```text
Git / protected main
  production.textproto + source
        |
        +------------------------------+
        |                              |
        v                              v
immutable ReleaseSet             edge-orchestrator
exact binaries/images            GitHub-only production owner
                                       |
                         +-------------+-------------+
                         |                           |
                       Vultr                     Cloudflare
                         |                 dedicated account: sing-box
                         |                 Mesh / Zero Trust / Access
                         |                 credential-delivery Workers
                         |
                    strict SSH
                    local forward
                         |
                         v
                     edge-agent
                  loopback-only VM owner
                         |
                         v
                     sing-box

Windows:
exact ReleaseSet
  -> SCM EdgePlatformController
  -> typed active/candidate local state
  -> generated sing-box JSON
  -> sing-box

Shared external boundary:
Cloudflare zone alegria.by
  -> project-owned DNS records only
```

## Ownership rules

- **Git** owns desired state and execution policy.
- **ReleaseSet** owns exact immutable release identity.
- **edge-orchestrator** owns provider/production composition.
- **Vultr/Cloudflare APIs** are observed provider state, never desired-state databases.
- **edge-agent** owns bounded VM observation/apply only; no provider authority.
- **EdgePlatformController** owns Windows-local runtime/config/lifecycle only; no provider authority.
- **edge-diagnostic** is independent, read-only diagnostics; it is not a repair owner.
- **GitHub Actions** authorize, materialize exact inputs, invoke typed owners and publish bounded evidence. YAML/shell/Python do not own domain semantics.

## Cloudflare target

All application-exclusive account-scoped Cloudflare resources converge into the dedicated account `sing-box`.

`alegria.by` deliberately remains a shared external DNS zone. DNS automation is zone-scoped and may mutate only the explicit sing-box record set.

Runtime credentials are not copied from the legacy Windows installation. The new stack gets fresh credential generations delivered through isolated Windows/VM credential projections. Cloudflare is a convergence/rotation dependency, not a runtime data-path dependency.

## Release and recovery

Normal release flow:

```text
source
 -> exact-head CI
 -> build once
 -> candidate acceptance
 -> protected merge
 -> promote exact accepted bytes without rebuild
 -> durable ReleaseSet
 -> converge / verify
```

Normal operation must preserve a previous accepted release and previous credential generation long enough for bounded rollback.

Generated `.env.runtime`, sing-box JSON and other consumer files are derived artifacts, not desired-state authority.

## Serialization

First-party contracts are protobuf-first:

- `.textproto` for human-authored Git desired state;
- `.pb` for machine/durable state;
- JSON only where an external consumer/protocol physically requires it.

Existing first-party JSON is frozen migration debt and may only shrink.

## Development rule

Prefer deletion over parallel architecture.

When a typed owner replaces old behavior, remove obsolete:
- workflow/YAML/shell parsing;
- SecretRef/Vault/DPAPI paths;
- custom trust/transport layers with no accepted consumer;
- duplicate provider/control-plane surfaces;
- stale JSON authority.

Do not split large files merely for aesthetics before dead behavior is removed.

## Continuing work

Always start a new engineering session by reading live:
- protected `main`;
- #26 current cursor;
- #169 when the cursor is in Cloudflare/credential convergence;
- open PRs and exact CI;
- the durable ReleaseSet only when release authority is required.

Never continue from a saved SHA or chat memory without re-observation.
