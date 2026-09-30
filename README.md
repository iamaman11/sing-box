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

## Accepted architecture and convergence target

The ownership model below is accepted. Cloudflare account convergence through the single production-account authority flip is closed. Current execution is the final convergence sequence in Issue #26: complete the bounded runtime-host Access identity bootstrap, then perform one terminal fresh-v2 credential cutover, then delete superseded historical/control surfaces. Stable architecture must not reopen the closed provider migration.

```text
Git / protected main
  production.textproto + source
        |
        +------------------------------+
        |                              |
        v                              v
immutable ReleaseSet             edge-orchestrator
exact binaries/images            GitHub-hosted provider owner
                                       |
                         +-------------+-------------+
                         |                           |
                       Vultr                     Cloudflare
                    provider lifecycle      account: sing-box
                                           Mesh / Zero Trust / Access
                                           credential-delivery Workers

Runtime hosts:

GitHub
  |-- Windows self-hosted runner (transport only)
  |      -> SCM EdgePlatformController
  |      -> typed local state / sing-box
  |
  '-- production-VM self-hosted runner (transport only)
         -> local root-owned typed runtime owner
         -> typed local state / Docker Compose / Docker Engine

Shared external boundary:
Cloudflare zone alegria.by
  -> project-owned DNS records only
```

## Ownership rules

- **Git** owns desired state and execution policy.
- **ReleaseSet** owns exact immutable release identity.
- **edge-orchestrator** owns GitHub-hosted provider/production composition, including Vultr/Cloudflare lifecycle and credential generation/publication.
- **Vultr/Cloudflare APIs** are observed provider state, never desired-state databases.
- **production-VM self-hosted runner** is outbound transport only; it dispatches typed local operations and is never desired-state or credential-plaintext authority.
- **Linux local runtime owner** owns VM-local application/config/credential lifecycle. Docker Compose is its fixed multi-container mutation adapter and Bollard is its typed Docker observation/diagnostic adapter. Existing `edge-agent` runtime logic may be reduced/reused locally; remote TCP/gRPC agent transport is not target architecture.
- **Windows self-hosted runner** is outbound transport only; SCM **EdgePlatformController** owns Windows-local runtime/config/credential lifecycle.
- **edge-diagnostic** is independent, read-only diagnostics; it is not a repair owner.
- **GitHub Actions** authorize, materialize exact inputs, invoke typed owners and publish bounded evidence. YAML/shell/Python do not own domain semantics.

## Cloudflare target

All application-exclusive account-scoped Cloudflare resources are owned by the dedicated account `sing-box`.

`alegria.by` deliberately remains a shared external DNS zone. DNS automation is zone-scoped and may mutate only the explicit sing-box record set. Credential-delivery Workers remain intentionally `workers.dev`-only with previews disabled; custom domains are not part of the accepted credential plane.

Runtime credentials are not copied from the legacy Windows installation. The new stack gets fresh credential generations through isolated Windows/VM credential Workers. Each Worker is only a fixed A/B delivery mailbox: no active pointer, history database or runtime authority. Canonical delivery is runner-blind direct HTTPS fetch by the trusted local owner using a projection-specific permanent Cloudflare Access host identity. Windows and VM host identities are physically distinct from each other and from proof identities. Self-hosted runners carry only non-secret intent and never receive credential plaintext. Cloudflare is a convergence/rotation dependency, not a runtime data-path dependency.

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

Prefer deletion over parallel architecture. The steady-state host transport is symmetric: one repository self-hosted runner per persistent runtime host, plus one trusted local runtime owner. Routine hosted-runner SSH/tunnels, custom agent mTLS and duplicate remote-control layers are migration debt, not target architecture.

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
