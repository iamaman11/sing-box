# sing-box

Production edge networking/control-plane project.

## Canonical authority

The remote repository `https://github.com/iamaman11/sing-box` is the only long-term source of truth.

Read authority in this order:

1. **GitHub Issue #26** — sole living execution cursor and ordering authority.
2. **`edge-platform/ARCHITECTURE.md`** — current stable ownership/invariant model.
3. **GitHub Issue #169** — historical Cloudflare account/credential convergence evidence only; it no longer owns the current cursor.
4. **GitHub Issue #154** — Windows Slice 2 implementation/evidence record. It does not schedule current work.
5. **GitHub Issue #60** — bounded Windows diagnostics specification.
6. **GitHub Issue #1** — canonical operator command channel/reference.
7. **Issues #2/#3/#4** — functional acceptance scopes for Lines 1/2/3.

Historical plans are never execution authority. If any document conflicts with #26, #26 wins after live repository state is re-read.

## Accepted architecture and convergence target

> **N1/N2 physical network 10/10 + reboot: ACCEPTED. Operational lifecycle closure: IN PROGRESS.** [Single immutable run #38627187731](https://github.com/iamaman11/sing-box/actions/runs/38627187731) proved all four Line1 and six Line2 external endpoints, TLS/positive+negative authentication, direct/WARP separation before/after the actual VM reboot and exact isolated Windows/Access cleanup. Original Worker credentials generation `38503639351` and one reboot BEGIN are irreversible journalled facts: **no replay**. The already-owned acceptance VM was retained, not provider-disposed. Native VM diagnosis [#38628848200](https://github.com/iamaman11/sing-box/actions/runs/38628848200) reports three healthy core containers but a **candidate-only** local credential cursor, no active generation and no proof of container-loaded credential source; release/network PASS does not close that state. The read-only Rust owner distinguishes candidate-on-disk from active-on-disk and explicitly refuses to equate either with the running container. See [Issue #26](https://github.com/iamaman11/sing-box/issues/26) for the only current operational cursor. Windows serving SCM remains intentionally stopped and ManagedTun is forbidden pending N3 safety acceptance.

**N1/N2 read-only runtime-source gate:** `/vm credential-runtime-source infra/application/disposable-acceptance.json` runs inside the **existing VM owner**, not a sidecar or new service. It compares exact durable Worker-v2 candidate/active projection → `.env.runtime` → canonical JSON templates → rendered Line1/Line2 files → Docker read-only bind identities → files actually visible at both running sing-box processes, then independently rechecks the cursor and renderer. It exports **no secret contents, digests or paths**. The only positive claim is `CONFIG_VISIBLE_LOADED_UNPROVEN`: process-visible files are exact; an in-memory load and real authenticated Line1 remain **unproven** until independent protocol witnesses. This read-only operation cannot promote credentials, rotate the Worker, reload a container, restart the VM or start Windows TUN. Fix Line2 human-readable `successes`/`negative_auth` field order in the same functional slice. **Initial candidate → active is still blocked**, and no operator is authorized to bypass the existing initial enrollment guard merely because this diagnostic passed.

**Physical CLI failure evidence (2026-10-15):** [GitHub run #38647607150](https://github.com/iamaman11/sing-box/actions/runs/38647607150) proved a gap between authorized `/vultr owner-upgrade` and the public orchestrator Clap enum (`unrecognized subcommand`). Host-binary update was never dispatched. The follow-up fix adds both public Clap owner commands, actual argument-roundtrip tests and a fail-early CLI preflight *before* acquiring transient host access. Until the fixed ReleaseSet is accepted and a new VM diagnosis confirms installation, owner upgrade remains unaccepted.

**N1/N2 source-in-progress — exact owner migration:** An existing Git-declared VM can migrate its installed root-owned `edge-agent` through `/vultr owner-upgrade <spec> <machine-id> <observed-old-sha256>` using the accepted ReleaseSet and existing typed Vultr/strict-SSH bootstrap authority, without re-registering the GitHub runner or applying containers/credentials. The transition is single-attempt with a host-local durable BEGIN and retained previous binary; an unknown outcome must be diagnosed, never retried. A typed `/vultr owner-rollback <spec> <machine-id> <current-sha256> <previous-sha256>` uses the exact on-host BEGIN and retained binary, with its own non-replay journal; rollback is never automatic. This is a **transitional bootstrap path**, not a new steady-state SSH requirement and not evidence of installed code until a real exact-target run proves it. The native VM credential candidate → active and running-container provenance remain separate gates.

**Read-only operations:** /windows diagnose uses the installed, hash-verified diagnostic binary and must not require resolving a newer release. /windows quality-line1 uses the already installed running ManagedTun only; it must not start TUN merely to perform a test. /vm diagnose uses the installed VM agent. Diagnose reports installed versus desired revision without treating mismatch as permission to mutate. Changes to runtime, DNS, TUN, firewall or credentials still require the regular typed authorization and immutable ReleaseSet gates.

**Windows state:** serving EdgePlatformController remains stopped by operator intent, with TUN disabled. Do not restart or capture routes until independent no-TUN DNS/control restoration and current real Line1 authentication are physically accepted. Never start/restart/converge/repair/rollback TUN merely to retest.

**One delivery order:** N1/N2 — complete the **same native VM lifecycle** used in production and external 10/10 authentication/TLS/egress tests, restart, reboot and disposal. N3 — complete safe bidirectional Windows modes using one SCM `EdgePlatformController`, desired mode from Git and real Internet restoration proof. N4 — exercise the same operations on production. First-use credentials require a durable journal and no blind replay after ambiguous ACK, **not another customer-facing installer**. No additional stages, helper PRs, new daemon, second control plane or acceptance-only runtime.

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

Runtime credentials are not copied from the legacy Windows installation. The new stack gets fresh credential generations through isolated Windows/VM credential Workers. Each Worker is only a fixed A/B delivery mailbox: no active pointer, history database or runtime authority. Canonical delivery is runner-blind direct HTTPS fetch by the trusted local owner using a projection-specific permanent Cloudflare Access host identity. Windows and VM host identities are physically distinct from each other and from proof identities. The one-time Windows host-identity bootstrap may carry only CMS/RFC5652 ciphertext through the NetworkService exchange; the non-exportable bootstrap key and plaintext terminate inside the SYSTEM/controller-owned boundary and are destroyed after installation. Provider-side Windows plaintext may exist only as temporary GitHub Environment bootstrap escrow and is deleted after successful SYSTEM installation. Existing host tokens are never rotated implicitly on retry: they require matching escrow or the operation fails closed. This bootstrap exception is not a steady-state credential transport. Self-hosted runners carry only non-secret intent and never receive credential plaintext. Cloudflare is a convergence/rotation dependency, not a runtime data-path dependency.

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
- #169 only when historical Cloudflare convergence evidence is specifically needed;
- open PRs and exact CI;
- the durable ReleaseSet only when release authority is required.

Never continue from a saved SHA or chat memory without re-observation.

Stage-transition rule: historical Stage 4A remains closed. The ONLY current work order is Issue #26 N1/N2 → N3 → N4. Historical Windows or production acceptance cannot authorize a new TUN cutover or certify an absent VM. Do not add another daemon/watchdog.
