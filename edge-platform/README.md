# edge-platform

Rust control-plane workspace for `iamaman11/sing-box`.

## Start here

There is one execution cursor and one architecture authority:

- **GitHub Issue #26** — current macro stage, exact next action and accepted live evidence;
- **`ARCHITECTURE.md`** — stable ownership, safety invariants and target steady state;
- **`FINALIZATION-PLAN.md`** — tombstone only; it is not executable.

Do not reconstruct current state from old chat context, local clones or historical issue bodies.
Before a mutation, refresh protected `main`, open PRs, latest Actions and the latest #26 evidence.

## Current convergence model

The target architecture is intentionally smaller than parts of the current repository. Some
migration/bootstrap/acceptance paths still exist only because their final consumer has not yet been
retired. Their presence does not make them steady-state authority.

Use the architecture classifications:

- `CANONICAL` — required steady-state path;
- `TRANSITIONAL` — bounded live consumer remains; do not broaden it;
- `DELETION_CANDIDATE` — remove after exact consumer proof;
- `HISTORICAL_EVIDENCE` — GitHub evidence only, never an execution path.

Stage 3 is closed. The project is in Stage 4A physical shrink. Stage 2 (fresh-v2 credentials plus
the managed Windows proxy-only runtime), historical application-exclusive Cloudflare retirement,
persistent local-owner production rollback, class-scoped application credential rotation and the
Stage-3 proof-token retirement/contraction are all accepted and must not be reopened for confidence.

Stage 4A is consumer-driven deletion only: remove one complete transitional vertical slice when its
exact production/acceptance/bootstrap/recovery/rollback consumer set is zero. After the current
contraction is terminally accepted, perform one fresh repository-wide last-consumer audit. If all
remaining transitional boundaries still have real consumers, record `STAGE4A=CLOSED` in #26 and
advance to Stage 4B. TUN remains deferred until that explicit gate. The currently working external
Windows sing-box stays untouched until the dedicated managed-TUN cutover passes.

## Steady-state owner map

```text
Git / production.textproto
          |
          +--------------------+
          |                    |
          v                    v
 immutable ReleaseSet     edge-orchestrator
                           provider composition
                            |             |
                         Vultr        Cloudflare

production VM:
GitHub self-hosted runner (transport only)
  -> exact allowlisted local operation
  -> root-owned typed Linux runtime owner
  -> Docker Compose / Bollard / Docker Engine

Windows:
GitHub self-hosted runner (NetworkService transport only)
  -> bounded SYSTEM EdgePlatformPrivilegedDispatch
  -> SCM EdgePlatformController
  -> native managed sing-box runtime

independent:
edge-diagnostic.exe -> read-only Windows observation
```

GitHub Actions authorizes and transports operations. It must not become a second lifecycle engine or
desired-state store.

## Intended normal operator surface

Final normal operation converges toward:

```text
/production converge
/production verify
/production diagnose
/production rollback

/credentials rotate
/credentials verify

/windows <only genuinely Windows-local physical lifecycle operations>
```

The routine production surface is `/production converge|verify|diagnose|rollback`, plus exceptional
`/production enroll-runtime` for explicit bootstrap/re-enrollment. Rollback uses the same persistent
self-hosted-runner -> typed local-owner boundary as converge/verify; the legacy lease/SSH rollback
dispatch is removed.

The credential surface includes read-only `/credentials verify`, explicit
`host-bootstrap-converge`, and class-scoped application rotation:
`/credentials rotate tunnel-auth|reality-identity|line2-proxy-auth`. Application rotation preserves
unselected nested generations, publishes only the inactive A/B slot, and keeps host identities as a
separate lifecycle. Windows/VM Access host identities are permanent (`forever`) create-once identities;
`host-bootstrap-converge` is their explicit bootstrap/recovery boundary, and retries never rotate an
installed host identity implicitly.

Separate production-facing `/dns`, `/mesh` and `/zero-trust` operator namespaces are retired.
The standalone `cloudflare-dns` and `line3-mesh` CLI namespaces are deleted; acceptance and
production composition use typed internal functions instead. The old executable Zero Trust
inventory/plan/apply/verify lifecycle is deleted; the internal
read-only `cloudflare-zero-trust doctor` remains only for acceptance guardrail observation.
The standalone application mutation/recovery CLI is also deleted; `application-lifecycle` retains
only the disposable-acceptance `materialize` boundary. Other provider-internal and migration-only
commands remain transitional unless #26 explicitly says otherwise.

## Canonical production authority

- desired state: `infra/production/production.textproto`;
- exact release identity: immutable `ReleaseSet.pb` / durable release publication;
- provider reality: fresh Vultr/Cloudflare observations;
- Windows release activation: `C:\sing-box\current.pb` plus exact immutable release directory;
- application credential state: typed local `state.pb` plus immutable canonical bundle bytes;
- generated env/sing-box JSON: reproducible output, never durable authority.

## Windows trust/runtime boundary

Canonical application root:

```text
C:\sing-box
  current.pb
  previous.pb
  releases\<release-set-sha256>\
  bin\
  state\
    secrets\
  runtime\
  logs\
  exchange\
```

Transport root is separate:

```text
C:\sing-box-runner
```

Accepted ownership:
- SCM service: `EdgePlatformController`;
- service identity: `NT SERVICE\EdgePlatformController`;
- GitHub runner: NetworkService transport only;
- SYSTEM privileged bridge: `EdgePlatformPrivilegedDispatch`;
- runner has no plaintext/decrypted application-secret authority.

The console is not a fallback startup owner. The external pre-existing Windows sing-box is not
adopted as LKG, rollback authority or managed state before the final managed-TUN cutover.

## Credential transition

Fresh application credentials use paired Windows/VM least-privilege projections and fixed Worker A/B
slots. Each local owner fetches its own exact generation directly through its projection-specific
`workers.dev` Worker and permanent Cloudflare Access host identity.

Runners carry only non-secret generation/slot/operation intent. They never receive plaintext
application credential payloads. Candidate publication is not activation. Each host-local stage fetches
the exact generation, materializes any class-scoped delta only inside its protected active store and
validates the candidate; both hosts are staged before the first runtime activation. Uncertain provider
mutations are resolved by read-only re-observation rather than blind replay.

One semantic config has one renderer. A runtime stage/validate/restart path may copy, check and launch
that generated config, but may not independently rewrite tunnel bindings or other semantic fields.

## VM transport

Steady-state VM operations use the repository self-hosted production runner as outbound transport:

```text
GitHub
 -> self-hosted low-privilege runner
 -> exact allowlisted typed operation
 -> root-owned local runtime owner
 -> Compose mutation / Bollard observation
```

Routine operation does not use hosted-runner SSH, temporary /32 ingress, SSH forwarding or a
TCP/gRPC agent listener. `/production enroll-runtime` may use bounded strict SSH only for explicit
bootstrap/re-enrollment and must remove the temporary lease before PASS.

The runner has no provider credentials, no generic root, no Docker socket access and no application
credential plaintext authority.

## Build/release model

```text
exact source
 -> exact-head CI
 -> build once
 -> candidate acceptance
 -> protected merge
 -> promotion of exact accepted bytes (no rebuild)
 -> immutable ReleaseSet
```

Production hosts do not build project Rust binaries or project OCI images.

## Change-completeness rule

A new typed operation is complete only across the full vertical slice:

```text
schema/CLI
 -> implementation
 -> workflow invocation
 -> OS privilege/identity allowlist
 -> recovery / uncertain-outcome handling
 -> topology guard
 -> tests / live acceptance
```

If one boundary is missing, fix that same contract. Do not add a second service, state machine,
store, workflow or generic privilege to work around incomplete wiring.

## Deletion-first finalization

After a replacement path is live-proven, classify its old consumers and delete dead behavior before
adding abstractions or splitting large files. Stage 4A removes only complete zero-consumer
transitional vertical slices. Its exit condition is not "no more code to simplify"; it is a fresh
repository-wide audit showing that every remaining transitional boundary has a real
production/acceptance/bootstrap/recovery/rollback consumer. At that point #26 closes Stage 4A and
Stage 4B performs the separate managed Windows TUN cutover.

A successful finalization should reduce:
- lifecycle owners;
- mutable state locations;
- operator namespaces;
- workflow branches and shell glue;
- legacy/acceptance-only transport;
- first-party JSON and obsolete persistence;
- topology guards that protect deleted architecture.

## First-party serialization

- `.textproto` — human-authored Git desired state;
- `.pb` — canonical machine/durable state;
- JSON — only where an external consumer/protocol requires it.

Existing internal JSON is frozen migration debt and may only shrink.

## Safety

Never reintroduce:
- Windows provider mutation authority;
- arbitrary remote PowerShell/SSH production surfaces;
- generic root/admin shell;
- TOFU SSH success paths;
- mutable release authority;
- plaintext credentials in Git/Issues/Actions/Release assets;
- a second desired-state or secret-history store;
- blind retry after uncertain mutation;
- a second Windows startup/runtime owner;
- TUN/default-route/system-proxy ownership before #26 explicitly records `STAGE4A=CLOSED` and opens the Stage 4B cutover gate.
