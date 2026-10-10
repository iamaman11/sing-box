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

Stage 3 and Stage 4A are closed. Stage 2 (fresh-v2 credentials plus the managed Windows
proxy-only runtime), historical application-exclusive Cloudflare retirement, persistent local-owner
production rollback, class-scoped application credential rotation, Stage-3 proof-token
retirement/contraction and Stage-4A zero-consumer physical shrink are accepted and must not be
reopened for confidence.

Windows `ManagedTun` has exactly one SCM `EdgePlatformController` runtime owner. **Stage 4B.2-C is CLOSED for the accepted bounded ManagedTun contract**: physical first-child one-shot recovery, second-child fail-closed, attended SCM restart, exact previous-ManagedTun rollback and latest reconverge, real Windows reboot, one SCM + one child, TUN/DNS/GitHub recovery, native Line1 HTTPS 20/20 and ordinary Windows no-proxy DNS/HTTPS. [Full physical proof](https://github.com/iamaman11/sing-box/issues/26#issuecomment-6098179421).

**Before Stage 4B.5 Android Mesh, Gate `NEW_VM_FRESH_APPLICATION_DEPLOYMENT` must PASS:** create a **new disposable Vultr VM** using the existing typed `/application acceptance` via issue #1. Require read-only Vultr doctor/inventory and clean room before any new VM, exact ReleaseSet v1 installation/health, idempotent reapply, v2 upgrade, exact rollback, VM reboot and postboot application+Mesh+DNS+VPC checks, scoped teardown, final zero-leak check and independent fresh provider inventory. No production VM mutations. [Active cursor #26](https://github.com/iamaman11/sing-box/issues/26) and [gate contract](https://github.com/iamaman11/sing-box/issues/26#issuecomment-6098256373) own progress. Stage 4C deletion-first follows Android functional acceptance.

**Cloudflare Mesh NODE prerequisite:** Cloudflare's server Mesh node requires an
exact warp_connector device profile (MASQUE/Traffic and DNS/100.96.0.0/12)
before server enrollment; this is not an Android-client-only prerequisite.
The typed `cloudflare-zero-trust doctor --scope vm-server` must fail closed
when the node profile or other shared account prerequisites are missing,
before the disposable VM is created. A missing project Mesh-node profile
must be provisioned only by an accepted scoped Cloudflare owner; do not
forge an Android client identity or bypass readiness in YAML.

**Current Mesh inactive diagnostic slice (pre-4B.5):** the existing disposable
`/application acceptance` must retain the Cloudflare provider `healthy` gate. If local
`MeshRuntimeState` is READY but provider health remains `inactive`, take exactly one
additional typed read-only deep Mesh observation before compensation destroys the guest;
emit only fixed-field, normalized, non-secret status (no raw CLI/log/token/registration ID).
The original provider failure remains primary even if this observation is unavailable.
This diagnostic improvement by itself does **not** close the full new-VM lifecycle gate.
Source, negative tests, accepted exact-head CI and new physical v1→v2→rollback→reboot
proof are separate obligations in the sole master plan, issue #26.

**Separate residual guard:** the foreign Cloudflare One Client is in `TunnelOnly` and may list both TUN DNS `172.19.0.2` and router `192.168.100.1`. Automatic independent no-TUN DNS/GitHub restore and ManagedTun→ProxyOnly teardown are not accepted. Keep `hijack + strict_route`, leave `native` DNS offline-only, never stop working TUN to manufacture recovery proof, and do not add an extra Windows service, DNS writer, daemon, scheduler, WFP exception or edit foreign Cloudflare One/MISH/OKX. The dedicated `NT SERVICE\\EdgePlatformController` retains least-scope TUN ownership; do not switch to LocalSystem.

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
- service identity: `NT SERVICE\EdgePlatformController`; in `MANAGED_TUN` this exact principal has local Administrators membership for Wintun/TUN ownership while remaining distinct from LocalSystem;
- the controller enables its existing `SeDebugPrivilege` only while spawning the MANAGED_TUN sing-box child, immediately restores the controller token, and relies on the child token for process-name loop prevention;
- GitHub runner: NetworkService transport only;
- SYSTEM privileged bridge: `EdgePlatformPrivilegedDispatch`;
- runner has no plaintext/decrypted application-secret authority;
- Windows Cloudflare One Client remains foreign/no-touch even when it mirrors the active sing-box TUN resolver onto its own adapter.

The console is not a fallback startup owner. The historical external Windows sing-box was not
adopted as release/rollback authority: the currently running managed TUN is SCM-owned, and
`previous.pb` is also `ManagedTun`, not a no-TUN rescue.

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
adding abstractions or splitting large files. Stage 4A's zero-consumer shrink is already closed;
its historical exit decision must not be reopened merely for cleanup. Stage 4B completes physical
failure recovery and remaining functional acceptance. Only then Stage 4C deletes newly orphaned
transitional consumers using exact GitHub evidence and bounded CI.

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
- a second TUN/default-route/system-proxy owner or teardown that bypasses #26's current Stage 4B.2-C recovery gate.
