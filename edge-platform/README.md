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

**ACTIVE N1/N2 → N3 → N4 (2026-10-12).** [Issue #26](https://github.com/iamaman11/sing-box/issues/26) is the sole execution cursor and [Draft PR #348](https://github.com/iamaman11/sing-box/pull/348) the only integrated functional slice. Old Stage 4B.5 Android Mesh and Stage 4C cleanup are historical follow-on records, not competing live plans. Stage 2/3/4A acceptance remains historical; it does not license a rebuilt network.

**VM present state:** [Provider doctor #38289563205](https://github.com/iamaman11/sing-box/actions/runs/38289563205) PASS with exact `application-acceptance-1` disposition **CREATE** and zero mutations: new VM, online self-hosted runner, installation, external authenticated Line1 4/4 + Line2 6/6, reboot and cleanup are **not yet accepted**. The old production VM was deleted. Current `/vultr initial-vm-install` in #348 is a transitional incomplete composition using hosted-runner SSH, an incompatible production-Windows first-use consumer, and unconditional final external BLOCKED. It must converge into the **same existing normal VM lifecycle** and bounded local owner used subsequently by production; only the durable Worker first-use journal/intent/unknown-ACK no-replay constraint remains a special internal transaction.

**Windows present state:** [Read-only physical /windows diagnose #38288078001](https://github.com/iamaman11/sing-box/actions/runs/38288078001) PASS: `EdgePlatformController` is **Stopped / AutoStart**, managed TUN absent, direct DNS and ordinary HTTPS PASS, Cloudflare One connected in TunnelOnly. Automatic no-TUN DNS/control recovery, new-server Line1 and ManagedTun→ProxyOnly are unproven; do not start or mutate Windows WARP/MISH/OKX to force a PASS. N3 accepts **one** SCM controller, Git-backed desired `WindowsDatapathMode`, native in-controller ProxyOnly ↔ ManagedTun transitions with both real traffic modes, routes, DNS and reboot/recovery proof.

**Operator product acceptance:** Issue #1 command → existing typed Rust owner → exact host. Self-hosted runners are bounded outbound transport only; local owners do all privileged runtime changes. Use one normal create/enroll/install/configure/diagnose/measure/repair/reinstall/destroy lifecycle. An acceptance VM is disposable, not a separate product installer. Independent authenticated 10/10 direct/WARP, public TLS, reboot and clean disposal are required; source/CI/provider metadata and internal loopback are not acceptance. See Issue #26 for live gates and failure resolution.

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

## One-shot production VM replacement boundary

The canonical production server is defined only by
`infra/production/production.textproto`. GitHub allows the existing native
Vultr destroy owner to expose **only** the exact production pair:
`/vultr destroy-plan infra/production/production.textproto production-1`
(read-only), then `/vultr destroy-apply infra/production/production.textproto
production-1 <fresh-destroy-digest>` (single exact owned VM deletion).
The Rust owner separately checks the fresh provider object, source revision,
destroy digest and authorized plan. Other operations on the production proto
remain disallowed in the Vultr workflow; normal production create/bootstrap
is the existing `/production enroll-runtime` and later
`/production converge` + `/production verify`. A destroy-plan is not
authorization to erase without an explicit replacement readiness decision.
No separate shell, control plane or permanent state.

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

**Disposable VM application_v1 SSH forensics:** an SSH/banner/strict-tunnel
failure in the accepted in-process application coordinator triggers **one
read-only bounded** pre-cleanup snapshot from the same Vultr/SSH owners:
actual VM provider readiness, port 22 TCP outcome (single 3s observation),
attached exact runner `/32` ingress rule, firewall acquire-plan disposition,
runner egress consistency and one CA-pinned SSH handshake-phase observation.
Snapshot fields are fixed-schema with no credentials/raw SSH stderr. Original
failure and fail-closed compensating cleanup remain the terminal authority.
No SSH mutation replay, global retry, additional job or service. A `PASS`
snapshot is diagnostic only, never physical acceptance.

**New disposable VM acceptance cleanup dependency:** the sole typed coordinator
first removes Mesh runtime/provider and acceptance DNS/temporary access, then
detaches and deletes the **exact project-owned VPC while the source VM remains
owned and observable**, and only after verified VPC absence destroys the VM.
Any stale/foreign/ambiguous attachment, failed detach or uncertain VPC read
blocks VM destruction and produces `DIAGNOSTIC_REQUIRED` rather than erasing
the resource ownership needed for recovery. Final independent zero-leak proof
still gates PASS. No new transport, scheduler, daemon, retry or generic shell.

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
