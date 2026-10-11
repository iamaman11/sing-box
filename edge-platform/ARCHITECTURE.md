# Edge platform architecture authority

This file defines the accepted stable ownership/invariant model and target steady state for the current project. Stage 3 and Stage 4A are closed. Cloudflare account convergence and Stage-2 fresh-v2/proxy-only acceptance are also closed. Provider reality must still be freshly observed before any mutation. Issue #26 now owns Stage 4B: native Windows ownership diagnostics, one explicit legacy-to-managed handoff, the managed Windows TUN cutover, and completion of the existing typed sing-box protocol/quality operator surface under the SCM `EdgePlatformController` owner; Stage 4C then deletes post-cutover legacy/transitional ownership. Accepted Stage 4A deletions must not be reopened merely for confidence or compiler-warning cleanup.

**Execution order is not defined here.** GitHub Issue #26 is the sole living execution cursor.
Issue #169 is historical Cloudflare convergence evidence and no longer owns current execution.
Issue #58 is a closed historical architecture record and must not be used to restore its old
global-controller model.

## Reading the repository: target architecture vs transitional debt

This document describes the **target steady state**, not a promise that every historical implementation
path has already been deleted. During final convergence, transitional code may still exist in the
tree without being architectural authority.

Use this classification whenever current code appears to contradict the target:

- **CANONICAL** — required by the steady-state owner model and may gain new capability;
- **TRANSITIONAL** — still has a live bounded consumer, but must not gain a second owner or broadened
  semantics;
- **DELETION_CANDIDATE** — no steady-state owner needs it; remove it after exact consumer proof;
- **HISTORICAL_EVIDENCE** — retained only in GitHub history/issues and must not drive execution.

The presence of transitional code is never evidence that it should be generalized or preserved.
Issue #26 is the only authority for when a transitional consumer has been proven dead and deletion
may proceed.

### Vertical-contract completeness

A new typed operation is not complete when only its Rust implementation compiles. The same logical
change must cover every boundary it crosses:

```text
schema / CLI
  -> semantic implementation
  -> workflow invocation
  -> OS privilege / identity allowlist
  -> recovery and uncertain-outcome handling
  -> topology guard
  -> focused tests and live acceptance
```

If one boundary is missing, fix that **same vertical contract**. Do not compensate by adding another
service, state machine, queue, store, workflow namespace, retry loop or generic privilege.

### Complexity and contraction budget

Until final convergence is closed:

- prefer deleting an obsolete path over wrapping it in a new abstraction;
- do not add a new lifecycle owner, durable store, resident daemon, scheduler or operator namespace
  unless a requirement cannot be expressed by an accepted owner;
- workflows remain authorization/transport/composition glue; domain semantics belong in typed Rust;
- when a replacement path is live-proven, consumer analysis and deletion are part of completion,
  not optional cleanup;
- delete dead behavior and its guards/tests before splitting large composition files merely for
  aesthetics;
- one semantic artifact has one renderer/owner: staging/validation code may copy, validate and launch
  generated configuration but must not independently re-render or rewrite its meaning.

The intended end state is smaller than the current transitional implementation. Reduction in owners,
mutable states, operator commands and orchestration branches is a correctness objective, not only a
maintainability preference.

### Delivery lock: functional installation, not preparatory PRs

**Normative Stage N1/N2 invariant (2026-10-12; executable cursor: Issue #26).**
The next accepted delivery is a **clean, disposable Vultr VM running the exact
immutable accepted sing-box release, with independent external authenticated
traffic evidence for all four Line1 and all six Line2 endpoints (4/4 + 6/6)**.
Source compilation, source CI, a ReleaseSet candidate, Worker binding metadata,
dummy probes, Docker container readiness, an SSH-ready guest, and a published
credential generation are intermediate evidence only. None can close N1/N2.

**No auxiliary delivery loop.** Until the physical 4/4 + 6/6 gate is satisfied:

1. The existing integrated Draft PR #348 is the **only source change set for
   completing N1/N2**. Do not open a helper-only, diagnostic-only, preparatory,
   documentation-only, or individual-primitive PR; do not split N1 into another
   stage or label a partial preflight as a release. Fix each discovered missing
   boundary inside the same complete GitHub -> typed Rust owner -> Windows/VM
   consumer -> externally verified network vertical.
2. Do not introduce new permanent or temporary *application services*, agents,
   schedulers, daemons, polling owners, long-running sidecars, generic shell
   executors, alternate deployment transports, independent credential issuers,
   fallback credentials, legacy credential-selection paths, or a second
   production desired-state authority. The existing bounded disposable VM and
   separately isolated non-TUN Windows acceptance consumer are **test targets**,
   not new permanent owners. Use the existing seven GitHub workflows and native
   owners; an exception cannot be silently granted by creating a helper PR.
3. Preserve strict fail-closed security: prove real unused A/B contents on both
   Workers through both host-specific Access identities; bind trustworthy
   disposable host/job provenance and exact artifact identity; durably record and
   re-read one first-use GitHub BEGIN **before any irreversible provider PATCH**.
   Two-Worker publication is not atomic. On a lost ACK, partial publication,
   stale version or ambiguous outcome, stop and perform read-only reconciliation
   without mutation replay. Never manufacture a passing E2E by bypassing this.
4. **Source acceptance is a prerequisite, not the finish line.** Complete the
   entire integrated implementation and its negative tests, run exact-head
   Windows/Linux/OCI/ReleaseSet CI, merge only the verified tested tree, and
   publish its immutable no-rebuild ReleaseSet; then execute the already
   defined disposable physical acceptance immediately, not another preparation
   initiative. Never deploy an unmerged Draft as a production authority.
5. The physical report MUST bind the release digest, source SHA, freshly created
   disposable VM identity, credential generation/projection/slot, independent
   endpoint attempts/results, TLS chain/hostname, direct vs WARP public egress
   identity, reboot proof, negative auth/generation tests and zero-leak cleanup.
   **Line1 4/4 Hysteria2/Reality** and **Line2 6/6 HTTP/SOCKS5/HTTPS** must each
   carry authenticated external traffic. A failed endpoint means FAIL, not
   “partially accepted”. Wrong password, stale generation or malformed
   certificate must fail closed.
6. Do not change serving production VM, production DNS, active Windows
   SCM/TUN/routes/DNS, Cloudflare One, MISH or OKX during N1/N2. In particular,
   a test hostname/certificate must not be made to work via production DNS
   cutover. N3 and N4 alone own the separately gated Windows and production
   handoffs, after isolated physical PASS.
7. On physical failure, retain the failed exact run evidence, classify the
   **specific failed boundary**, repair only the same integrated vertical and
   rerun the full gate. After #348 has merged, a necessary corrective PR is
   allowed **only** as a single integrated end-to-end repair, never as a helper
   or a substitute for physical proof. If an external blocker cannot be
   resolved safely, record BLOCKED with owner and observable exit criterion;
   do not expand scope or invent a new preparatory stage.

**Finish condition:** one full external, reproducible, independently observable
4/4 + 6/6 clean-VM install with exact accepted ReleaseSet and safe cleanup.
Only after this evidence may work advance to N3. Issue #26 alone sets the
ordered operational steps. Any older Stage 4B historical instructions or
intermediate CI snapshots must not supersede this delivery lock.

## 1. One-owner architecture

```text
                         Git
             production.textproto + source
                         |
          +--------------+----------------+
          |                               |
          v                               v
   immutable ReleaseSet             edge-orchestrator
   exact release identity           GitHub-hosted owner
                                          |
                               +----------+-----------+
                               |                      |
                             Vultr                Cloudflare
                        provider lifecycle   account: sing-box
                                             Mesh / ZT / Access
                                             credential Workers

Physical runtime hosts:

GitHub
  |-- Windows self-hosted runner (transport only)
  |      -> SCM EdgePlatformController
  |      -> Windows typed local state / sing-box
  |
  '-- production-VM self-hosted runner (transport only)
         -> local root-owned typed runtime owner
         -> Linux typed local state / Docker Compose / Docker Engine

Independent:
edge-diagnostic.exe = read-only Windows observer

Shared external dependency:
alegria.by DNS zone only
```

### Git / desired state

Git is the only long-term desired-state authority.

Production desired state is human-authored protobuf text format:
`infra/production/production.textproto`.

Provider object IDs, current IPs, health/status and other observations do not become a second
desired-state database.

### ReleaseSet

ReleaseSet is the exact immutable release authority.

Candidate artifacts build once. Acceptance and merge promotion reuse exact accepted bytes without
rebuild. Windows/Linux production never treats a mutable latest artifact as authority.

### edge-orchestrator

`edge-orchestrator` is the GitHub-hosted provider/production composition owner.

The public `/production converge|verify|rollback` operator path is the GitHub
workflow's exact ReleaseSet provider preflight and the self-hosted VM's typed
`edge-agent local bundle-*` owner. Direct hosted Rust `production converge`
and `production verify` subcommands, which separately reacquired SSH/leases
and applied the same application, are deleted. The remaining hosted Rust
`production dns-noop` is an internal read-only workflow preflight; exceptional
`production enroll-runtime` is the sole bootstrap SSH consumer.

It owns typed provider sequencing, plan/apply/verify/rollback semantics and the internal
`/credentials` lifecycle owner. Provider credentials remain only in the GitHub Environment and do
not move onto Windows or the production VM.

Its credential domain creates one semantic generation and derives least-privilege Windows/VM
projections. It publishes only the inactive fixed Worker A/B slot and resolves uncertain mutation by
read-only exact-generation re-observation before replay.

### Role boundary invariant

Every mutable production path follows:

```text
Git desired state
   -> typed owner decision
   -> narrow provider or host transport
   -> trusted local runtime owner
   -> observed verification
```

- owner decides lifecycle and mutation;
- protobuf carries closed typed intent/state;
- provider adapters only observe/execute provider APIs;
- GitHub runners are transport, never desired-state or credential-generation owners;
- provider IDs, generated env/JSON and SQLite rows are observed/derived state, never competing
  desired-state authority.

### Production-VM self-hosted runner

The production VM has one permanent repository-scoped self-hosted GitHub runner with outbound-only
GitHub connectivity.

The runner is low privilege and transport only. It may resolve exact accepted artifacts and invoke
allowlisted typed local operations. It must not:
- own provider credentials or provider lifecycle;
- read/return application credential plaintext;
- expose arbitrary root shell, generic sudo, filesystem, Docker or systemd mutation;
- become runtime desired-state authority.

Routine production runtime and credential operations execute locally through this runner. The
previous GitHub-hosted-job -> temporary /32 firewall lease -> SSH -> local-forward -> TCP/gRPC
`edge-agent` path is migration/bootstrap debt, not steady-state architecture.

### Linux local runtime owner

Linux has exactly one root-owned typed local runtime boundary.

Existing `edge-agent` implementation may be reduced/reused for this local role if doing so removes
code. Its network daemon/TCP-gRPC role and custom mTLS/`edge-trust` are not canonical.

The local owner may:
- observe local runtime/network state through typed host probes and Bollard;
- apply/rollback fixed Docker Compose application/runtime operations;
- own local active/candidate/previous credential state;
- acquire only the exact VM credential projection through the runner-blind delivery mechanism selected by #26;
- emit bounded secret-safe evidence.

Canonical credential delivery is direct local-owner HTTPS fetch from the projection-specific `workers.dev` Worker using a permanent projection-specific Cloudflare Access host identity. The runner supplies only non-secret generation/slot intent. Windows and VM host identities are physically distinct from each other and from bounded proof identities.

The Windows permanent host identity has one bounded bootstrap-only exception: SYSTEM creates a non-exportable temporary document-encryption key, only its public certificate crosses to the provider job, and only CMS/RFC5652 ciphertext returns through the NetworkService exchange. Decryption, validated identity installation and private-key destruction occur inside the SYSTEM/controller-owned boundary. Windows plaintext may be retained only as temporary GitHub Environment bootstrap escrow until that installation succeeds, then it is deleted. Retries never rotate an existing host token implicitly: exact matching escrow is reused or the bootstrap fails closed and requires an explicit recovery action. This mechanism is not used for application credential delivery or normal rotation.

It may not own Vultr/Cloudflare provider lifecycle or return credential plaintext to the runner.

### Windows EdgePlatformController

The only Windows application/runtime owner is the SCM service
`EdgePlatformController`, running as the dedicated virtual account `NT SERVICE\EdgePlatformController`.
For canonical `MANAGED_TUN`, that exact service principal is a member of the local built-in
Administrators group because the Windows TUN/Wintun datapath requires administrator-class local
authority. The identity remains distinct from LocalSystem and retains the per-service SID boundary.

It owns only Windows-local concerns:
- active/candidate/previous credential state;
- runner-blind exact-generation credential acquisition through the mechanism selected by #26;
- generated local sing-box configuration;
- local sing-box check/apply/lifecycle;
- selectors and local status;
- bounded local rollback/recovery.

The repository self-hosted Windows runner runs as NetworkService and is outbound transport only. It
must never become plaintext/decrypted application-secret authority.

`EdgePlatformPrivilegedDispatch` remains the bounded SYSTEM bridge for explicitly allowlisted
privileged operations. It is not an arbitrary remote shell.

Windows release bytes are materialized and verified only by the protected privileged installer; the
NetworkService workflow must not pre-download a second copy merely to duplicate release validation.
For `repair`, exact runtime stop, accepted-release rematerialization and failure recovery are one
privileged reinstall transaction. Workflow fail-closed rollback to `previous.pb` is reserved for a
post-activation verification failure after the typed lifecycle mutation itself succeeded; a preflight
or mutation failure is re-observed and recovered by its owning boundary instead of triggering a second
competing recovery path.

### edge-diagnostic

`edge-diagnostic.exe` is independent from the Windows controller.

Default growth is bounded one-shot native observation. A resident observer is allowed only if live
evidence proves a continuous-observation requirement that one-shot diagnostics cannot satisfy.

Diagnostics are read-only by default. Repair is always a separate explicit typed action.

For Windows network ownership, diagnostics must report enough native evidence to distinguish the
canonical runtime from legacy, foreign and unknown host owners without inferring ownership from an
interface name. The bounded observation set may include process/listener identity, adapter identity,
per-interface addresses/DNS, IPv4/IPv6 route counts and deterministic route-set fingerprints. Unknown
ownership fails closed at a mutation gate; diagnostics must not mutate an object merely to classify it.

### Shared-host foreign-project isolation

The Windows host may run unrelated projects and network software. Co-location is not ownership.

A sing-box lifecycle operation must not stop, restart, reconfigure, delete, clean up, reuse or repurpose
a foreign project's runner, service, task, process, firewall rule, file tree, credential state or network
object. This explicitly includes co-located MISH/mobile-proxy-mish and OKX surfaces. Their existence may
be observed only when necessary to prove non-interference.

The sing-box self-hosted runner is transport for this repository only. A different repository runner
remains foreign even when it uses the same GitHub runner binaries, Windows service account or physical
host. Unknown host objects remain `UNKNOWN`; matching names, drivers or parent directories are not enough
to adopt them.

### Sing-box configuration, protocol selection and quality authority

There is one canonical Windows sing-box renderer. Generated JSON is a consumer artifact, not an operator
API and not a desired-state store.

The supported Windows transport set is closed and typed around the existing direct/WARP Hysteria2 and
VLESS Reality outbounds plus their bounded automatic selectors. A durable default protocol/route policy
belongs to Git-owned typed desired state. A transient live test may use the existing typed selector
boundary, but it must preserve/restore the previous selection on every terminal path and must not turn
an observation database into competing desired state.

Network-quality measurement is bounded observation under the existing controller/operator vertical
contract, not a benchmark daemon or a second scheduler. Comparative tests should use the same target and
policy for every candidate transport and may report availability, repeated request latency, distribution
statistics, jitter, request failure rate, egress/trace identity and bounded throughput. HTTP request
failure rate must not be labeled packet loss. Upload throughput requires an explicitly controlled upload
sink before it becomes an acceptance metric.

### Product traffic planes

The canonical VM has three independent product traffic lines composed from four project-owned container identities.
Co-location and shared primitives do not merge their functional ownership.

1. `vultr-warp-egress` — shared VM-side Cloudflare WARP egress for WARP variants of Lines 1 and 2 only.
2. `vultr-line1-gateway` — Line 1 Hysteria2/VLESS Reality direct/WARP tunnel ingress.
3. `vultr-line2-proxy` — Line 2 six authenticated HTTP/SOCKS5/HTTPS direct/WARP proxy inbounds.
4. `vultr-cloudflare-mesh` — Line 3 Cloudflare Mesh connector/egress for external Android Cloudflare One Client.

Acceptance identifies these exact project-owned containers/images; it must not require that the entire Docker host contain only four containers. Additional Docker objects remain foreign/unknown until separately proven.

**Line 1 — tunnel transport plane.** The VM `line1-gateway` exposes Hysteria2 and VLESS Reality in direct and WARP variants. Windows canonical sing-box consumes these four endpoints. Direct leaves via the VM public uplink; WARP variants use `warp-egress`. Windows `PROXY_ONLY` versus `MANAGED_TUN` changes only the local Windows datapath around this Line 1 plane.

**Line 2 — authenticated application proxy plane.** One VM `line2-proxy` process owns six public inbounds on the canonical production hostname: direct HTTP/SOCKS5/HTTPS-proxy and WARP HTTP/SOCKS5/HTTPS-proxy. The three WARP inbounds use `warp-egress`; the three direct inbounds use the VM direct outbound. Line 2 requires no Windows TUN. Its authentication is the independent `line2-proxy-auth` credential class and remains rotatable/testable without changing Line 1 or Windows datapath.

**Line 3 — Android Cloudflare Mesh plane.** The VM `cloudflare-mesh` container is a separate Cloudflare Mesh/WARP-Connector runtime with its own `/dev/net/tun`, identity-scoped Mesh state/token and MASQUE/WARP connection. Android uses Cloudflare One Client in Traffic and DNS mode through Cloudflare Zero Trust/Mesh to destinations explicitly routed through this VM connector. Connector health alone does not prove arbitrary/full-Internet Android egress: public CIDR/hostname routing and any broader exit-node contract require explicit provider routing/policy plus Android E2E proof. Line 3 exposes no public proxy listener merely for Android and does not use Windows TUN, Line 1/2 gateways or the shared `warp-egress`. Its provider node/route/token/runtime lifecycle remains independently verifiable and removable.

`BootstrapFull` owns `warp-egress + line1-gateway + line2-proxy`; the existing typed Mesh lifecycle independently converges `cloudflare-mesh` because Mesh provider identity/token/recovery is a different resource class. This remains one local VM owner and one Docker Compose file, not a second host control plane.

**Fresh-VM and production cutover boundary (N1):** routine `production converge` for the core Line1/Line2 product first requires the canonical public DNS to be a verified NOOP for the current exact production owner. It must neither publish/change the production DNS record nor deploy/require optional Android Mesh; normal core verification likewise does not require a healthy Line3. This does **not** yet provide a new-VM staging or DNS-switch command: a clean new host is still blocked from production `converge` until the separate typed initial Worker-v2 enrollment, isolated authentication and explicit authorized DNS cutover contract are implemented and physically accepted. The production hostname's ACME HTTP-01 challenge must be resolved without silently repointing it at an unaccepted candidate; disposable acceptance must use a distinct validated hostname/issuer path. Do not claim read-only DNS NOOP as proof that four tunnels are authenticated.

The Windows Cloudflare WARP client/service/adapter is not any of these VM traffic mechanisms. It is a foreign shared-host network owner. The sing-box project may observe it when needed to prove non-interference and may render an explicit bypass for its process/control endpoints to avoid a managed-TUN loop, but it must not adopt, configure, stop, clean up or depend on that Windows WARP client.

Legacy local resolver/interface-DNS ownership is also distinct from authoritative Cloudflare DNS and from Line 3 Mesh DNS. A stale legacy resolver address on a surviving interface is a Windows handoff failure, not a reason to mutate the shared `alegria.by` zone, Line 3 Mesh, or the dedicated Cloudflare application account.

## 2. Edge Control Plane

The repository-level Edge Control Plane is a thin owner-gated router, not a business-logic engine.

Steady-state direction:

```text
/production converge
/production verify
/production rollback
/production diagnose

/credentials rotate <credential-class>
/credentials verify

/windows <bounded physical/local operations>
```

Exact grammar may become smaller.

After Cloudflare ownership convergence, separate production-facing `/dns`, `/mesh`,
`/zero-trust` and public `/production target-plane-*` command/workflow ownership disappears into
canonical typed `/production` composition. The standalone `cloudflare-dns` and `line3-mesh`
operator CLI namespaces are physically removed; disposable acceptance and production composition
invoke their typed internal functions directly. The obsolete executable Zero Trust
inventory/plan/apply/verify lifecycle is physically removed; only the internal read-only
`cloudflare-zero-trust doctor` remains for acceptance guardrail observation. Provider-specific
target-plane logic may remain as an internal typed implementation detail; it is not a second
steady-state operator namespace. The transitional standalone application mutation/recovery CLI is
also removed: `application-lifecycle` retains only the one acceptance-consumed `materialize`
subcommand, while production and disposable acceptance invoke typed lifecycle functions directly.

Historical application-exclusive account-scoped Cloudflare residuals have been retired.
The historical/shared account remains only as an explicit shared-DNS/external dependency boundary;
no historical retirement operator surface or historical write credential belongs to steady state.

Disposable `/application acceptance|cleanup` and `/production enroll-runtime` are exceptional
acceptance/bootstrap surfaces, not normal steady-state operator API. They remain only while their
exact disposable-acceptance or reinstallation consumers exist.

Workflows may:
- authorize actor/repository/environment;
- resolve exact accepted revision/ReleaseSet;
- inject narrowly scoped control credentials;
- invoke typed binaries;
- publish bounded secret-safe evidence.

Workflows must not define domain semantics through YAML, shell, Python or jq.

No generic `/exec`, arbitrary PowerShell or arbitrary SSH production API is allowed.

## 3. Cloudflare ownership

The target steady state has two non-overlapping Cloudflare boundaries.

### Dedicated account `sing-box`

Owns all application-exclusive account-scoped resources:
- Mesh;
- project-owned Zero Trust/Gateway/Access resources;
- credential-delivery Workers;
- Windows/VM Access machine identities.

The dedicated account ID is non-secret desired state and should be declared once in the typed
production composition rather than duplicated across subsystems.

The Phase 5 authority flip is closed:
- `cloudflare.active_account_id` is the sole active owner for application-exclusive account-scoped resources and points at the dedicated `sing-box` account;
- no migration-target field is a competing active authority;
- the shared DNS account coordinate remains separate with the DNS boundary, so `alegria.by` is not adopted into the application account.

Credential Workers are intentionally `workers.dev`-only with previews disabled and zero custom domains. Access applications bind to the exact workers.dev hostnames. The deprecated Mesh-local account field is not an authority in canonical production schema.

### Shared zone `alegria.by`

Remains intentionally external/shared.

The project owns only its explicit record set, currently centered on `miu.alegria.by`.
DNS automation uses a separate zone-scoped credential and must fail closed on ambiguous/foreign
records.

Do not move unrelated zone resources into the dedicated account merely for symmetry.

## 4. Credential architecture

Legacy application credentials are not migrated into the new runtime.

**Enforced single issuance path:** the GitHub-owned credential operation generates
one application credential generation and publishes two least-privilege projections
into Cloudflare credential Workers. VM/Windows local owners may persist protected
immutable copies of the *same* verified Worker deliveries for offline runtime
autonomy; they may not generate substitute credentials, adopt a historical local
credential file, silently select a different generation, or recover to an
untracked non-Worker secret. The Cloudflare Workers publish the accepted
generations, while each local `active` pointer is the independently observable
applied state; Worker availability is never required for already-running traffic.

**Fail-closed VM implementation:** `edge-agent` requires an active, locally
verified Worker-v2 projection before materializing any new VM runtime environment.
A missing v2 cursor fails the operation without silently creating a local
`application-runtime-v1.env`. The retired `ApplyLegacy` transition is rejected;
failure while applying a v2 candidate may only restore the verified **previously
active v2** projection. The `RetireLegacy` operation can remove the obsolete
local file *only after* exact active-v2 runtime verification, never use it for
authentication. Running containers must not be assumed to consume the on-disk
environment without a separate bounded runtime-reload or functional proof.

**Migration / operations gate:** On 2026-10-11 the existing production VM
reported `credential_state_present=false`. Removing the legacy fallback in source
does not prove v2 enrollment on this VM: installing or converging an updated
binary may now deliberately fail closed. Never force restart, stop/recreate Line1,
change Windows SCM/TUN/DNS, or delete the currently serving VM secret file to
"prove" centralized credential ownership. First establish the exact paired
Worker-issued v2 credentials, explicit local active projection and an independent
safe client/network recovery path; only then authorize bounded cutover and
destructive cleanup. Existing deployed runtime remains read-only until that gate
is satisfied. No legacy secret-generation bypass may be reintroduced to make
reinstallation green.

The new stack receives independently generated credential generations.

### Initial paired Worker-v2 enrollment (not steady-state rotation)

**GitHub operator retry guard:** repeat attempts (`GITHUB_RUN_ATTEMPT != 1`)
of existing `rotate-application` and `host-bootstrap-converge` requests
are refused during authorization, before any host or provider mutation.
A new comment is a new request: GitHub's read-only first-use preflight
now materializes all Issue #26 comment pages and the Rust owner rejects a
previous, malformed or displaced credential BEGIN marker. That read-only
observation is NOT a committed initial attempt. Actual pre-mutation BEGIN
write/readback and verified dual host-job provenance are still absent;
initial paired publication therefore remains disabled.

**Provider mutation fail-closed invariant:** a lost ACK for a credential Worker
secret PATCH is not proof of which opaque bytes were stored, even if the
latest Worker version advanced. The native rotation owner now reads version
metadata and stops without deploying or retrying that PATCH. A failed deploy
may be accepted only if read-only observation proves the exact previously
returned version is already active; otherwise it stops without a second
deploy. The initial pair publisher must add a durable pre-mutation journal
and both host attestations before it gains any mutation authority. No
cross-Worker atomicity or automatic replay is claimed.


**Integrated N1/N2 operator contract (under construction):** a single
`/credentials initial-pair-preflight <generation> <a|b>` request resolves the
exact immutable orchestrator through GitHub and checks both Worker identities,
active/latest versions, fixed A/B layout and independently bound permanent
Access service-token identities. This step is deliberately **read-only**:
`initial_publication_authorized=false` until both native host attestations,
a durable attempt identity and provider-side no-replay/partial-publication
handling exist. It never generates or publishes a secret. The Windows owner
provides `edge-console credential-initial-probe --install-root ...`: this
checks the exact installed activation, refuses any existing/partial local v2
store or managed runtime state, authenticates to the Windows-specific Worker,
and proves both exact dummy generations. It does not touch DNS, TUN, SCM,
proxy selection, or the foreign Cloudflare One adapter. The VM has its own
separate read-only initial probe. Neither report authorizes a publish by
itself; worker binding metadata cannot substitute for an authenticated GET.

**Pre-mutation identity and ownership (N1, Draft only):** the single
native `edge-orchestrator credentials initial-pair-journal-plan` policy
accepts an exact provider intent, fixed generation/slot, two distinct
64-character host attestation digests, immutable ReleaseSet and GitHub run
identity. It constructs a non-secret `BEGIN` comment; it never writes it.
The read-only `initial-pair-journal-observe` route is now part of the
existing GitHub credential preflight and rejects any prior/corrupt first
attempt. Neither command is a credential publisher, and their input digests
alone cannot authenticate a caller.

Native `edge-agent local credential-initial-attest` and `edge-console
credential-initial-attest` reuse each local owner's exact clean-state and
authenticated dummy A/B probe before deriving a shared domain-separated
SHA-256 evidence identifier. It binds role, first-use generation, slot,
provider intent, ReleaseSet, and local machine identity; Windows also
requires the exact installed ReleaseSet. **A hash is not a host signature.**
The GitHub workflow must independently prove which immutable binaries
actually ran on each owned *disposable* host and bind those verified outputs
to the single run before it can write an irreversible BEGIN. The existing
production VM/Windows root are not clean first-use hosts. Unknown ACK,
cross-request duplicates and half-published Workers must always stop without
repeating PATCH/deploy. Source-only acceptance does not prove this barrier.

For the VM, `edge-agent local credential-initial-verify <generation>` is
the nonmutating next acceptance boundary after initial-apply. It requires
only the exact unpromoted VM candidate (no active/previous), verifies the
rendered runtime environment against the protected candidate bytes,
observes all three running Docker application containers with the native
Bollard owner, and reuses existing `line2_quality::measure` to perform
five authenticated HTTP 204 samples through **each** of the six Line2
HTTP/SOCKS5/HTTPS direct/WARP endpoints. It prints
`line2_authenticated_endpoints=6` only after all samples pass, while keeping
external direct-vs-WARP egress identity and external TLS chain `UNPROVEN`;
these must be checked by independent external clients. It also keeps
`line1_authenticated_endpoints=UNPROVEN` and
`credential_pair_committed=false`. Thus a passed VM-local Line2 gate is
neither a Windows tunnel proof nor permission to promote a credential.

The integrated PR must continue beyond preflight to the **single full initial
transaction**, staged source-only bundle, distinct host activation and
isolated authenticated Line1/Line2 acceptance before merge. Do not treat these
new preflight commands as N1/N2 acceptance, and never run them as a covert
production or Windows-TUN cutover.

**Initial fixed A/B slot proof (N1, read-only):** Cloudflare secret binding
metadata never establishes that an A/B slot is unused. The VM's typed
`edge-agent local credential-initial-probe` first proves a clean host and
observes both well-known *nonsecret* Worker probe generations through the
permanent VM Access service identity. The existing Worker must return two
exact canonical dummy bundles of the VM projection (different generations),
with no live payload, and no ambiguity or missing response; otherwise it
fails closed. Provider and runtime mutations are zero, and no Worker payload
or Access secret is printed. Both probe generation constants are shared with
the Rust Worker publisher. Windows must independently prove its own projection
and the initial issue must enforce both proofs at the final provider publish
boundary before any A/B secret replacement. A successful VM-only proof does
**not** authorize the provider to issue credentials and is **not** evidence
of Line1/Line2 authentication. No credential rotation command may bypass
this separate initial issuance gate.

**Fresh VM policy-only bootstrap (N1, source only):** the typed
`edge-agent local bundle-stage-initial` accepts only an exact digest-bound
application bundle with immutable Compose, pinned image digests and Git-owned
runtime policy. It requires an empty/non-serving host and absent local v2 and
legacy credentials, stages the repository inputs **without** deriving a
`.env.runtime` and **without** starting Docker containers. The operation
refuses a second invocation, including after a partial or uncertain stage;
there is no cleanup/retry to mask an incomplete initial transaction. This
breaks the previous cycle in which normal `bundle-converge` required an
active Worker-v2 projection while `credential-initial-apply` required a
materialized application bundle. No independent secret authority is added.

**New isolated VM application primitive (N1, source only):** the VM's typed
`edge-agent local credential-initial-apply <generation>` is distinct from
rotation. Before a Worker fetch or any disk mutation, it additionally requires the
exact initial policy-only bundle marker, policy, Compose and image digests;
it rejects an existing
v2 store (including incomplete state), the old local credential file, an
existing runtime environment/rendered sing-box configuration, unavailable
Docker, or any of the three core application containers already present. It
fetches the exact VM projection with its permanent host Access identity,
stages one candidate and performs a forced core bootstrap. A partial or
uncertain attempt leaves the candidate and fails closed on repetition.
**Success means only `APPLIED_NOT_PROMOTED`, with authenticated traffic still
`UNPROVEN`.** No initial promotion path is exposed until independent
paired cross-host generation and authenticated endpoint evidence are provided.
The normal `credential-stage` and rotation `ApplyCandidate/Promote` retain
their own active-v2 requirements and must not substitute for this command.
This is not yet available through the production command grammar or deployed
to any VM. It must be used only by a future explicitly authorized disposable
fresh-VM acceptance transaction; never against the serving production VM.

Initial enrollment is a distinct bounded operation, because `/credentials rotate` requires
an already-active v2 generation on **both** hosts. Neither reuse rotation as initial
enrollment nor bypass this guard with direct local `promote`.

**Before any write** the operator must observe: the exact accepted ReleaseSet; the
Windows SCM/TUN/DNS condition and independently proven no-TUN control recovery;
the existing VM runtime and any legacy secret (presence only); both permanent
Cloudflare Access host identities installed behind their OS trust boundaries;
the fixed A/B Workers and a provably unused target slot; no local active/candidate/
previous v2 pointers or foreign owner ambiguity. Any missing proof is BLOCKED,
never inferred from a Worker version tag, `ready=true`, or a password file.

One GitHub-owned Rust credential operation creates **one** fresh snapshot with paired
least-privilege Windows/VM projections (matching delivery, tunnel-auth and
Reality-identity generation, fixed A/B slot). No GitHub runner observes or persists
plaintext; Workers hold only fixed encrypted secret bindings; local native owners
fetch exact generation using permanent host-specific Access identities.

On a new, isolated non-serving runtime, hosts may stage and validate candidates
without installing them as active. Runtime application requires an explicit typed
initial-enrollment gate, functional Line1 authentication on all four direct/WARP
endpoints through a bounded non-TUN path, and a proven return to independent
DNS/management access. A runtime already serving legacy traffic must not be
restarted or switched to perform initial enrollment without this safety proof;
testing a candidate is not evidence of successful application.

Both existing rotation `ApplyCandidate` and `Promote` operations require an
established local active Worker-v2 generation; no-active-v2 initial enrollment
cannot be simulated by these commands. VM promotion checks the exact rendered
candidate environment and local READY state; Windows promotion checks the exact
rendered candidate state/config. **These are necessary on-disk/readiness checks,
not proof that a running process consumed those credentials.** Container reload,
authenticated Line1 E2E and the independent Windows control recovery gate require
separate physical evidence before an explicit paired initial cutover is accepted.
If either host is unknown or disagrees, stop without claiming `ACCEPTED`; no
implicit legacy fallback, generation guessing, or retransmission after an
uncertain provider mutation. Only a successful paired cutover permits legacy
credential-file deletion and normal v2 rotation.

**Physical starting state 2026-10-11:** Cloudflare fixed A/B contract PASS;
VM native diagnostic `credential_state_present=false`, three running containers;
Windows SCM stopped, no TUN, direct DNS/HTTPS PASS, independent automated
recovery UNPROVEN. Therefore production initial enrollment is **BLOCKED**; code
can be built/tested, and safe read-only checks are allowed, but neither
`host-bootstrap-converge` (which includes privileged Windows activation) nor
`/credentials rotate` is a safe initial activation shortcut.

Operator terms:
- **active credential generation** — the validated local generation currently in use;
- **candidate credential generation** — fetched/staged generation not yet accepted.

Do not use `LKG generation` in operator-facing architecture.

Credential delivery uses one code owner deployed as two stateless Workers:
- Windows projection;
- VM projection.

The Windows Worker physically has no server-private secret binding.

Each Worker has a fixed two-slot encrypted A/B buffer. A typed bundle contains its generation and
projection identity. The Worker returns an exact requested generation only when exactly one slot
matches; otherwise it fails closed.

A/B is a bounded rollback buffer, not a history database. Do not add KV/D1/R2/Durable Objects or a
secret database unless a concrete requirement proves the fixed buffer insufficient.

### Secret classes must remain separate

Do not rotate unrelated secrets together merely because an old file grouped them.

Separate lifecycles include:
- client tunnel authentication generation;
- server Reality/private identity;
- Line 2 proxy authentication;
- Cloudflare Access machine identities;
- Mesh node token;
- provider API/control credentials.

The accepted v2 application projection boundary is derived from actual consumers:

```text
single /credentials snapshot builder
        |
        +-- tunnel-auth generation
        |     '-- direct + WARP UUID / Hysteria2 password / Reality short ID
        |          projected identically to Windows and VM
        |
        +-- Reality-identity generation
        |     +-- Windows: direct + WARP public keys only
        |     '-- VM:      matching private keys only
        |
        '-- Line 2 proxy-auth generation
              '-- VM only
```

These are three independent application credential lifecycles. The initial fresh-v2 snapshot may
create fresh values for all three, but later tunnel-auth rotation must not imply Reality server
identity rotation, Reality identity rotation must not imply Line 2 proxy-auth rotation, and vice
versa.

Each selected credential class is generated once by the GitHub-only `/credentials` owner and then
projected least-privilege. Reality keypairs are generated once per Reality-identity generation: the
private half is projected only to the VM and the corresponding public half only to Windows.
Cloudflare Access identities, Mesh node tokens and provider/control credentials are not application
projection fields.

The fixed A/B `CredentialDeliveryBundle.generation` is a delivery-snapshot revision. Nested
tunnel-auth, Reality-identity and Line 2 proxy-auth generations express their independently rotating
lifecycles.

Real credential bundles additionally carry explicit fixed-slot identity (`A` or `B`). Phase 6A
dummy bundles leave it unspecified so their accepted wire bytes remain unchanged. Local active
credential state records the active delivery generation and slot.

Initial contract installation may atomically install Worker code plus both fixed secret slots.
Windows and VM projections of one credential snapshot use the same outer delivery generation and the
same fixed slot; independent per-projection A/B cursors are forbidden.

Steady-state rotation is narrower: replace exactly the inactive fixed slot and leave the active slot
untouched. The system must not require plaintext readback of the active Worker secret, re-upload both
slots merely to rotate one candidate, or introduce a second plaintext secret database. Therefore a
steady-state inactive-slot publication is a typed class-scoped `CredentialDeliveryBundle` rotation delta: the GitHub-only owner generates and projects only the
selected class. Each host-local owner merges that delta with its already validated active local full
projection and persists the resulting full candidate bundle in its existing private A/B store. Unselected
secret classes never leave the local owner merely to be copied forward. A Windows Line 2 delta carries
no Windows secret material but still advances the paired outer delivery generation/slot.

Candidate publication is not activation; runtime owners promote only after both projections and functional
verification pass. An uncertain slot mutation is resolved by read-only exact-generation
re-observation before any replay.

Operator-visible application rotation is class-scoped. The independent classes are
`tunnel-auth`, `reality-identity` and `line2-proxy-auth`; rotating one must preserve the other
two generations. Windows and VM Cloudflare Access host identities are separate permanent
(`forever`) identities with explicit create-once bootstrap/recovery semantics and must never rotate
implicitly as a side effect of application credential rotation or retry. The accepted Stage-2
`fresh-v2-*` and contract-proof operations are migration/proof surfaces, not steady-state commands.

Non-secret endpoint/domain/port policy remains Git-owned desired state and is not duplicated into
credential payloads.

VM and Windows runtime owners may fetch, validate, stage, activate and roll back typed credential
state. They do not generate a replacement production identity when the requested generation is
missing. Missing desired generation is fail-closed while an already validated active generation
continues to serve traffic.

Do not add a generic secret map, arbitrary payload bytes, first-party JSON secret contract, second
secret database, new credential daemon or dedicated credential crate.

### Local credential state

Local runtime persistence uses one crash-safe pattern on both owners:

```text
private credential root/
  state.pb                 # typed non-secret refs only
  bundles/
    <sha256>.pb            # immutable canonical CredentialDeliveryBundle bytes
```

`state.pb` contains only projection plus bounded `active`, `candidate` and `previous`
references (delivery generation, A/B slot and canonical bundle digest). Secret payload bytes never
enter SQLite, JSON, logs or a second metadata database.

Transition invariants:
- staging writes/verifies the immutable candidate blob first, then atomically updates `state.pb`;
  active bytes are never rewritten by staging;
- promotion is one atomic pointer-state replacement: candidate becomes active and the former active
  becomes previous;
- rollback swaps active/previous by the same typed pointer transition;
- candidate and previous never coexist because fixed A/B has only one inactive slot;
- previous must be explicitly dropped after the bounded grace period before another candidate can be
  staged;
- restart/recovery decodes canonical `state.pb` and verifies every referenced bundle's projection,
  generation, slot, digest and canonical protobuf bytes before runtime use.

Physical roots:
- Windows: `C:\sing-box\state\secrets\application-v2`, inside the existing controller-owned ACL
  boundary (SYSTEM/Administrators/EdgePlatformController; NetworkService runner excluded);
- VM: `<stack-parent>/runtime-secrets/application-v2`, inside the existing root-owned private
  runtime-secret boundary; Unix directories/files remain mode `0700/0600`.

Candidate acquisition and staging are deliberately narrower than the persistence API:
- self-hosted runners carry only non-secret operation intent such as projection, generation and slot;
- runners do not fetch, receive, log, cache or artifact credential plaintext;
- the local owner validates projection/generation/slot/canonical bytes and stages through the accepted active/candidate/previous store;
- staging cannot activate or silently generate replacement credentials;
- Windows and VM never share fetch identity or projection-private material;
- direct local-owner Worker fetch through the projection-specific permanent Access host identity is canonical;
- Windows and VM host identities are physically distinct and are not reused as bounded proof identities;
- project-specific custom X25519/HKDF/AEAD transport is not canonical and must not return.

The two Workers remain bounded A/B delivery mailboxes, not secret-history or runtime-state authorities.
A `/production diagnose` read-only classification may report
`credential_rendered_source=V2_ACTIVE_RENDERED` with nonsecret generation IDs,
or `UNPROVEN` with a bounded reason (including an obsolete local store).
A v2 rendered file alone is **not** end-to-end authentication proof; the
diagnostic explicitly reports `credential_running_source=UNPROVEN_WITHOUT_CONTAINER_RELOAD_PROOF`.
`healthy=true` without these proofs is local Docker/Compose readiness only.

## 5. Runtime autonomy and recovery

Cloudflare availability is not on the proxy data path.

A healthy VM/Windows runtime continues from validated local active state when Cloudflare credential
delivery is unavailable. Reconcile/rotation/recovery requiring a missing generation fails closed
without destroying the active generation.

Generated files are reproducible artifacts:

```text
production.textproto
        +
typed active local secret state
        |
        v
typed renderer
        |
        +-- .env.runtime
        +-- sing-box JSON
        |
        v
runtime validation / activation
```

Generated env/JSON must not become competing durable authorities.

## 6. Provider and transport boundaries

### Vultr

`edge-provider-vultr` is the only Vultr API adapter.

Mutations follow:
`observe -> plan -> exact authority -> one bounded mutation -> re-observe -> verify`.

Uncertain mutation outcomes are resolved by read-only re-observation, never blind replay.

### Runtime-host transport

Both persistent runtime hosts use repository self-hosted GitHub runners with outbound-only
connectivity.

Windows:
`GitHub -> self-hosted NetworkService runner -> SCM EdgePlatformController`.

Linux:
`GitHub -> self-hosted low-privilege runner -> local root-owned typed runtime owner`.

Routine production runtime/credential operations do not use hosted-runner SSH, temporary /32 ingress,
SSH tunnels or TCP/gRPC agent transport. The only retained remote-agent consumer in Macro Stage 1 is
the disposable acceptance/bootstrap path, where a fresh temporary VM has no self-hosted runner yet.
It is not steady-state production transport.

The standalone `/mesh` and public `/production target-plane-*` operator namespaces are retired.
Production Mesh provider state remains owned by the GitHub-only typed production composition;
Mesh container/runtime state is owned by the VM local runtime owner through Compose/Bollard. There
is no second normal Mesh transport or public target-plane control surface.

The remaining tonic/`edge-trust` server surface is named `acceptance-serve` and has no default
invocation. Production enrollment disables `edge-agent.service` and proves port 50061 absent; the
server code remains only because disposable acceptance still needs a bootstrap-time RPC observer.

Persistent-host bootstrap is explicit: `/production enroll-runtime` may temporarily acquire the
canonical /32 SSH lease to create/verify the VM substrate, converge VPC attachment, install the exact
ReleaseSet local owner and register the low-privilege runner. The command compensates the lease before
PASS. It is enrollment/reinstallation, not steady-state application transport.

Neither runner has provider credentials or plaintext application credential authority. Privileged
host mutations cross only explicit typed local boundaries.

Production rollback must use the same accepted persistent-host transport as normal production
runtime operations: self-hosted runner -> typed local owner. Historical rollback semantics and
authorization may be reused, but the legacy implementation that acquires transient support access
and performs remote rollback is not a steady-state operator path and must not be exposed as-is.

## 7. Diagnostics contract

Final diagnostics must provide secret-safe read-only evidence for:

- Git desired revision and accepted ReleaseSet;
- exact release binary/image identities;
- Vultr machine/VPC/firewall/support-access state;
- VM self-hosted-runner identity plus local typed Docker Compose/Bollard/runtime readiness;
- direct/WARP functional probes;
- Cloudflare account/Mesh/Zero Trust/Access state;
- credential Worker identity and generation metadata without values;
- shared DNS record observation;
- Windows SCM path/identity/state;
- Windows active/candidate credential generation;
- local sing-box config/runtime ownership;
- routes/DNS/TUN/system-proxy ownership when those slices are accepted;
- rollback/reboot readiness;
- bounded failure reasons.

A diagnostic result does not repair the machine.

### Accepted native read-only production diagnosis (2026-10-11)

The existing `/production diagnose` GitHub operation is the canonical one-command entry point
for production VM and provider observation. Its two independent read-only jobs must run
concurrently: provider inventory through the existing GitHub-hosted typed orchestrator;
VM runtime observation through the existing low-privilege, outbound-only VM self-hosted
GitHub runner invoking its installed root-owned Rust `edge-agent local diagnose`
through the fixed `sudo` allowlist. Observation must not require the newest runtime
binary to be installed, a completed provider inventory, a rebuild, SSH access, an
extra VM-side GitHub Release lookup, Python interpreter, daemon, scheduler or polling
loop. An installed/desired revision mismatch is **reported**, not hidden by blocking
read-only observation; the host filesystem ownership boundary must remain enforced.
`converge`, `verify` and `rollback` retain their separate exact accepted
ReleaseSet and binary-identity gates. A diagnostic observation NEVER authorizes mutation.

**Physical acceptance:** [PR #339](https://github.com/iamaman11/sing-box/pull/339),
[exact-head CI #38104473521](https://github.com/iamaman11/sing-box/actions/runs/38104473521),
[no-rebuild promotion #38104822020](https://github.com/iamaman11/sing-box/actions/runs/38104822020),
and [real VM diagnose #38104889553](https://github.com/iamaman11/sing-box/actions/runs/38104889553)
PASS. On the last run, the VM runtime job completed before provider inventory;
the native owner reported `healthy=true`, `ready=true`, Docker/Compose available,
three expected exact-image containers running, zero missing/degraded reasons,
network object counts, and Mesh not ready. Credential state observation succeeded
but `credential_state_present=false`. Provider inventory later completed read-only.
These facts prove **observability and local runtime readiness**, not authenticated
end-to-end Line1 datapath acceptance.

**Coverage limit — do not misreport as complete:** current `local diagnose` does
not by itself establish Hysteria2 per-endpoint authentication, server-side rejection
reason, Windows/VM active credential-generation parity, real browser DNS/traffic
through Windows ManagedTun, independent DNS/control recovery or reboot safety.
The 2026-10-10 `authentication failed, status code: 400` remains causally UNPROVEN;
`ready=true` and running containers do not supersede that observation.
Report each unobserved layer as `UNKNOWN/UNPROVEN`, never `PASS`, and distinguish
missing local v2 credential-state from proof of absent legacy runtime credentials.

Next diagnostic improvements belong inside the **existing typed native owners**,
not workflow shell: bounded nonsecret per-Line1 functional result and rejection
classification, active generation/endpoint identity metadata from each host, and
specific correlation/time/first-failure provenance. Each output must separate
`observed`, `blocked`, `unknown` and `not_applicable`, and state the next safe
read-only check; no plaintext, password, keys, credential hashes, or arbitrary
container log exports. The GitHub Actions queue adds unavoidable scheduling latency;
the native local probe should remain bounded and avoid unrelated network prerequisites.

Installed Windows diagnostics/status must observe the SCM-owned managed runtime directly and must
not treat the intentionally absent server-agent RPC listener on port 50061 as a Windows health
failure. The 50061/`acceptance-serve` surface is transitional only for disposable bootstrap-time
acceptance. Runtime dial `server_ip` and logical tunnel/TLS domain are distinct diagnostic fields
and must not be compared as interchangeable identities. Persisted selector intent remains canonical
while start/restart recovery consumes it; status must distinguish desired intent from live observed
selection rather than deleting or silently overriding that recovery state.

## 8. Full lifecycle closure

The target architecture must cover the complete supported cycle through typed bounded owners:

```text
bootstrap/enroll
 -> provision
 -> exact ReleaseSet deploy
 -> converge
 -> verify
 -> diagnose
 -> upgrade
 -> release rollback
 -> credential rotation/rollback
 -> reboot/recovery
 -> cleanup/destroy
 -> zero-leak verification
```

Normal updates must require no manual secret copying or legacy checkout.

VM reconstruction target:
Git desired state + exact ReleaseSet + provider APIs + credential plane.

Windows reconstruction target:
exact ReleaseSet + one-time machine enrollment + active credential generation.

Recurring manual host surgery after cutover is unfinished architecture unless it is an intentional
external governance or one-time trust-enrollment boundary.

## 9. Protobuf and serialization policy

New first-party JSON contracts are forbidden by default.

Use:
- protobuf binary (`.pb`) for machine contracts and durable machine state;
- protobuf text format (`.textproto`) for human-authored Git desired state;
- Rust semantic/domain types behind protobuf boundaries.

JSON is allowed only when an external runtime/protocol physically requires it, such as sing-box
configuration or a third-party JSON API.

Existing first-party JSON is frozen migration debt. It may only shrink.

The production textproto is compiled/validated through the repository-owned protobuf schema.
Do not create a parallel `production.json`.

## 10. Persistence policy

Do not treat SQLite itself as an architectural goal.

Keep SQLite where genuinely transactional local mutable state makes the implementation simpler and
safer. Remove obsolete tables after their owners disappear, especially historical
`secret_refs`/`trust_store`/provider-deployment state.

Do not replace a mature transactional boundary with hand-rolled files solely to remove a
dependency.

## 11. Deletion-first rule

When a new accepted path replaces an old path, delete the old path after live-consumer proof.

Deletion requires evidence, not intuition. For each candidate record:
1. current steady-state owner, if any;
2. exact live consumers;
3. recovery/rollback consumer, if any;
4. last accepted evidence that the replacement path works;
5. classification as CANONICAL, TRANSITIONAL, DELETION_CANDIDATE or HISTORICAL_EVIDENCE.

A DELETION_CANDIDATE is removed as one logical contraction with its obsolete tests, workflow glue,
privilege entries, persistence projections and documentation. Do not leave compatibility shims with
zero consumers.

### Stage 4A exit decision — CLOSED

Stage 4A was bounded consumer-driven contraction, not an open-ended cleanup program. The terminal
repository-wide compiler/topology exit decision found no newly exposed complete zero-consumer
transitional vertical slice, so Issue #26 records `STAGE4A=CLOSED`.

After an active contraction is terminally accepted, perform one fresh repository-wide last-consumer
audit. For every remaining transitional boundary, include production, acceptance, bootstrap,
re-enrollment, recovery and rollback consumers.

- If a complete transitional vertical slice has zero consumers, it may become the next single
  deletion slice.
- If every remaining transitional boundary has at least one real consumer, Stage 4A is complete.
- Do not create a replacement owner, transport, state store, compatibility API or workflow merely to
  make a live boundary removable.
- Managed TUN is now permitted only inside the explicit Stage 4B cutover owned by Issue #26.
- Do not reopen accepted Stage 4A deletions merely for confidence or isolated warning cleanup.

### Stage 4B entry contract — managed Windows TUN

Stage 4B is one bounded ownership cutover, not another cleanup programme. The existing Windows ownership
chain remains unchanged:

```text
Git desired state + exact ReleaseSet
        -> EdgePlatformPrivilegedDispatch (bounded privileged bridge; never runtime owner)
        -> SCM EdgePlatformController (sole Windows runtime owner)
        -> managed sing-box
        -> Windows TUN
```

Current Stage-4B implementation state:

- canonical production is `MANAGED_TUN`; the mode flip, exact-head candidate, no-rebuild promotion and
  physical managed-TUN converge/diagnose datapath proof have already been accepted;
- the Git-owned `windows_datapath_mode` remains the only durable datapath desired-state authority and is
  part of Windows candidate identity;
- `windows-physical.yml` remains the sole physical Windows operator boundary. Release transitions are
  single-owner: the existing privileged activation owns stopping the exact managed child, immutable release
  activation and SCM reconciliation; the workflow does not duplicate that stop;
- typed Windows process observation distinguishes managed / conflicting external / absent ownership;
- SCM `EdgePlatformController` is the sole steady-state runtime owner. It performs bounded startup
  convergence, is not a watchdog/polling loop, and a managed sing-box child is valid only while owned by the
  current controller process;
- controller Stop/Shutdown/normal exit stops only the exact managed sing-box before the service reports
  Stopped. If startup finds one exact managed-config child whose parent is not the current controller, that
  child is treated as an orphan: stop only that exact managed child and start a new child under the current
  controller. Any true external sing-box remains fail-closed and untouched;
- `/windows stop` and `/windows start` are transient runtime controls only. They do not change ReleaseSet
  authority or durable mode; ordinary stop deliberately leaves SCM running, and start is idempotent when the
  exact managed runtime is already healthy;
- if NetworkService cannot classify a sing-box while SCM is Stopped, recovery may continue only for
  `/windows converge` after the existing SYSTEM `privileged-runtime-evidence` proves zero external owners.
  That read-only proof authorizes the existing privileged release transition; it does not create a second
  process manager or allow arbitrary process mutation;
- `edge-diagnostic` uses native Windows SCM/process/IP Helper observation for persistent diagnostics;
  bounded PowerShell remains workflow glue/recovery only and must not become a resident observer;
- legacy launch owners are disabled and zero external sing-box owners are required in canonical
  `MANAGED_TUN` steady state. Stage 4B.2-C now concerns resilience/repair/reboot acceptance, not another
  mode flip or another cutover mechanism.

#### Required implementation shape

The numbered requirements below are the accepted design constraints that produced the current implementation; references to the earlier `PROXY_ONLY` phase describe historical acceptance gates, not current production mode.

1. Add one typed Windows datapath mode to the existing protobuf desired-state boundary, with an explicit
   `PROXY_ONLY` -> `MANAGED_TUN` transition. No environment flag, generated-JSON inference or second
   desired-state file may select the mode.
2. Keep that Git-owned mode only in the embedded canonical `ProductionDesiredState`. It must not be
   copied into `WindowsRuntimeState`, `WindowsRuntime`, or `WindowsActivationState`: those are runtime
   projection/release-file identities, not a second desired-state authority. The exact accepted Windows
   binary reads its embedded desired mode through one canonical renderer used by initial materialization,
   credential apply/rollback, reboot convergence and cutover. Generated sing-box JSON remains a consumer
   artifact and never selects its own mode.
3. While Windows binaries compile canonical production desired-state bytes, include
   `infra/production/production.textproto` in Windows candidate input identity and add a regression test
   proving any production desired-state byte change invalidates artifact reuse. Removing the compile-time
   dependency later is allowed only if the replacement ReleaseSet/activation contract carries the same
   immutable authority explicitly.
4. Add one bounded local Windows ReleaseSet rollback to the existing privileged bridge. It may target only
   the exact locally verified `previous.pb`, must require no Git/provider/network access and must not accept
   an arbitrary release digest. Rollback restores the previous exact binary/activation authority without
   swapping the abandoned current release back into `previous.pb`; after success `current.pb == previous.pb`,
   so a repeated rollback fails closed before runtime stop instead of toggling between releases. That
   previous SCM owner then rematerializes runtime JSON from the unchanged typed runtime projection and its
   own embedded canonical desired state before startup. Repair is rematerialization, not upgrade: the physical
   workflow must reject a repair target that differs from the exact current ReleaseSet before stopping runtime.
   Lifecycle verification must execute the immutable
   diagnostic named by the verified active activation rather than infer datapath mode from a stable copy
   built for a different release. Fail-closed rollback must likewise execute from the immutable current
   console, never from the stable console path that rollback itself must refresh. No duplicated mode marker
   participates in rollback.
5. For the pinned sing-box line, Windows TUN routing/DNS is owned by sing-box itself: TUN + `auto_route`,
   `strict_route`, native/hijack DNS, existing `route.auto_detect_interface`, exact endpoint route
   exclusions and stable DIRECT loop-prevention rules. The `warp-svc.exe -> direct` process rule remains
   a loop-prevention boundary, not ownership of CloudflareWARP. For MANAGED_TUN child creation the controller
   may enable its already-present `SeDebugPrivilege` only for the sing-box spawn, then must restore the
   controller token immediately; the child inherits the enabled privilege needed for Windows process-name
   lookup. Linux-only `auto_redirect` is not a Windows mechanism and must not be introduced here.
6. Extend the existing `edge-diagnostic` with native read-only Windows network observation sufficient to
   prove the exact managed TUN adapter, addresses, routes and per-interface DNS. Route exclusions are
   acceptance-tested by Windows best-route selection to the exact runtime server IP: the selected interface
   must not be the managed TUN. The NetworkService runner must obtain that non-secret server IP through the
   existing typed `ControllerStatus.deployment.server_ip` localhost RPC/console path; it must not read
   controller-private `state/secrets/runtime-state.pb` or widen that ACL. Do not require an artificial
   explicit /32 route merely because the excluded destination is absent from sing-box's auto-route prefixes.
   Prefer Win32/IP Helper APIs for persistent diagnostics; bounded PowerShell `Find-NetRoute` is acceptable
   only inside the existing physical workflow. Do not create WMI/PowerShell parsing, a duplicate projection
   or a resident observer merely for acceptance.
7. Add one typed Windows process observation in the existing local-runtime boundary that distinguishes
   the exact managed process, any external sing-box process and absence. Mutations may act only on the
   exact managed process. While canonical production is PROXY_ONLY, one managed mixed-proxy runtime may
   coexist with the observed external sing-box because it owns no TUN/routes/DNS; duplicate managed owners
   remain fail-closed. MANAGED_TUN always treats any external sing-box as evidence/STOP until the explicit
   physical cutover has pre-authorized that exact observed owner.
8. Add startup convergence inside the existing SCM `EdgePlatformController`: after reboot/service start,
   an installed, validated managed runtime is started when absent; an already-running exact managed runtime
   is a NOOP; an unexpected/external sing-box remains fail-closed and untouched. Do not add a Scheduled
   Task, watchdog daemon or second startup owner.
9. Do not widen the SCM service identity merely by assumption. The live cutover first proved that the
   existing `NT SERVICE\\EdgePlatformController` token could not create/configure the managed TUN:
   pinned sing-box failed with `configure tun interface: Access is denied.` The accepted least-privilege
   decision is to keep that dedicated virtual service identity and grant only that principal membership
   in the local built-in Administrators group required by the Windows TUN/Wintun path. Do not switch the
   controller identity to LocalSystem and do not create a second privileged TUN owner.
10. Cloudflare One Client remains a foreign, independent owner. Its local DNS proxy addresses
   `127.0.2.2` and `127.0.2.3` must **never** be treated as proof that our application owns an
   adapter. Retire the former PowerShell DNS-reset-on-stop/startup-failure path: it selected interfaces
   by those DNS addresses and could reset Cloudflare One Client DNS. The managed Windows TUN DNS
   (`172.19.0.2`) is separate; this project must not reset/rewrite the `CloudflareWARP` adapter.
   If `warp-svc` re-pins managed TUN DNS onto that foreign adapter, observe without mutation and
   keep TUN teardown/rollback blocked until true independent DNS and control-channel restoration
   are proven. Cloudflare One and sing-box must operate simultaneously with explicit nonoverlapping
   route and DNS authority; no second owner, DNS watchdog, fallback daemon or unproven reset.

#### Stage 4B.2-C DNS independence — source-proven decision (2026-10-09)

**Observed Windows reality, not a diagnosis of router failure.** The installed immutable
ReleaseSet `1ebe355143ac3d59a11d4c40755e1f8aa2aa9060c957822d831f18d4ace667b5`
pins sing-box `v1.14.2` (Windows ZIP SHA-256
`c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32`).
Its exact `go.mod` pins `github.com/sagernet/sing-tun` at
`ddaa4ca25e3bcb776d6ce81f4477b3becb5426de`.
On this Windows host, the read-only local agent proved:
`warp-svc.exe` sets the foreign CloudflareWARP adapter's DNS to
`172.19.0.2,192.168.100.1`; Ethernet obtains `192.168.100.1` via DHCP;
the latter has a physical on-link route but an explicit DNS query there
timed out. WFP read-only inspection showed `sing-tun` sublayer PERMIT exact
sing-box process (weight 13), PERMIT managed TUN interface (weight 11) and
BLOCK remote port 53 (weight 10). TCP/53 reported Winsock 10013; router
TCP/80 and TCP/443 worked. This **proves current active TUN policy blocks
ordinary Ethernet DNS**, not that the router resolver is broken or would
work after TUN failure. The user confirmed physical administrator console
access, not a completed automatic recovery test.

**Exact pinned upstream behavior**, not speculative Windows WFP changes:
- `sing-tun/tun_windows.go`: both `dns_mode=native` and
  `dns_mode=hijack` configure native DNS **on the project TUN adapter**
  (`configure`, `luid.SetDNS`); `disabled` does not configure TUN DNS.
- With `strict_route=true`, sing-tun opens `FWPM_SESSION_FLAG_DYNAMIC`.
  The additional Windows remote-port-53 WFP BLOCK v4/v6 is installed
  **only when** `DNSModeOrDefault() == DNSModeHijack`; not when `native`.
  Thus `native + strict_route` is a *source-supported test candidate* for
  simultaneous ordinary Ethernet DNS, **not** a verified no-leak policy.
- A clean close calls `FwpmEngineClose0`. Windows WFP dynamic-session
  lifecycle removes its associated objects at close/process rundown by
  platform contract. This does **not** prove real host route/DNS/SCM/
  CloudflareWARP/GitHub Runner recovery after sing-box failure.
- `route_exclude_address`, direct `warp-svc.exe` routing and `strict_route`
  alone **cannot** grant ordinary Windows processes an exception to the
  observed host-wide `hijack` port-53 block. Never add ad-hoc WFP permit
  rules, a DNS watchdog, a second controller or DNS writers to bypass it.

**Decision matrix / current authority:**
- `hijack + strict_route=true`: **CURRENT ACCEPTED HOST POLICY** for normal
  single-TUN DNS leak prevention, but fails the stronger invariant that
  native Ethernet DNS can be independently used while TUN is running.
- `native + strict_route=true`: **CANDIDATE ONLY**. Retains per-TUN native
  DNS settings and strict WFP session, omits the extra port-53 BLOCK; Windows
  multihomed resolver behavior can leak queries via Ethernet or WARP.
  Never infer leak safety from `sing-box check` or a passing DNS probe.
- `disabled`, or disabling `strict_route` alone: **NOT AN ACCEPTED
  REPLACEMENT**. Changes resolver/anti-leak semantics without the required
  independently scoped DNS policy or evidence.

**Bounded acceptance, in order; no change to production on the design step:**
1. Prove source and dependency identity; validate a *proposed* candidate
   offline with the exact released `sing-box check` and renderer unit
   tests, including WARP Mesh/excluded routes and no writes to foreign DNS.
   Keep canonical desired mode/config `hijack` until explicitly accepted.
2. Before any physical activation, agree on which Windows resolver requests
   may use independent Ethernet versus sing-box's managed DoT. Specify
   explicit non-TUN DNS authorization/anti-leak checks for both Windows
   multihomed queries and foreign Cloudflare One/Mesh, plus IPv6.
   A standalone direct `Resolve-DnsName -Server 192.168.100.1` success
   would prove only an explicitly targeted resolver, not DNS isolation,
   automatic failover or GitHub runner independence.
3. Require one pre-authorized, bounded **physical** evaluation with owner
   present at the confirmed local administrator console, exact release
   manifest, before/after network DNS/route/WFP evidence, positive DNS
   tests on each required path, negative DNS leak tests and Cloudflare
   Mesh functionality. Define and prove deterministic reversion before
   changing the working TUN. Do not execute stop/crash/reboot/rollback
   to discover whether a recovery path exists.
4. Separately prove TUN-absent Windows DNS fallback, removal of dynamic
   WFP filters, non-TUN network and independent GitHub control transport.
   The existing GitHub broker/token path **uses TUN** while it is healthy.
   Ethernet DHCP default route and a manual administrator console are
   not equivalent to a verified automatic remote recovery channel.

**Current result:** `SING_TUN_DYNAMIC_WFP_SESSION=SOURCE_PROVED`;
`HIJACK_OUTSIDE_TUN_DNS_BLOCK=HOST_PROVED` (historical label preserved
only for this decision text); `NATIVE_MODE_SIMULTANEOUS_DNS=UNTESTED`;
`NATIVE_MODE_NO_LEAK=UNTESTED`; `AUTOMATIC_RECOVERY=UNPROVEN`.
**Historical 2026-10-09 gate state (superseded by issue #26):** Stage 4B.2-C was OPEN and fault injection BLOCKED at that checkpoint. The later bounded ManagedTun acceptance is CLOSED; independent automatic no-TUN DNS/GitHub recovery and ManagedTun→ProxyOnly teardown remain unproven. Do not treat this historical paragraph as a current execution gate.
Canonical operator execution cursor and local evidence: issue #26.
Upstream exact sources:
https://github.com/SagerNet/sing-box/blob/v1.14.2/go.mod ;
https://github.com/SagerNet/sing-tun/blob/ddaa4ca25e3b/tun_windows.go ;
https://sing-box.sagernet.org/configuration/inbound/tun/ ;
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management .

#### Stage 4B execution gates

**4B.1 — code-proven candidate, no live TUN mutation**

- introduce the typed datapath mode while canonical production remains `PROXY_ONLY`;
- implement and unit-test the single renderer's `MANAGED_TUN` branch;
- make canonical production desired-state bytes part of Windows candidate identity and prove a mode change
  cannot reuse an artifact compiled with the previous mode;
- implement and test bounded local rollback to exact verified `previous.pb`; the previous exact binary
  must rematerialize runtime/config from its own embedded desired mode with no duplicated mode field;
- validate the exact pinned Windows sing-box config with `sing-box check` in CI;
- implement typed managed/conflicting/absent process observation, native network diagnostics and SCM startup convergence;
- lock the existing Windows workflow/router as the sole physical owner boundary; do not add a speculative
  cutover mutation command in 4B.1. The fixed operation is derived and added in 4B.2 only after read-only
  external-owner/restore proof;
- exact-head CI and no-rebuild promotion must PASS.

**Mandatory proxy-only operator lifecycle gate — before 4B.2**

4B.1 is closed only after exact-head CI and no-rebuild promotion. Before any `MANAGED_TUN` mode flip
or cutover work, the accepted PROXY_ONLY application must prove the real ChatGPT operator lifecycle
through the existing single GitHub/Windows boundary:

- `/windows diagnose`: read-only activation/SCM/process/network evidence plus a live managed proxy trace;
- `/windows converge`: install/update the exact accepted protected-main ReleaseSet with no Windows build,
  start only the exact managed PROXY_ONLY runtime, and prove DIRECT + WARP egress;
- `/windows repair`: re-download the same accepted durable ReleaseSet into the bounded alternate immutable
  slot, preserve `previous.pb`, retarget the one SCM/privileged owner, and re-prove DIRECT + WARP;
- `/windows rollback`: stop only the exact managed process and restore exact verified `previous.pb`;
- `/windows stop` / `/windows start`: transient runtime controls only. They may stop/start only the exact
  managed sing-box through the existing controller RPC, must not change ReleaseSet authority or durable
  datapath desired state, and leave the SCM controller running. `start` is idempotent: an already healthy
  managed runtime is NOOP, not a restart. If a read-only pre-state diagnostic fails because an external
  sing-box conflicts with MANAGED_TUN, the workflow may collect only the existing bounded SYSTEM
  `privileged-runtime-evidence` before failing; it must not stop or adopt that external owner. A service
  restart or Windows reboot intentionally re-applies startup convergence, so `stop` is a temporary pause
  rather than a second persistent desired-state mechanism;
- reconverge to the current accepted ReleaseSet and repeat read-only diagnosis.

The external working sing-box must have the same observed process identity before and after every managed
operation. TUN, route, DNS and system-proxy mutation remain forbidden throughout this gate. A failure in
install, functional proxy verification, repair, rollback or reconvergence blocks 4B.2.

**4B.2 — bounded physical handoff and cutover acceptance**

Before the handoff, read-only observation must prove the exact legacy process/startup owners, legacy
network ownership and a bounded restore procedure. The installed managed side must also have an exact
locally verified `PROXY_ONLY` previous activation and the bounded local ReleaseSet rollback must already
have passed a physical no-TUN proof. These are cutover rollback evidence, not adoption of legacy
config/secrets as project authority. If either rollback path cannot be proven, STOP rather than guess.

The canonical application must not gain a generic legacy Scheduled-Task/process manager merely for this
one migration. Once issue #26 records `READY_FOR_LEGACY_HANDOFF`, the one-time operator handoff may
freeze/stop the exact pre-proven legacy launch owners outside the steady-state application. The next
canonical action is read-only diagnosis: it must prove that legacy controller/runtime/listeners cannot
resurrect, legacy TUN route/DNS ownership has been released, canonical `PROXY_ONLY` remains healthy,
and foreign shared-host projects were unchanged. Any mismatch blocks MANAGED_TUN.

The production mode flip is itself a separate Git-authorized candidate transition: change canonical
desired mode to `MANAGED_TUN`, require exact-head CI and no-rebuild promotion for that exact revision,
and resolve the resulting exact accepted ReleaseSet before the first managed Windows datapath mutation.
A `PROXY_ONLY` ReleaseSet must never be treated as authority for the TUN cutover.

Then activate that exact accepted `MANAGED_TUN` ReleaseSet through the existing Windows privileged
boundary and prove all of the following before declaring ownership transferred:

- exact TUN adapter/address and expected IPv4/IPv6 route ownership;
- endpoint/control-plane bypass and no self-routing loop;
- native DNS ownership, resolution and no stale dependency on the retired legacy resolver;
- DIRECT selector egress and WARP selector egress;
- managed restart and failed-candidate last-known-good recovery;
- SCM service restart and full Windows reboot recovery without a second startup mechanism;
- bounded cutover rollback restores connectivity if acceptance fails;
- repeated read-only verification is stable after success.

**4B.3 — protocol/config operator completion**

Do not add a generic JSON editor. The existing renderer and selector model remain the only sing-box
configuration/route owners. Durable defaults are typed Git desired state; bounded experiments may select
only the closed allowlist of rendered transports through the existing selector boundary and restore the
previous selection afterward.

**4B.4 — bounded Line 1/Line 2 quality acceptance**

Add quality testing only as a typed bounded operation in the existing controller/operator contract.
It compares the four Line 1 transports and the six Line 2 proxy endpoints under stable per-group policy
and returns evidence, not durable state. It must not create a benchmark daemon, scheduler, second status
database or another sing-box process. Transient Line 1 selection must restore the previous live selector
on every terminal path.

**4B.5 — Line 3 Android Mesh functional closure**

Before new-VM server Mesh acceptance, Cloudflare's *node* profile is a required
account-level prerequisite: exact warp_connector selector, MASQUE Traffic and
DNS mode, and the Mesh CIDR. This is not an Android user-client profile.
`vm-server` preflight must check that node profile and shared account
prerequisites; Android device enrollment/real traffic remains a separate
4B.5 functional gate. Never bypass the missing node profile by renaming
the scope, and never mutate the active Cloudflare account via the
historical migration-only target-plane route.

Line 3 reuses the existing Cloudflare Mesh provider lifecycle, VM local Mesh runtime owner and
`vultr-cloudflare-mesh` container. A healthy connector or private/VPC CIDR route is not by itself evidence
of Android Internet egress. Public CIDR/hostname routing and any broader exit-node contract require
explicit current Cloudflare support, fresh provider plan/authority and real Android Traffic-and-DNS E2E
evidence. Do not infer a default route from generic CIDR support, do not add another connector/container,
and do not reuse or mutate MISH as an Android test surface.

Only after managed-TUN, Line 1/2 operator-quality acceptance and Line 3 functional acceptance pass does
the project enter Stage 4C final deletion/convergence. Stage 4C deletes legacy startup/config/secret glue
and any migration-only or recovery-only compatibility surface whose last consumer disappeared.

Known transitional examples remain live while these consumers exist: disposable
`acceptance-serve`/TCP 50061/tonic/`edge-trust`; bounded bootstrap SSH/support access for
`/production enroll-runtime`; read-only Zero Trust doctor/guardrails for disposable acceptance;
Device Profile/Split Tunnel writes for production target-plane; `application-lifecycle materialize`
for disposable acceptance; and typed DNS/Mesh/target-plane composition used by production or
acceptance.

Expected cleanup after convergence includes:
- production-facing duplicate Cloudflare workflows/commands;
- Windows controller provider/Deploy/Destroy/SecretRef/trust paths;
- Agent custom mTLS and `edge-trust` when unused;
- old bundle/remote deployment machinery when unused;
- obsolete SQLite tables;
- DPAPI/Vault/current-edge legacy secret paths after Windows cutover;
- superseded first-party JSON contracts;
- redundant YAML/shell/PowerShell plumbing.

Delete dead behavior before splitting large Rust composition roots.

## 12. Safety invariants

- Stage N1/N2 is closed only by physical clean-VM installation and **4/4 Line1 + 6/6 Line2 authenticated external traffic**, not by source CI or local READY.
- No helper PR, extra preparatory stage, new application service/agent/daemon, fallback credential or alternate transport may delay or substitute for that integrated delivery; see **Delivery lock** above.
- Keep production VM/DNS and stopped Windows TUN unchanged until separately accepted N3/N4 cutover gates; uncertain provider writes are never replayed.


- one owner per mutable resource class;
- no second desired-state store;
- no blind retries;
- no secret values in Git, Issues, logs, artifacts or Release assets;
- self-hosted runners do not receive application plaintext credentials;
- exact accepted artifacts only;
- mutations are re-observed and verified;
- generated external config is never first-party authority;
- no TUN/DNS/default-route/system-proxy ownership before its explicit gate;
- foreign projects remain no-touch at all times; legacy sing-box ownership changes only inside the explicit issue-#26 handoff gate.


### Disposable VM SSH failure visibility (N1/N2)

The existing native Rust `vultr-lifecycle substrate-verify` now reports one
`disposable_ssh_failure_forensics` observation on strict substrate failure,
before the existing cleanup. The same typed provider/firewall/controller-egress,
TCP:22 and strict SSH handshake-stage observer already used for application
acceptance is reused for the specifically owned `lifecycle-acceptance-1` VM.
Every other machine/environment, including production, is excluded by typed
identity. This adds no new command, transport, service, retry, sleep or mutation;
provider power-ready is not treated as guest SSH-ready. It classifies the next
physical incident rather than silently retrying instance creation.


Disposable Vultr workflow uses stdout redirection only to preserve successful
structured JSON evidence. If native `substrate-verify` fails at initial,
no-op, post-start or post-reboot verification, the existing workflow prints the
captured bounded native failure-forensic evidence before the existing abort and
cleanup. No second probe, mutation, polling owner or fallback transport is used.


For a disposable lifecycle reboot, the existing native `action reboot` first
requires exact guest Linux boot ID over strict SSH. If that one-shot preflight
fails, it performs zero reboot mutations and reports the same bounded
provider/firewall/TCP/SSH phase forensics. After the single authorized reboot,
failed boot-ID-change proof reports post-observation evidence and refuses any
mutation replay. The GitHub workflow surfaces both failure results before
cleanup rather than hiding them in redirected output. Production or mismatched
VM identities cannot invoke disposable forensics.


### Exact initial pair provider intent (N1)

The read-only native initial pair preflight produces
`initial_pair_provider_intent_sha256`: a non-secret SHA-256 digest over the
versioned intent schema, desired Cloudflare account, generation and slot,
plus the independently observed VM and Windows Worker identity, exact
active/latest version, Access application, service token and client identity.
The same metadata may be observed repeatedly and yields the same digest.
Any desired-generation, slot, Worker version or host Access change invalidates
the digest; active-vs-latest version drift fails closed. The digest is designed
to bind the future append-only GitHub provider-attempt journal and BOTH real
host attestations, not to replace either. Current preflight remains read-only,
does not issue credentials, and prints `initial_publication_authorized=false`.
