# Edge platform architecture authority

This file defines the accepted stable ownership/invariant model and target steady state for the current project. Stage 3 and Stage 4A are closed. Cloudflare account convergence and Stage-2 fresh-v2/proxy-only acceptance are also closed. Provider reality must still be freshly observed before any mutation. Issue #26 now owns Stage 4B: one managed Windows TUN cutover under the existing SCM `EdgePlatformController` owner, followed by Stage 4C post-cutover deletion/final acceptance. Accepted Stage 4A deletions must not be reopened merely for confidence or compiler-warning cleanup.

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
`EdgePlatformController`, running as `NT SERVICE\EdgePlatformController`.

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

### edge-diagnostic

`edge-diagnostic.exe` is independent from the Windows controller.

Default growth is bounded one-shot native observation. A resident observer is allowed only if live
evidence proves a continuous-observation requirement that one-shot diagnostics cannot satisfy.

Diagnostics are read-only by default. Repair is always a separate explicit typed action.

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

The new stack receives independently generated credential generations.

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

The Stage-4B preflight audit of protected main established these implementation facts:

- the canonical Windows renderer is intentionally proxy-only and rejects a TUN inbound;
- credential apply/rollback re-renders the managed config from typed canonical state, so TUN must not be
  enabled by a hidden environment switch or by mutating generated JSON;
- local runtime restart already stages the candidate, runs exact `sing-box check`, activates only after
  validation, observes startup and restores the last-known-good managed config on failure;
- SCM `EdgePlatformController` is delayed-auto-start with bounded service recovery, but service startup
  currently does not converge/start the managed sing-box after reboot;
- current local-runtime process detection returns only the exact managed-config sing-box, so it cannot
  classify a concurrently running external sing-box; Stage 4B must add explicit
  `managed / conflicting external / absent` observation before TUN ownership can converge;
- Windows binaries embed canonical `infra/production/production.textproto` through
  `edge-shared-types/build.rs`, but the current Windows candidate input digest does not include that
  external file; a production desired-state change can therefore be misclassified as artifact `REUSE`;
- Windows activation persists a verified `previous.pb`, but there is no executable local Windows
  ReleaseSet rollback operation and normal activation requires the target revision to be current
  protected `main`; relying on a new Git revert + CI during a failed cutover is not bounded rollback;
- `edge-diagnostic` currently proves release identity and controller process identity only; Stage 4B
  requires native read-only adapter/route/DNS/TUN observation before live cutover;
- Windows DNS observation in `edge-local-runtime` is native IP Helper, while the old owned-DNS reset is
  still a bounded PowerShell recovery path. It must not become the normal TUN DNS owner;
- the physical Windows backend is the existing `windows-physical.yml`; 4B.1 locks this as the only
  permitted Windows physical owner boundary. The evidence-derived fixed cutover mutation is added there
  only in 4B.2 after the exact external startup owner and restore procedure are read-only proven.

#### Required implementation shape

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
   an arbitrary release digest. Rollback restores the previous exact binary/activation authority; that
   previous SCM owner then rematerializes runtime JSON from the unchanged typed runtime projection and its
   own embedded canonical desired state before startup. No duplicated mode marker participates in rollback.
5. For the pinned sing-box line, Windows TUN routing/DNS is owned by sing-box itself: TUN + `auto_route`,
   `strict_route`, native/hijack DNS, existing `route.auto_detect_interface`, exact endpoint route
   exclusions and stable DIRECT loop-prevention rules. Linux-only `auto_redirect` is not a Windows
   mechanism and must not be introduced here.
6. Extend the existing `edge-diagnostic` with native read-only Windows network observation sufficient to
   prove the exact managed TUN adapter, addresses, routes and per-interface DNS. Prefer Win32/IP Helper
   APIs; do not create WMI/PowerShell parsing or a resident observer merely for acceptance.
7. Add one typed Windows process observation in the existing local-runtime boundary that distinguishes
   the exact managed process, any conflicting external sing-box process and absence. Startup/cutover code
   may act only on the exact managed process; a conflicting external process is evidence/STOP unless the
   explicit physical cutover has pre-authorized that exact observed owner.
8. Add startup convergence inside the existing SCM `EdgePlatformController`: after reboot/service start,
   an installed, validated managed runtime is started when absent; an already-running exact managed runtime
   is a NOOP; an unexpected/external sing-box remains fail-closed and untouched. Do not add a Scheduled
   Task, watchdog daemon or second startup owner.
9. Do not widen the SCM service identity merely by assumption. The live cutover must first prove whether
   the existing `NT SERVICE\\EdgePlatformController` authority can create/own the TUN. Any privilege change
   requires concrete failure evidence and a least-privilege decision; switching the controller to
   LocalSystem merely for convenience is not an accepted default.
10. The old PowerShell DNS reset remains recovery-only while it has a real consumer. New managed-TUN DNS
   must not depend on it. If failed-runtime cleanup proves a host DNS reset is still necessary, implement
   that mutation inside the existing local-runtime boundary with native Windows APIs and exact-interface
   ownership; otherwise delete the obsolete reset in Stage 4C.

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

**4B.2 — bounded physical cutover acceptance**

Before touching the currently working external Windows sing-box, read-only observation must prove the
exact external process/startup owner and a bounded restore procedure. The installed managed side must
also have an exact locally verified `PROXY_ONLY` previous activation and the bounded local ReleaseSet
rollback must already have passed a physical no-TUN proof. These are cutover rollback evidence, not
adoption of legacy config/secrets as project authority. If either rollback path cannot be proven, STOP
rather than guess.

The production mode flip is itself a separate Git-authorized candidate transition: change canonical
desired mode to `MANAGED_TUN`, require exact-head CI and no-rebuild promotion for that exact revision,
and resolve the resulting exact accepted ReleaseSet before the first Windows datapath mutation. A
`PROXY_ONLY` ReleaseSet must never be treated as authority for the TUN cutover.

Then perform one authorized cutover with that exact accepted `MANAGED_TUN` ReleaseSet: stop only the
pre-observed external owner, start the managed TUN, and prove all of the following before declaring
ownership transferred:

- exact TUN adapter/address and expected default routes;
- endpoint/control-plane bypass and no self-routing loop;
- native DNS ownership, resolution and no multihomed DNS leak;
- DIRECT selector egress and WARP selector egress;
- managed restart and failed-candidate last-known-good recovery;
- SCM service restart and full Windows reboot recovery without a second startup mechanism;
- bounded cutover rollback restores connectivity if acceptance fails;
- repeated read-only verification is stable after success.

Only after this PASS does the external Windows runtime lose its live consumer. Stage 4C then deletes its
startup/config/secret glue and any recovery-only compatibility surface whose last consumer disappeared.

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

- one owner per mutable resource class;
- no second desired-state store;
- no blind retries;
- no secret values in Git, Issues, logs, artifacts or Release assets;
- self-hosted runners do not receive application plaintext credentials;
- exact accepted artifacts only;
- mutations are re-observed and verified;
- generated external config is never first-party authority;
- no TUN/DNS/default-route/system-proxy ownership before its explicit gate;
- old legacy runtime remains no-touch until controlled cutover.
