# Edge platform architecture authority

This file defines the accepted stable ownership/invariant model and target steady state for the current project. Cloudflare account convergence, Stage-2 fresh-v2/proxy-only acceptance, and the Stage-3 historical application-exclusive Cloudflare retirement are closed; provider reality must still be freshly observed before any mutation. Issue #26 owns the remaining Stage-3 steady-state lifecycle closure (local-owner production rollback and class-scoped credential rotation) and the later Stage-4 physical shrink / managed-TUN cutover.

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
steady-state operator namespace.

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
