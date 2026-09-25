# Edge platform architecture authority

The canonical execution plan is GitHub Issue #26. Issue #58 is the retained
architecture-design record; Issue #60 is the bounded Windows diagnostics
implementation track.

## Ownership

```text
edge-controller-core
  reusable deterministic domain/lifecycle policy
        /                         \
       /                           \
edge-orchestrator                  edge-controller.exe
GitHub-only provider/VM owner      Windows-local TUN/runtime owner
       |                                    |
edge-agent                           sing-box.exe
Linux bounded executor/observer      dataplane

edge-windows-agent.exe
Windows-local independent read-only diagnostics
```

Rules:

- GitHub Actions authenticates, materializes exact authority, invokes typed
  binaries and publishes evidence. Workflow YAML does not own lifecycle policy.
- Provider credentials and provider/VM lifecycle never belong to the installed
  Windows controller.
- The Linux agent has no provider desired-state authority and no arbitrary
  shell/filesystem/Docker RPC surface.
- The Windows diagnostic agent is read-only and is never a repair or release
  activation surface.
- ReleaseSet bytes/digests remain immutable release authority.
- Candidate artifacts build once; merge promotion reuses exact accepted bytes.
- Mutations use observe -> plan -> bounded apply -> re-observe -> verify and
  fail closed on unknown ownership/drift.

## Protobuf policy

`edge.platform.v1` is physically split by contract responsibility while
remaining one generated package. Physical moves inside that package are guarded
with Buf PACKAGE-level breaking checks. Field numbers, enum values, message
names, service names and RPC signatures are compatibility authority.

The first lint baseline is Buf MINIMAL: package/directory correctness and import
cycle safety without forcing a breaking rename of established v1 symbols.

## First-party serialization policy: JSON prohibited by default

New first-party JSON contracts are forbidden. This applies to desired state,
release/build manifests, lifecycle authority, durable evidence, local control
state, IPC, and machine-to-machine contracts.

Use:

- protobuf binary (`.pb`) for canonical machine contracts and durable machine
  state;
- protobuf text format (`.textproto`) for human-authored Git desired state that
  must remain reviewable and diffable;
- Rust semantic/domain types behind protobuf DTO boundaries.

JSON is allowed only where an external consumer or protocol physically requires
JSON and no project-controlled protobuf/textproto representation can replace
that boundary. Examples are sing-box configuration files and third-party HTTP
APIs whose wire protocol is JSON.

Boundary rules:

- external JSON must be decoded immediately into typed Rust/domain structures;
  raw JSON must not become downstream lifecycle authority;
- `serde_json`, `jq`, or equivalent tooling may exist only at such external
  boundaries or as frozen migration debt; convenience is not an exception;
- an exception must identify the external consumer that mandates JSON and why a
  project-controlled protobuf/textproto contract cannot replace it;
- existing first-party JSON is frozen migration debt: do not create new files,
  new contract families, or new production authority on JSON; the debt set may
  only shrink;
- generated/transient first-party JSON and Windows-local `current.json` are
  also legacy debt and must migrate when their owning Slice 2 path is touched;
- production desired state is specifically
  `infra/production/production.textproto` backed by a
  `ProductionDesiredState` protobuf schema. Do not create
  `infra/production/production.json`.

CI enforces the tracked-file boundary in
`edge-platform/scripts/test_json_contract_policy.py`. The only permanently
allowlisted tracked JSON files are those physically consumed as JSON by an
external runtime. Legacy internal entries are explicitly frozen and may be
deleted without replacement by another JSON format.

## Typed process boundary (Gate C / C2)

The controller, console and agent process entry points use a closed typed CLI
grammar before any lifecycle mutation can execute. Manual `env::args().nth()`
and magic argument-index constants are forbidden by CI.

Dependency decisions:

- `clap 4.6.7`: current stable release, MSRV 1.85; used with a reduced feature
  set to remove positional parser/index machinery while preserving help/usage.
- `thiserror 2.0.18`: already present in the accepted lock graph; now used
  directly for process-boundary error categories.
- `tracing 0.1.44`: already present in the accepted lock graph.
- `tracing-subscriber 0.3.20`: deliberately pinned with only `fmt`; it
  contains the ANSI-injection fix and avoids the currently reported
  0.3.22/0.3.23 span-clone regression.

`edge-observability` is deliberately tiny. It owns only process-level,
secret-safe structured tracing and correlation identity. It is not a telemetry
backend, remote collector, lifecycle authority or state store. Correlation IDs
accept only bounded safe tokens from `EDGE_CORRELATION_ID`; arbitrary
environment content is never emitted.

## Deterministic lifecycle authority (Gate C / BIG SLICE 1)

`edge-controller-core::lifecycle` defines the shared authority envelope for
provider/application plans:

```text
canonical desired
      +
canonical observation
      +
exact derived plan
      +
plan disposition
      |
      v
PlanAuthority
  desired_digest
  observed_digest
  plan_digest
  authority_digest
```

The authority digest is deterministic and stale-safe. A mutation authorization
must match the authority derived from a fresh observation; changed provider or
runtime state changes the digest and fails closed. `NOOP` is the only
converged disposition.

Existing domain-specific destroy/cleanup/rollback digests remain valid
compatibility authorities during migration. They are not removed or weakened.

The v1 protobuf surface now has additive typed diagnostics, operation metadata,
plan authority and a separate `OrchestratorService` contract. The service is
deliberately separate from `ControllerService`: future provider/VM production
ownership belongs to the GitHub-only `edge-orchestrator`, while installed
Windows `edge-controller.exe` remains local-runtime owner.

Legacy string/time fields remain temporarily for wire compatibility. New typed
fields are populated at the controller adapter boundary; persistent event
storage migration is intentionally deferred to the versioned-migration
execution-hardening slice rather than adding another ad-hoc schema mutation.
