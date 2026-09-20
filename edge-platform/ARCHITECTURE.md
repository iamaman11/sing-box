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
