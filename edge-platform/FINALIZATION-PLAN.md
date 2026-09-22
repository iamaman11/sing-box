# edge-platform Finalization Plan

> **SUPERSEDED — historical planning record only.**
>
> This file is not an execution or ownership authority. The sole living execution
> plan is GitHub Issue #26, and the canonical process-ownership model is
> `edge-platform/ARCHITECTURE.md`. In particular, provider/VM lifecycle belongs
> to the GitHub-only `edge-orchestrator`; installed Windows `edge-controller.exe`
> owns local Windows runtime/config/selectors. Legacy statements below are
> retained only as historical context and must not be used to reintroduce a
> second production orchestration path.


## Objective

Finish the Rust control plane so the normal operator workflow no longer depends
on PowerShell orchestration, while keeping the current 5-container server
topology unchanged.

The finished production shape is:

- `edge-controller` as the only orchestrator
- `edge-console` as the operator entrypoint
- `edge-agent` as the host-level server daemon
- `proto + gRPC` as the only machine-facing transport
- `SQLite` as the controller state backend

## What is already finished

- local runtime control in Rust
- selector read/write in Rust
- trace/IP observation in Rust
- bundle rendering and apply in Rust
- fresh-host create/bootstrap path in Rust
- deploy/destroy orchestration in Rust
- persisted trust material for steady-state agent access
- rollback of failed deploys with local state restoration
- secret references persisted in controller state

## Remaining work to close the project

### Phase 1. Rust-first operator surface

Purpose:
- make `edge-console` sufficient for day-to-day operation

Required outcomes:
- status, local runtime, selector, trace, deploy, destroy already stay in Rust
- operation inspection must be available from the console
- secret references must be inspectable and configurable through the controller
- menu/help/docs must point to Rust entrypoints first

Acceptance:
- normal operator flow uses `edge-console`
- PowerShell is no longer the primary documented entrypoint

### Phase 2. Cutover the repository contract

Purpose:
- remove legacy PowerShell files from the authoritative repository model

Required outcomes:
- repository inventory must treat Rust artifacts as required inputs
- legacy `.ps1` files must stop being blockers or required runtime dependencies
- docs must describe PowerShell as historical reference only

Acceptance:
- `ControllerStatus.inventory` reflects the Rust platform, not the retired menu

### Phase 3. Transport hardening

Purpose:
- make steady-state controller -> agent operation use persisted trust without
  bootstrap assumptions

Required outcomes:
- remote agent resolution comes from persisted deployment + trust state
- direct redeploy never silently falls back to loopback
- SSH remains only for first-host bootstrap and explicit maintenance

Acceptance:
- steady-state status/deploy/redeploy paths use remote agent targeting and TLS

### Phase 4. Recovery hardening

Purpose:
- make failures recoverable without manual cleanup

Required outcomes:
- deploy failure restores prior local live state
- trust rows and deployment rows are cleaned on failed new deployment
- destroy clears deployment and trust state deterministically
- operation events remain queryable after controller restart

Acceptance:
- a failed deploy leaves controller state internally consistent

### Phase 5. Legacy retirement

Purpose:
- freeze PowerShell as reference, not workflow

Required outcomes:
- Rust runbook becomes the primary operational document
- legacy docs are preserved only as historical mapping/reference
- no current workflow document tells the operator to start from `.ps1`

Acceptance:
- a new operator can run the platform using Rust docs only

## Implementation order

1. complete controller RPCs for secret refs and operation inspection
2. complete console commands for secret refs and operation watch
3. switch inventory required inputs to Rust-first artifacts
4. rewrite runbook/architecture docs to Rust-first flow
5. run focused crate tests, then a full workspace run

## Done criteria

The application is considered functionally complete when:

- `edge-console` covers the day-to-day operator workflow
- `edge-controller` owns deploy/destroy/runtime orchestration
- `edge-agent` owns server runtime observation and apply/bootstrap endpoints
- secret refs, trust rows, deployment rows, and operation events are persisted
- PowerShell is no longer part of the normal operational path

## Explicit non-goals for this final pass

- changing the 5-container server topology
- introducing a web UI
- replacing sing-box itself
- live-provider integration testing from this workspace session
