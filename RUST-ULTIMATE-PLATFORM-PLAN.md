# Ultimate Rust Platform Plan for Modular Edge Architectures

## Summary

This document defines the target-state migration from the current PowerShell-
driven orchestration model to a full Rust control-plane platform for modular
edge architectures built around:

- server lifecycle on an IaaS provider
- DNS cutover and verification
- modular direct and WARP datapaths
- public proxy plane
- public tunnel plane
- Windows local `sing-box` client orchestration
- selector-driven local routing

The migration target is not "rewrite scripts in Rust". The migration target is:

1. a **Local Control Plane** on Windows
2. a **Server Control Plane** on Linux
3. a **strict state machine**
4. a **single authoritative state backend**
5. a **local API + web UI**
6. a **multi-provider core**
7. a **compose-first but pluggable runtime model**

Existing dataplane components remain:

- `sing-box`
- `Cloudflare WARP`
- `docker compose`
- the current proxy/tunnel topology

Rust replaces orchestration, lifecycle control, health evaluation, status
semantics, state coordination, secret integration, and operational UX.

---

## Goals

### Primary goals

- eliminate fragile operational behavior caused by ad-hoc PowerShell orchestration
- make deploy/destroy/start/status operations exact, bounded, and observable
- make state authoritative and explicit
- make health evaluation layered and machine-readable
- make the local control plane fast and consistent
- make the platform reusable for similar edge topologies

### Non-goals

- rewriting `sing-box`
- replacing `Cloudflare WARP`
- moving the dataplane itself to Rust
- introducing Kubernetes in the first implementation
- introducing a full external vault in the first implementation

---

## Current system being replaced

## Current local control plane

The current Windows-side orchestration is implemented with:

- `windows/singbox-dual-menu.ps1`
- `windows/start-vultr-edge-session.ps1`
- `windows/sync-vultr-dual-config.ps1`
- `windows/local-secrets.ps1`
- `windows/initialize-local-secrets-store.ps1`

Current properties:

- can start and stop local dual `sing-box`
- can sync config from server state
- can manipulate selector state through Clash API
- can deploy and destroy the server
- can show backend health and current tunnel IP

Current weaknesses:

- slow operations due to shell startup, provider calls, and SSH checks
- no true authoritative state model
- accidental semantic drift between provider errors and server health
- operational logic tightly coupled to script control flow
- hidden latency and failure semantics in nested processes

## Current server topology

The current server topology is a 5-container modular stack:

1. `vultr-warp-egress`
2. `vultr-edge-gateway`
3. `vultr-edge-gateway-direct`
4. `vultr-tunnel-edge`
5. `vultr-tunnel-edge-warp`

This topology is already logically sound. The migration does not flatten it.
Instead, the migration formalizes it into a topology model and replaces the
control-plane around it.

---

## Target architecture

## Layer A: Local Control Plane

Introduce a Windows-local Rust controller process, e.g.:

- `edge-control.exe`

This process becomes the only authoritative local orchestrator.

Responsibilities:

- local state authority
- operation orchestration
- provider API interaction
- config rendering and syncing
- local `sing-box` lifecycle management
- selector state management
- current tunnel IP trace probing
- event logging
- local API serving
- background reconciliation

It must be:

- long-running
- cache-aware
- timeout-aware
- stateful
- deterministic in error reporting

It must not:

- depend on nested shells for normal operations
- use SSH for normal status rendering
- treat JSON files as source of truth
- emit success before completion is verified

## Layer B: Server Control Plane

Introduce a small Linux Rust service, e.g.:

- `edge-agent`

This service runs on the server and exposes local control/health semantics for
the server dataplane.

Responsibilities:

- health endpoint
- readiness endpoint
- detailed runtime state endpoint
- bundle/version identity reporting
- optional metrics endpoint
- local container and port inspection

It must not:

- replace `sing-box`
- replace `WARP`
- become the public client-facing data plane
- become a broad admin interface exposed to the internet

## Layer C: Provider abstraction

Introduce a provider boundary at the controller level.

Target interfaces:

- `ComputeProvider`
- `DnsProvider`
- `SecretProvider`
- `RuntimeProvider`
- `ServerHealthProvider`

Initial implementations:

- compute: `Vultr`
- DNS: `Cloudflare`
- runtime: `docker-compose`
- health provider: `edge-agent`

The purpose is not to build a plugin marketplace. The purpose is to prevent the
entire system from hard-coding one provider's control flow into the domain
model.

## Layer D: UI/API layer

Operational UX moves to:

- local web UI
- local HTTP API
- optional thin CLI

PowerShell is demoted to:

- optional emergency wrappers
- optional launcher convenience
- no orchestration logic

---

## Domain model

## Deployment

Represents one lifecycle deployment unit.

Fields:

- deployment id
- provider kind
- region
- plan
- runtime kind
- instance id
- server IP
- deployment label
- topology version
- credential set version
- current phase
- result status
- timestamps
- bundle hash
- controller version
- agent version

## Topology

Represents the target stack shape.

For the current edge architecture it includes:

- `warp-egress`
- `edge-gateway`
- `edge-gateway-direct`
- `tunnel-edge`
- `tunnel-edge-warp`

The topology object must describe:

- modules
- dependencies
- networks
- public surfaces
- internal surfaces
- required volumes
- required generated configs
- readiness requirements

## Profile

Represents a logical traffic profile.

Initial profiles:

- `direct`
- `warp`

Profiles must be first-class entities used consistently by:

- server topology
- deployment credentials
- local selectors
- health reporting
- UI

## SelectorState

Represents the desired and observed local routing state.

Fields:

- desired main route
- observed main route
- desired direct transport
- observed direct transport
- desired warp transport
- observed warp transport
- last sync time
- degraded flag

## Observation

Represents live or cached observed state.

Examples:

- provider instance state
- backend readiness
- local process state
- selector state
- tunnel IP
- tunnel WARP flag
- tunnel colo
- DNS state

## CredentialSet

Represents versioned deployment credentials.

Fields:

- direct VLESS UUID
- direct Hysteria2 password
- direct Reality public key
- direct short id
- warp VLESS UUID
- warp Hysteria2 password
- warp Reality public key
- warp short id
- proxy username
- proxy password
- certificate metadata
- creation time
- deployment linkage

---

## Local Control Plane responsibilities

## 1. State authority

The local Rust controller owns authoritative state.

Storage:

- SQLite database

Derived artifacts:

- generated bundles
- rendered config files
- known_hosts files
- optional exported summaries

JSON is no longer the source of truth.

## 2. Lifecycle orchestration

The controller is responsible for:

- creating instances
- waiting for provider readiness
- initializing SSH trust
- rendering bundle artifacts
- uploading artifacts
- bootstrapping base stack
- verifying base readiness
- switching DNS
- bootstrapping tunnel stack
- verifying tunnel readiness
- writing authoritative state
- syncing local config

## 3. Local `sing-box` management

The controller manages only the expected dual config.

It must support:

- detect whether `sing-box` is running
- detect whether the running config is the expected config
- refuse to kill foreign configs
- start expected config
- stop expected config
- restart expected config
- validate config before start
- query Clash API
- set selector state
- read current egress trace

## 4. Background reconciliation

The controller must continuously reconcile:

- provider instance state
- DNS state
- server readiness via `edge-agent`
- local `sing-box` status
- selector state
- tunnel current IP/warp/colo

This is mandatory for fast UX.

The UI must read cached truth, not trigger expensive live checks by default.

---

## Server Control Plane responsibilities

## 1. Health contract

`edge-agent` defines the authoritative server health contract.

Endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /state`
- `GET /version`
- optional `GET /metrics`

## 2. What `edge-agent` checks

- required containers present
- required containers running
- required public ports listening
- required rendered config files present
- required runtime state directories present
- bundle/version identity
- optional cert and tunnel state expectations

## 3. What `edge-agent` returns

The response must be machine-readable and precise.

`/state` should include:

- container state map
- port readiness map
- topology version
- active bundle id
- degraded reasons
- runtime type
- last health evaluation time

## 4. Health semantics

The platform must distinguish:

- provider says instance exists
- server responds over network
- agent is alive
- base plane is ready
- tunnel plane is ready
- direct profile is ready
- warp profile is ready

SSH must not remain the primary normal status path.

---

## State machine

## Deploy phases

The deploy operation must be a strict state machine.

Phases:

1. `requested`
2. `instance_create_requested`
3. `instance_provisioning`
4. `instance_address_assigned`
5. `instance_runtime_ready`
6. `host_trust_initialized`
7. `bundle_rendered`
8. `bundle_uploaded`
9. `base_bootstrap_started`
10. `base_ready_verified`
11. `dns_cutover_started`
12. `dns_cutover_verified`
13. `tunnel_bootstrap_started`
14. `tunnel_ready_verified`
15. `deployment_published`
16. `local_config_synced`
17. `completed`

Failure path:

- `failed`
- optional `rollback_started`
- `rollback_completed`

## Destroy phases

1. `requested`
2. `local_detach_started`
3. `provider_delete_requested`
4. `provider_delete_confirmed`
5. `dns_cleanup_started`
6. `dns_cleanup_confirmed`
7. `state_archived`
8. `completed`

## Invariants

- no operation reports success before phase completion
- provider timeout does not imply instance missing
- backend health does not depend on provider API being healthy
- DNS switch happens only after base readiness
- local start is blocked until backend readiness is satisfied
- stale credentials cannot silently remain active after deployment change

---

## Provider and runtime abstractions

## ComputeProvider

Required methods:

- `create_instance`
- `get_instance`
- `delete_instance`
- `wait_until_ready`
- optional `list_instances`

## DnsProvider

Required methods:

- `upsert_a_record`
- `get_record`
- `verify_record`
- optional `delete_record`

## RuntimeProvider

The runtime remains compose-first.

Required methods:

- `upload_bundle`
- `apply_base`
- `apply_tunnel`
- `inspect_runtime_state`
- `fetch_runtime_logs`

First implementation:

- `DockerComposeRuntimeProvider`

Later possible implementations:

- `SystemdRuntimeProvider`
- `ContainerdRuntimeProvider`
- `KubernetesRuntimeProvider`

## ServerHealthProvider

Required methods:

- `health`
- `ready`
- `state`
- `version`

First implementation:

- `EdgeAgentHealthProvider`

---

## Storage design

## SQLite as authoritative state

Use SQLite for local authoritative state.

Required tables:

- `deployments`
- `deployment_credentials`
- `topologies`
- `desired_state`
- `provider_observations`
- `server_observations`
- `local_observations`
- `operations`
- `operation_events`
- `trust_store`
- `config_sync_runs`

## Filesystem layout

The platform should still keep generated bundles and runtime artifacts on disk.

Suggested layout:

- `%LOCALAPPDATA%\\edge-control\\db\\state.sqlite`
- `%LOCALAPPDATA%\\edge-control\\bundles\\<deployment-id>\\...`
- `%LOCALAPPDATA%\\edge-control\\runtime\\...`
- `%LOCALAPPDATA%\\edge-control\\logs\\...`

Generated files remain useful for:

- debugging
- auditability
- emergency manual recovery

But they are no longer the authoritative source of truth.

---

## Secrets and trust

## Local secrets

Target backend:

- Windows Credential Manager

Secrets to store:

- Vultr API key
- Cloudflare API token
- optional SSH private key reference
- optional sing-box binary path override

## Server secrets

In this migration, server-side secrets remain:

- generated bundle env
- rendered runtime artifacts

Full external vault integration is out of scope for the first Rust transition.

## Trust model

SSH host trust becomes structured:

- trust entries stored in SQLite
- known_hosts file materialized as derived artifact
- trust linked to instance id, IP, and deployment id

States:

- unknown
- trusted
- rotated
- invalidated

---

## Local HTTP API

## Required endpoints

### Status

- `GET /api/status`

Returns:

- local sing-box state
- expected-config classification
- active deployment summary
- provider state
- backend state
- selector state
- current tunnel IP/warp/colo
- warnings and degraded reasons

### Deploy

- `POST /api/deploy`

Input:

- optional `instance_id`
- optional `reuse_existing`
- optional `region`
- optional `plan`
- optional `tunnel_domain`
- optional `acme_email`

Returns:

- `operation_id`

### Destroy

- `POST /api/destroy`

Input:

- optional `instance_id`
- optional `active_only`

Returns:

- `operation_id`

### Local sing-box lifecycle

- `POST /api/local/start`
- `POST /api/local/stop`
- `POST /api/local/restart`

### Selector control

- `POST /api/selector/main`

Supported values:

- `auto-direct-tunnel`
- `hysteria2-direct`
- `vless-reality-direct`
- `auto-warp-tunnel`
- `hysteria2-warp`
- `vless-reality-warp`

### Config sync

- `POST /api/config/sync`

### Current IP

- `GET /api/current-ip`

Returns:

- `ip`
- `warp`
- `colo`
- `timestamp`

### Operations

- `GET /api/operations`
- `GET /api/operations/:id`
- `GET /api/operations/:id/events`

---

## UI model

## Target UX

Primary interface:

- web UI served locally

Optional:

- thin CLI

Not primary:

- PowerShell menu

## UI responsibilities

The UI must:

- read current status
- show operation progress
- show precise current phase
- show last failure reason
- show effective selector state
- show current tunnel IP/WARP/colo
- allow deploy/destroy/start/stop/select/sync

The UI must not:

- call Vultr directly
- call Cloudflare directly
- run SSH directly
- interpret shell output itself

---

## Rust workspace structure

Recommended workspace:

- `edge-platform/`
  - `crates/edge-controller`
  - `crates/edge-controller-core`
  - `crates/edge-state`
  - `crates/edge-secrets`
  - `crates/edge-vultr`
  - `crates/edge-cloudflare`
  - `crates/edge-runtime-compose`
  - `crates/edge-health-client`
  - `crates/edge-singbox`
  - `crates/edge-deployer`
  - `crates/edge-agent`
  - `crates/edge-shared-types`
  - optional `ui/`

## Crate responsibilities

### `edge-controller`

- Windows-local daemon
- local HTTP server
- orchestration runtime host

### `edge-controller-core`

- state machine
- orchestration domain logic
- no OS-specific code

### `edge-state`

- SQLite schema
- migrations
- repositories
- event journal persistence

### `edge-secrets`

- Windows Credential Manager integration
- abstract secret interfaces

### `edge-vultr`

- Vultr API client
- typed errors
- retries and timeouts

### `edge-cloudflare`

- Cloudflare DNS client

### `edge-runtime-compose`

- compose bundle apply
- upload/invoke/inspect helpers

### `edge-health-client`

- client for `edge-agent`

### `edge-singbox`

- process manager
- config sync/render
- Clash API client
- trace probe logic

### `edge-deployer`

- remote bootstrap sequencing
- bundle generation
- deploy phase execution

### `edge-agent`

- server-side health and readiness service

### `edge-shared-types`

- API DTOs
- status and operation structures

---

## Operational behavior requirements

## Timeouts

Defaults to enforce:

- provider GET: 10s
- provider create/delete: 20s
- DNS provider calls: 10-20s
- SSH connect: 5s
- single probe: bounded
- full deploy: bounded by operation deadline

## Retries

Retries must be explicit and typed:

- provider GET retryable
- provider DELETE retryable if transport failed before clear result
- DNS update retryable
- SSH bootstrap retryable
- health endpoint retryable

## Error model

Every failure must include:

- `code`
- `stage`
- `message`
- `retryable`
- `subsystem`

Subsystem examples:

- `provider.compute`
- `provider.dns`
- `runtime.compose`
- `transport.ssh`
- `local.singbox`
- `server.agent`

---

## Testing strategy

## Unit tests

Required:

- state machine transitions
- desired/observed selector reconciliation
- topology rendering
- credential generation and versioning
- provider error mapping
- current IP trace parsing
- trust-store logic
- status semantics

## Integration tests

Required:

- mocked Vultr API
- mocked Cloudflare API
- mocked `edge-agent`
- config sync against real sample sing-box config
- Clash API integration
- deploy phase executor with fake SSH transport

## End-to-end scenarios

1. fresh server deploy
2. redeploy existing active server
3. destroy active server
4. deploy fails before DNS switch
5. deploy fails after DNS switch and rollback path is triggered
6. provider timeout while server remains reachable
7. backend healthy while provider status unavailable
8. local start blocked on backend unready
9. foreign sing-box process blocks local start/stop
10. selector switch direct -> warp -> direct
11. stale credentials detection
12. current tunnel IP status remains available during normal operation

## Acceptance criteria

- status returns quickly and consistently
- no false-success delete
- no false-success deploy
- normal status does not depend on SSH
- exact phase always visible during long operations
- server topology remains modular
- local control plane remains accurate under provider/API failure
- architecture remains reusable for similar multi-plane edge stacks

---

## Migration strategy

## Phase 1: foundation

Build:

- Rust workspace
- shared types
- SQLite state layer
- secret provider
- provider clients
- read-only local API

Outcome:

- local controller can describe truth accurately without mutation

## Phase 2: local control

Build:

- local sing-box manager
- Clash API selector control
- config sync/render
- current tunnel trace
- local web UI skeleton

Outcome:

- PowerShell menu no longer needed for local control

## Phase 3: server agent

Build:

- `edge-agent`
- `/healthz`
- `/readyz`
- `/state`
- runtime inspection

Outcome:

- backend status no longer depends on SSH for normal rendering

## Phase 4: deploy orchestrator

Build:

- deploy state machine
- bundle generator
- runtime apply flow
- DNS cutover flow
- destroy flow
- rollback semantics

Outcome:

- deploy and destroy become exact operations, not shell workflows

## Phase 5: hard cutover

Build:

- final web UI
- optional thin CLI
- emergency-only PowerShell shims
- migration of operational docs

Outcome:

- Rust platform is the only normal control plane

---

## Assumptions

- local control plane is implemented in Rust
- server control plane is implemented in Rust
- `docker-compose` remains the first runtime
- `Vultr` and `Cloudflare` remain first provider implementations
- `sing-box` remains the client and server dataplane engine
- `Cloudflare WARP` remains the egress mechanism where currently used
- secrets move to Windows Credential Manager locally
- a full external vault is out of scope for the first migration
- PowerShell orchestration is replaced, not preserved as a long-term control plane

---

## Final target

The end state is a modular Rust platform that is:

- layered
- stateful
- observable
- deterministic
- provider-extensible
- runtime-aware
- fast in normal operation
- exact in status semantics
- reusable for similar edge topologies

This is the level required to make the current architecture truly industrial and
scalable rather than merely strongly scripted.
