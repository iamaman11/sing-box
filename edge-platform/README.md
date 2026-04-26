# edge-platform

Rust control plane for local `sing-box` operation and Vultr edge runtime.

## Executables

- `edge-controller` - local daemon/orchestrator
- `edge-console` - operator console client
- `edge-agent` - Linux host daemon on the Vultr server

## Current shape

- machine transport: `gRPC + protobuf`
- local state: `SQLite + rusqlite`
- server runtime: `edge-agent` on the host, dataplane still in the existing 5-container topology
- local operator flow: `edge-console` -> `edge-controller`
- server flow: `edge-controller` -> `edge-agent`

## What already works

- read-only controller status
- local `sing-box` start/stop/restart
- Clash selector read/write
- trace/IP observation
- bundle rendering
- runtime apply to `edge-agent`
- base/tunnel bootstrap over gRPC
- deploy/destroy orchestration in Rust
- fresh-host Vultr create + initial host bootstrap in Rust
- steady-state remote agent target resolution from persisted deployment + trust state

## Fresh-host bootstrap inputs

The fresh-host create/bootstrap path is activated when `deploy` is called without
`target_ip` and without `instance_id`.

Required environment:

- `VULTR_API_KEY`
- `EDGE_VULTR_SSH_KEY_ID`
- `EDGE_SSH_PRIVATE_KEY_PATH`

Optional environment:

- `EDGE_AGENT_BINARY_PATH`
  - defaults to `edge-platform/target/debug/edge-agent` if present
- `EDGE_VULTR_REGION`
  - default: `waw`
- `EDGE_VULTR_PLAN`
  - default: `vc2-1c-1gb`
- `EDGE_VULTR_OS_ID`
  - default: `2136`
- `EDGE_BOOTSTRAP_VIA_SSH=1`
  - forces SSH bootstrap/tunnel for an existing remote target

Bootstrap transport remains SSH-only for first host preparation:

- wait for SSH
- wait for cloud-init and Docker
- upload/install `edge-agent`
- open local SSH tunnel to host loopback agent
- continue deploy through gRPC

For later remote deploy/redeploy operations, `edge-controller` now requires one of:

- explicit `EDGE_AGENT_ENDPOINT`
- targeted persisted trust material for the resolved `instance_id + ip`
- forced SSH bootstrap via `EDGE_BOOTSTRAP_VIA_SSH=1`

Status/runtime observation can now resolve the active remote agent target from
persisted deployment and trust rows. The remaining hardening step is to remove
any bootstrap-tunnel assumptions from the operational path and finish the
production mTLS cutover semantics.

## What is still left

- direct steady-state `mTLS` controller -> agent operation without SSH tunnel assumptions
- dedicated `edge-secrets` backend instead of environment/file-driven bootstrap inputs
- provider-path hardening and recovery semantics
- production cutover cleanup and retirement of legacy PowerShell workflow
