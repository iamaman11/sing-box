This bundle provisions a new Vultr instance in Warsaw and deploys a modular edge stack.

Default target:
- Region: `waw`
- Plan: `vc2-1c-1gb`
- OS: Debian 12 x64 (`2136`)
- SSH key: `public vultr`

Services:
- `warp-egress`
- `edge-gateway`
- `tunnel-edge` (enabled only when `TunnelDomain` is provided)

Target server model:

- Docker installed by `cloud-init`
- `edge-agent` installed as a host binary under `/opt/vultr-edge-stack/bin`
- normal runtime status/readiness served by `edge-agent` gRPC
- deploy bundle uploaded already prepared
- steady-state deploy path should use prebuilt images instead of server-side builds

Primary entrypoint:
- [deploy-waw.ps1](C:/Users/Bose/vm-edge-stack/vultr-waw/deploy-waw.ps1)

Example:

```powershell
$env:VULTR_API_KEY = '...'
& ".\deploy-waw.ps1"
```

With tunnel domain:

```powershell
$env:VULTR_API_KEY = '...'
& ".\deploy-waw.ps1" -TunnelDomain "waw.alegria.by" -AcmeEmail "admin@alegria.by"
```

Prebuilt-image mode for the uploaded server bundle:

- set `EDGE_USE_PREBUILT_IMAGES=1` in `.env.runtime`
- provide image refs such as:
  - `EDGE_WARP_EGRESS_IMAGE`
  - `EDGE_GATEWAY_IMAGE`
- `bootstrap.sh` then prefers `docker compose pull` + `docker compose up -d`
  instead of `docker compose up -d --build`

`deploy-waw.ps1` can prepare this mode directly:

```powershell
& ".\deploy-waw.ps1" `
  -UsePrebuiltImages `
  -WarpEgressImage "ghcr.io/iamaman11/vultr-warp-egress:latest" `
  -GatewayImage "ghcr.io/iamaman11/vultr-edge-gateway:latest" `
  -EdgeAgentBinaryPath ".\edge-agent"
```

`EdgeAgentBinaryPath` is optional during transition. When provided, the script
uploads it to `/opt/vultr-edge-stack/bin/edge-agent`, enables the host
`edge-agent.service`, restarts it, and checks that the service is active.

`deploy-waw.ps1` now expects a local `edge-controller` binary for the
bootstrap RPC path. It resolves this from `EDGE_CONTROLLER_BINARY_PATH` or the
workspace default `edge-platform/target/{release,debug}/edge-controller(.exe)`.
Bootstrap/update continues to use SSH only for upload and local port forwarding;
the actual `base` / `tunnel` actions are executed through `AgentService.BootstrapRuntime`.
