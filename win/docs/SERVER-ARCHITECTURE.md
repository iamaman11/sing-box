# Server architecture

Execution order is owned by GitHub Issue #26.
Stable ownership/invariants are in `edge-platform/ARCHITECTURE.md`.

## Control plane

Canonical production server control path:

```text
Git / protected main
        |
        v
edge-orchestrator
GitHub-only production owner
        |
        +-- Vultr API
        +-- Cloudflare API
        |
        v
temporary strict SSH support-access path
        |
        v
OpenSSH local forward
        |
        v
127.0.0.1:50061
edge-agent
        |
        v
Docker Compose / host runtime
```

`edge-agent` is supervised by systemd and is not a public management service.

The historical `edge-console -> edge-controller -> edge-agent` remote-provider model is retired.

## Host model

Canonical host root:

```text
/opt/vultr-edge-stack/
  bin/
  stack/
  runtime-secrets/
  warp-state/
  mesh-state/
  certificate-state/
```

Exact details are owned by the current Rust/application lifecycle, not by this document.

Cloud-init prepares only host/bootstrap prerequisites. It must not become full application
deployment or a durable secret store.

## Current dataplane services

Canonical `win/vultr-waw/stack/docker-compose.yml` currently defines:

1. `warp-egress` — Cloudflare WARP egress;
2. `line1-gateway` — profile `tunnel`, direct/WARP VLESS + Hysteria gateway;
3. `line2-proxy` — authenticated remote proxy services;
4. `cloudflare-mesh` — profile `mesh`, Cloudflare Mesh connector/egress.

Profiles allow bounded composition without creating separate host control planes.

Project-owned OCI images are pulled by exact digest from the accepted ReleaseSet. No normal
production image build occurs on the VM.

## edge-agent responsibilities

Allowed responsibilities:
- exact bundle/apply/rollback;
- Docker/container/image observation;
- host/network observation;
- runtime rendering/validation;
- bounded Mesh/runtime convergence;
- secret-safe diagnostics;
- exact readiness/functional verification.

Forbidden responsibilities:
- Vultr/Cloudflare desired-state ownership;
- production ReleaseSet selection;
- arbitrary shell RPC;
- arbitrary filesystem RPC;
- arbitrary Docker API passthrough;
- second desired-state database.

## Transport

Strict OpenSSH host-certificate verification remains the bootstrap/control transport.
Canonical application lifecycle forwards to loopback `edge-agent`.

Do not add:
- public agent management port;
- TOFU success path;
- generic remote shell API;
- another resident control daemon merely to avoid SSH local forwarding.

Historical Agent custom TLS/`edge-trust` is targeted for deletion after live-consumer proof.

## Secret/runtime model

Provider API tokens never belong on the VM application runtime.

Target after Issue #169:
- VM receives only the VM credential projection required by its runtime;
- local active/candidate typed secret state is root/private;
- missing desired generation fails closed;
- generated `.env.runtime` and rendered sing-box JSON are derived artifacts;
- Cloudflare credential delivery is not required for every runtime request/start once active local
  state exists.

Mesh node token remains tied to the Mesh-node/provider lifecycle, not to Windows client credential
rotation.

## Lifecycle

Normal production path:

```text
observe provider
 -> plan
 -> converge machine/VPC/support resources
 -> materialize exact accepted application
 -> install/update exact edge-agent
 -> apply runtime
 -> DNS/Mesh/Zero Trust composition
 -> verify
 -> release support access
 -> prove cleanup
```

Rollback restores the previous exact accepted application release and re-verifies runtime.

Credential rollback is independent from application-release rollback.

## Recovery

A replacement VM must be reconstructible from:
- Git desired state;
- exact accepted ReleaseSet;
- Vultr API;
- dedicated Cloudflare account/shared DNS boundaries;
- credential plane;
- bootstrap trust credentials.

No Windows legacy checkout or old DPAPI/Vault state is part of server recovery.
