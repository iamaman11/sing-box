# Server architecture

Execution order is owned by GitHub Issue #26.
Stable ownership/invariants are in `edge-platform/ARCHITECTURE.md`.

## Control plane

```text
GitHub-hosted edge-orchestrator
  -> Vultr / Cloudflare provider lifecycle

GitHub self-hosted production-VM runner
  -> exact allowlisted local command only
  -> root-owned local edge-agent runtime owner
      +-- fixed Docker Compose mutation
      +-- Bollard Docker observation/diagnostics
      '-- bounded host/network probes
  -> Docker Engine / four-container dataplane
```

The self-hosted runner is outbound transport only. It has no provider credentials, generic root, Docker socket or plaintext application-secret authority.

Strict SSH is bootstrap/migration/break-glass transport only. The historical hosted-runner -> /32 lease -> SSH -> local-forward -> TCP/gRPC agent path is not steady-state architecture.

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

The retained Linux runtime logic is a **local typed owner**, not a remote management daemon.

It owns:
- fixed Docker Compose lifecycle operations;
- Bollard container/image/health/restart/OOM/network/port/mount observations;
- bounded host/network observations;
- local application and credential state transitions;
- secret-safe evidence.

It does not expose generic shell, arbitrary Docker API passthrough, provider mutation or runner-readable credential plaintext.

## Transport

Steady-state transport is the production VM repository self-hosted runner invoking a closed local owner surface. The runner cannot invoke arbitrary sudo commands and is not in the Docker group.

SSH remains only for initial enrollment, migration and explicit break-glass recovery. Port 50061/TCP-gRPC is migration debt while legacy consumers remain and must not be re-established as the normal production path.

## Secret/runtime model

Provider API tokens never belong on the VM application runtime.

Canonical credential target:
- VM receives only the VM credential projection required by its runtime;
- local active/candidate typed secret state is root/private;
- missing desired generation fails closed;
- generated `.env.runtime` and rendered sing-box JSON are derived artifacts;
- Cloudflare credential delivery is not required for every runtime request/start once active local
  state exists.

Mesh node token remains tied to the Mesh-node/provider lifecycle, not to Windows client credential
rotation.

## Lifecycle

Normal steady-state production path:

```text
resolve exact accepted ReleaseSet
 -> GitHub-hosted typed provider observe/converge
 -> transport the exact ReleaseSet-bound application bundle
 -> production VM self-hosted low-privilege runner
 -> fixed sudo allowlist -> root-owned local edge-agent
 -> local bundle-converge / bundle-verify / bundle-rollback / diagnose
 -> provider + runtime verification
```

Routine production converge/verify/diagnose/rollback does not acquire a support lease, open SSH, or use a
TCP/gRPC agent listener. `/production enroll-runtime` is the explicit bootstrap/re-enrollment exception
and must compensate its bounded temporary support access before PASS.

Steady-state rollback restores the previous exact accepted application release through the same persistent
self-hosted-runner -> local-owner boundary. The exact current ReleaseSet-bound bundle is used only as stale
authorization: the local owner refuses the swap if active changed, switches to the previous immutable
bundle, and accepts the rollback only after full runtime readiness. The old lease/remote rollback
implementation is deleted from the normal orchestrator surface.

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
