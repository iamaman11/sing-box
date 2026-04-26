# Server Architecture

## Production shape

The server-side control plane is:

- `edge-agent` as a Linux host daemon
- `docker compose` for the dataplane
- `systemd` supervising `edge-agent`

The control path is:

- `edge-console` -> `edge-controller` -> `edge-agent`

PowerShell is no longer part of the normal server control path.

## Host model

The target host layout is:

- `/opt/vultr-edge-stack/bin/edge-agent`
- `/opt/vultr-edge-stack/stack`
- `/opt/vultr-edge-stack/tls`

`cloud-init` installs Docker and prepares the host directories. The controller
then installs or updates `edge-agent`, applies the rendered bundle, and drives
bootstrap over gRPC.

## Runtime contract

`edge-agent` is responsible for:

- health/readiness
- runtime inspection
- bundle apply
- bootstrap `base` / `tunnel`
- rendered artifact checks
- bundle identity reporting

Steady-state observation is gRPC-based. SSH is reserved for first-host bootstrap
and controlled maintenance.

## Dataplane topology

The current 5-container topology remains unchanged:

1. `vultr-warp-egress`
2. `vultr-edge-gateway`
3. `vultr-edge-gateway-direct`
4. `vultr-tunnel-edge`
5. `vultr-tunnel-edge-warp`

This is intentionally preserved during the control-plane migration.

## Deploy model

The Rust deploy sequence is:

1. resolve or create the target instance
2. wait for SSH, cloud-init, and Docker when first bootstrap is required
3. install or update `edge-agent`
4. generate trust material and prepared bundle locally
5. apply bundle to `edge-agent`
6. bootstrap base runtime
7. optionally update DNS
8. bootstrap tunnel runtime
9. verify runtime and sync local config
10. persist deployment, trust, secret refs, and operation events

## Recovery model

On failed deploy, the controller rolls back:

- DNS changes when applicable
- freshly created instance when applicable
- local live deployment state
- deployment rows
- trust rows

The goal is to keep controller state internally consistent after a failed run.

## Legacy boundary

Legacy scripts under `win/vultr-waw` are retained only for migration review and
historical comparison. They are not the primary deployment architecture.
