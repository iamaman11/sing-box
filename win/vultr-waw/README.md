# Vultr WAW Stack

## Current role

This directory now provides the server bundle templates and legacy reference
material for the Warsaw edge deployment.

Primary orchestration is Rust-first:

- `edge-controller serve`
- `edge-console deploy`
- `edge-console destroy`

## What stays here

- `cloud-init.yaml`
- `stack/`
  - compose file
  - bootstrap script
  - config templates
  - Dockerfiles for the current dataplane

These files remain inputs to the Rust bundle/render/apply pipeline.

## Current deployment model

The Rust controller:

1. resolves or creates the Vultr instance
2. waits for host readiness
3. installs `edge-agent`
4. renders the full bundle locally
5. sends the bundle to the host through `AgentService.ApplyBundle`
6. drives `base` and `tunnel` bootstrap through `AgentService.BootstrapRuntime`

Steady-state status/readiness comes from `edge-agent` gRPC.

## Legacy reference only

The old PowerShell scripts in this directory are preserved only for migration
review:

- `deploy-waw.ps1`
- `destroy-edge.ps1`
- `status-edge.ps1`
- `verify-edge.ps1`

They are not the primary deployment entrypoint anymore.
