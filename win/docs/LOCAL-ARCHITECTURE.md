# Local Architecture

## Production shape

The Windows-side control plane is now Rust-first:

- `edge-controller` - local daemon and only orchestrator
- `edge-console` - operator console client
- local `sing-box` - managed runtime

PowerShell scripts remain only as legacy reference.

## Local runtime model

The managed local config stays:

- `win/windows/edge-dns-clean-vultr-dual.json`

The managed local runtime surface includes:

- process discovery
- expected-config ownership checks
- start/stop/restart for the managed config only
- Clash API selector read/write
- current trace/IP/WARP/colo observation

The controller must refuse to replace or stop a foreign `sing-box` process.

## State model

The controller keeps authoritative local state in SQLite:

- deployments
- operations
- operation events
- trust store
- secret refs

Local JSON files such as `win/vultr-waw/current-edge.json` are retained only as
derived or transitional artifacts. They are not the architectural source of
truth anymore.

## Secret model

Secrets are configured as persisted secret references in controller state.

Supported logical secrets:

- Vultr API key
- Cloudflare API token
- Vultr SSH key id
- SSH private key path

Supported reference formats:

- `env:`
- `file:`
- `path:`
- `literal:`

## Operator model

Normal operation goes through `edge-console`, either in menu mode or command
mode.

Examples:

- `edge-console status`
- `edge-console start-local`
- `edge-console set-selector auto-direct-tunnel`
- `edge-console trace`
- `edge-console deploy`
- `edge-console destroy`
- `edge-console secrets`
- `edge-console watch-operation <id>`

## Legacy boundary

Legacy files under `win/windows` still document the old behavior and are useful
for parity review, but they are no longer the primary control path.
