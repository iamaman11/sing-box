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
