# Vultr WAW application stack

## Current role

This directory contains canonical Linux host/bootstrap and application bundle inputs for the Warsaw
production edge VM.

Server/provider lifecycle authority is outside Windows:
- `edge-orchestrator` owns production composition;
- `edge-provider-vultr` is the only Vultr API adapter;
- GitHub workflows provide owner/environment authorization and invoke exact typed owners;
- Windows owns only Windows-local runtime/configuration.

There is no supported direct PowerShell VM create/delete/SSH deployment path.

## Stack

`stack/docker-compose.yml` currently defines:
- `warp-egress`;
- `line1-gateway` (tunnel profile);
- `line2-proxy`;
- `cloudflare-mesh` (mesh profile).

Accepted-main CI publishes exact immutable image identities. Production pulls exact digests and does
not build project images on the VM.

## Control flow

Routine steady-state production flow:

```text
protected main
  -> exact-head CI / candidate acceptance
  -> immutable ReleaseSet
  -> GitHub-hosted edge-orchestrator provider composition
  -> production VM self-hosted low-privilege runner
  -> fixed sudo allowlist
  -> root-owned local edge-agent
  -> exact application bundle converge / verify / diagnose
```

Routine production does not acquire a temporary support lease, open SSH, local-forward to port 50061,
or use the network edge-agent service. Strict SSH remains only for explicit enrollment/reinstallation,
migration, or break-glass recovery and must be compensated before PASS. Production rollback is not yet
a public operator command on current `main`; the remaining Stage-3 slice must reuse the persistent
runner -> local-owner boundary rather than the legacy lease/remote rollback path.

## Runtime secrets

Do not commit `.env.runtime` or rendered credential-bearing config.

The canonical architecture owns the fresh typed credential model delivered through isolated
VM/Windows Cloudflare projections; #26 owns execution. Generated runtime env/JSON remains a consumer artifact.

Do not reintroduce:
- legacy credential import;
- direct Windows provider credentials;
- TOFU SSH;
- runtime Docker builds;
- mutable image tags;
- generic remote shell/agent APIs.

## Destruction / cleanup

Destructive provider operations remain exact-plan/digest authorized and must re-observe absence.

A successful full lifecycle must prove support-resource cleanup and zero leaked disposable
resources.
