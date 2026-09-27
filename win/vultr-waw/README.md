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

```text
protected main
  -> exact-head CI / candidate acceptance
  -> immutable ReleaseSet
  -> edge-orchestrator
       -> Vultr lifecycle
       -> strict SSH local-forward
       -> loopback edge-agent
       -> exact application apply/verify/rollback
       -> Cloudflare/DNS production composition
```

## Runtime secrets

Do not commit `.env.runtime` or rendered credential-bearing config.

Issue #169 owns the transition to fresh typed credential generations delivered through isolated
VM/Windows Cloudflare projections. Generated runtime env/JSON remains a consumer artifact.

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
