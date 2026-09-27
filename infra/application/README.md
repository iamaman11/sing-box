# VM application desired state

## Authority

Canonical production desired state is:

`infra/production/production.textproto`

backed by `ProductionDesiredState` protobuf.

Production does not use a graph of JSON sub-specs as authority.

Current production ownership:

```text
Git production.textproto
        |
        v
edge-orchestrator
        |
        +-- Vultr provider lifecycle
        +-- shared alegria.by DNS lifecycle
        +-- Cloudflare Mesh / production composition
        |
        v
strict SSH local forward
        |
        v
edge-agent (loopback)
        |
        v
Docker Compose application runtime
```

Issue #169 defines the accepted migration of application-exclusive Cloudflare account-scoped
resources into the dedicated `sing-box` account and the new credential-delivery model.

## Application/runtime ownership

The VM `edge-agent`:
- receives an exact accepted application artifact/bundle;
- owns bounded local apply/rollback/observation;
- observes Docker/runtime/network state;
- does not own provider desired state;
- does not select the production ReleaseSet;
- does not expose arbitrary shell/filesystem/Docker mutation APIs.

The orchestrator owns provider/application composition and exact lifecycle sequencing.

## Runtime secrets

Application secret values are never Git desired state.

Historical/current compatibility code may materialize `.env.runtime` for the container stack.
That file is a generated consumer artifact and must not become a second durable source of truth.

Accepted target after #169:
- typed local active/candidate credential state;
- fresh generations, not imported legacy Windows credentials;
- VM/Windows receive separate credential projections;
- generated `.env.runtime` and sing-box JSON are reproducible from typed policy + typed local
  secret state;
- missing desired production generation fails closed instead of silently generating a new identity.

Secret lifecycle classes remain separate: client tunnel credentials, server identity, Line 2
authentication, Cloudflare Access machine identities, Mesh node token and provider API credentials
do not rotate as one monolithic bundle unless their actual lifecycle requires it.

## VM control transport

Canonical production uses strict SSH host-certificate trust and a bounded local forward to
loopback `edge-agent`.

GitHub-hosted runner egress support access is a temporary provider-lifecycle lease and is cleaned
up/re-observed after use.

The target is not a new remote shell or second control daemon.

## Application operations

Lower-level typed application operations remain implementation boundaries for:
- materialize/apply;
- verify;
- upgrade;
- rollback.

Normal production operation converges toward the single `/production` composition surface rather
than exposing independent production-facing DNS/Mesh/Zero Trust owners.

## Rollback

Keep one previous accepted application release/artifact identity for bounded runtime rollback.

Credential rollback is separate from release rollback. Issue #169 uses a fixed A/B credential
buffer so a previous accepted credential generation remains available for a bounded grace/recovery
period without introducing a secret-history database.

## Legacy JSON

Files under `infra/application/*.json`, `infra/cloudflare/*.json` and similar acceptance paths
are frozen migration debt unless an active disposable/legacy test still consumes them.

Rules:
- no new production authority in JSON;
- migrate/delete a legacy JSON contract when its owning path is touched;
- never replace one internal JSON contract with another internal JSON contract.

## Disposable acceptance

Disposable acceptance may keep legacy JSON inputs until its path is deliberately migrated.
It must remain isolated from permanent production state and must leave zero leaked resources.
