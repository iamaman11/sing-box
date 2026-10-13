# VM application desired state

## Authority

Git owns desired application policy. The exact durable ReleaseSet owns immutable executable/image identity. The production VM self-hosted runner is transport only; the root-owned local runtime owner performs VM-local lifecycle operations.

```text
protected main + exact ReleaseSet
        |
        v
production VM self-hosted runner
        |
        v
root-owned typed local owner
   +-- fixed Docker Compose mutation
   +-- Bollard Docker observation
   '-- rtnetlink / bounded host probes
        |
        v
Docker Engine / application runtime
```

Provider lifecycle remains GitHub-hosted. No provider credential moves onto the VM.

## Application/runtime ownership

The Linux local owner owns only VM-local application lifecycle, configuration, runtime observation and local credential state.

- Docker Compose remains the declarative four-container composition/mutation adapter.
- Bollard remains the typed Docker Engine observation/diagnostic adapter.
- The runner invokes only a closed allowlist of local operations.
- No arbitrary shell/filesystem/Docker/systemd API is exposed.
- The retired TCP/gRPC edge-agent transport is not steady-state authority.

## Runtime secrets

Application secret values are never Git desired state.

Historical/current compatibility code may materialize `.env.runtime` for the container stack.
That file is a generated consumer artifact and must not become a second durable source of truth.

Accepted canonical credential target:
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

Steady-state control is outbound GitHub runner transport plus the local typed owner. Routine operation does not acquire a temporary /32 SSH lease and does not local-forward to port 50061.

Strict SSH may be used only for bootstrap, migration or explicit break-glass recovery and must be closed again after enrollment/recovery.

## Application operations

Lower-level typed application operations remain implementation boundaries for:
- materialize/apply;
- verify;
- upgrade;
- rollback.

Normal production operation uses the single `/production` composition surface rather than exposing
independent production-facing DNS/Mesh/Zero Trust owners. `/production rollback` uses the same
persistent self-hosted-runner -> root-owned local-owner boundary as converge/verify and authorizes the
mutation with the exact active bundle digest; the old lease/SSH rollback dispatch is not a production path.

## Rollback

Keep one previous accepted application release/artifact identity for bounded runtime rollback.

Credential rollback is separate from release rollback. The canonical credential architecture uses a fixed A/B credential
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


### Universal, read-only VM checks (GitHub operator)

Target an **exact canonical application manifest** instead of a hardcoded VM name:

```text
/vm diagnose infra/application/disposable-acceptance.json
/vm quality-line2 infra/application/disposable-acceptance.json
/vm credential-initial-probe infra/application/disposable-acceptance.json
```

The protected GitHub revision supplies `machine_id`, `vultr_spec_path`, application profile, and runner selection. The workflow rejects missing, ambiguous, or inconsistent declarations before scheduling a self-hosted runner and requires its observed identity to match the Git-owned machine. The same syntax applies to every VM with a canonical application manifest; it does not discover/operate unmanaged hosts. Both commands are read-only and never install containers or publish credentials. Credential-bearing converge/rollback require a **per-target immutable ReleaseSet bundle and verified provider ownership** and are deliberately not exposed by this read-only interface yet.

The initial credential probe is read-only. The existing root-owned edge-agent proves the exact canonical dummy A/B Worker deliveries using its VM-only Cloudflare Access identity and requires an empty local credential store, no application containers and a reachable Docker daemon. It does not stage, publish or promote credentials.

The VM credential preflight inspects **both** reserved dummy generations through its own Cloudflare Access identity. A 404 at the exact dummy generation is reported as `NOT_FOUND_OR_OTHER_GENERATION`, **not** as an empty Worker slot or permission to publish. A syntactically valid non-dummy payload is reported only as `NONCANONICAL_PAYLOAD`; secret bytes and discovered generations are never logged. Any such result fails closed; provider metadata alone cannot resolve it. The active initial-pair journal, Worker version fences and no-replay ownership remain mandatory before any first-use write.
