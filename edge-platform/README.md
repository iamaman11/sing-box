# edge-platform

Rust control-plane workspace for `iamaman11/sing-box`.

For execution order read GitHub Issue #26 first. For stable ownership/invariants read
`ARCHITECTURE.md`.

## Runtime owners

```text
edge-orchestrator (GitHub-hosted)
  -> Vultr / Cloudflare provider lifecycle only

production VM:
GitHub self-hosted runner (low privilege, transport only)
  -> exact allowlisted sudo commands
  -> root-owned local edge-agent runtime owner
  -> fixed Docker Compose mutations
  -> Bollard + rtnetlink observations
  -> Docker Engine / four-container runtime

Windows:
GitHub self-hosted runner (NetworkService transport only)
  -> SYSTEM EdgePlatformPrivilegedDispatch
  -> SCM EdgePlatformController
  -> native sing-box runtime

edge-diagnostic.exe
  -> independent read-only Windows diagnostics
```

The Linux local owner reuses the existing mature Docker/Compose/Bollard/runtime logic. The target removes its routine TCP/gRPC/SSH transport role, not the Docker runtime itself.

## Canonical production authority

- desired state: `infra/production/production.textproto`;
- exact release identity: immutable `ReleaseSet.pb` / durable release publication;
- provider reality: fresh Vultr/Cloudflare observations;
- Windows activation: `C:\sing-box\current.pb` plus exact immutable release directory;
- VM application activation: exact accepted application release/bundle + immutable image digests.

GitHub Actions is an authorization/execution transport. It does not own lifecycle semantics.

## Windows trust/runtime boundary

Canonical application root:

```text
C:\sing-box
  current.pb
  previous.pb
  releases\<release-set-sha256>\
  bin\
  state\
    secrets\
  runtime\
  logs\
  exchange\
```

Transport root is separate:

```text
C:\sing-box-runner
```

Accepted ownership:
- SCM service: `EdgePlatformController`;
- service identity: `NT SERVICE\EdgePlatformController`;
- GitHub runner: NetworkService transport only;
- SYSTEM privileged bridge: `EdgePlatformPrivilegedDispatch`;
- runner has no plaintext/decrypted application-secret authority.

The console is not a fallback startup owner. Do not restore child-process controller autostart.

## Credential transition

Fresh application credentials use the accepted paired Windows/VM projections and fixed Worker A/B slots. Delivery to each local owner must be runner-blind. Direct Worker fetch is used only if the host identity bootstrap/rotation lifecycle is proven; otherwise the boundary uses the smallest audited standard recipient-encrypted handoff.

Runners carry only non-secret generation/slot/operation intent and never receive plaintext credential payloads.

## VM transport

Steady-state VM operations use the repository self-hosted production runner as outbound transport only:

```text
GitHub
 -> self-hosted low-privilege runner
 -> exact allowlisted local operation
 -> root-owned edge-agent local owner
 -> Compose mutation / Bollard observation
```

Routine application/runtime operations do not require GitHub-hosted-runner SSH, temporary /32 ingress, SSH local-forwarding or a TCP/gRPC agent listener. Strict SSH remains bootstrap/migration/break-glass only until the last recovery dependency is retired.

The runner has no provider credentials, no generic root, no Docker socket access and no application credential plaintext authority.

The old standalone `/mesh` workflow is not a steady-state control surface. Mesh provider lifecycle is part of the hosted production target plane; VM Mesh runtime operations stay inside the local owner.

For a fresh or re-enrolled production VM, `/production enroll-runtime` is the bounded bootstrap path: temporary strict SSH -> host substrate/VPC -> exact local owner -> permanent self-hosted runner -> SSH lease removed. Normal `/production converge|verify|diagnose` does not use SSH.

## Build/release model

```text
exact source
 -> exact-head CI
 -> build once
 -> candidate acceptance
 -> protected merge
 -> promotion of exact accepted bytes (no rebuild)
 -> durable immutable ReleaseSet
```

Production never builds Rust or project OCI images on the target VM/Windows machine.

## Full lifecycle target

Typed owners must eventually cover:

- bootstrap/enrollment;
- provision;
- deploy;
- converge;
- verify;
- diagnose;
- upgrade;
- release rollback;
- credential rotation/rollback;
- reboot/recovery;
- cleanup/destroy;
- zero-leak verification.

Normal operation must not require manual secret copying or a legacy checkout.

## First-party serialization

- `.textproto` — human-authored Git desired state;
- `.pb` — canonical machine/durable state;
- JSON — only where an external consumer/protocol requires it.

Existing internal JSON is frozen migration debt and may only shrink.

## Safety

Never reintroduce:
- Windows provider mutation authority;
- arbitrary remote PowerShell/SSH production surfaces;
- TOFU SSH success paths;
- mutable release authority;
- plaintext credentials in Git/Issues/Actions/Release assets;
- a second desired-state store;
- a second Windows startup owner.
