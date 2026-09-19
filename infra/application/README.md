# VM application desired state

This directory is the Git authority for VM application composition. It does not contain provider
instance UUIDs, provider IPs, runtime credentials, or Cloudflare node tokens.

The application lifecycle is separate from the generic Vultr VM lifecycle:

```text
Git desired application state
        |
        v
edge-controller-core::application_lifecycle
        |
        v
edge-controller application-lifecycle
        |
        +-- accepted Vultr lifecycle observation
        +-- accepted strict SSH host-certificate trust
        |
        v
VM edge-agent typed RPC
        |
        v
Docker Compose application bundle
```

## Schema 1

A desired-state file is a strict JSON object:

```json
{
  "schema": 1,
  "environment": "production",
  "vultr_spec_path": "infra/vultr/<canonical-vm-spec>.json",
  "machine_id": "<logical-machine-id>",
  "application_profile": "<profile-declared-by-machine>",
  "bundle_root": "win/vultr-waw/stack",
  "runtime_env_required": true,
  "bootstrap_mode": "base"
}
```

`bootstrap_mode` is currently one of `base`, `tunnel`, or `full`. Mesh is deliberately not
part of this contract yet; it is added only after this GitHub-controlled deployment path is
accepted.

The exact Linux `edge-agent` artifact is not named by a mutable path in desired state. Production
automation builds it from the exact Git revision, computes SHA-256, creates an ephemeral artifact
manifest bound to that revision, verifies the local digest, verifies the uploaded digest, and
re-observes the installed digest after service restart.

`.env.runtime` must never be present under `bundle_root` in Git. When a composition needs runtime
secret material, the caller provides a private file through
`EDGE_APPLICATION_RUNTIME_ENV_PATH`. Its bytes participate in the exact bundle digest and are sent
to `edge-agent` as a sensitive `0600` bundle file.

The generic `VM Application Lifecycle` GitHub workflow intentionally uses only the
`production-vultr` environment and does not source application or Cloudflare secrets. Therefore a
secret-requiring spec is observable/plannable there but cannot be mutated there without a separate,
narrow orchestration authority. Line-specific orchestration (for example Line 3) must inject its
runtime secret only for the job that actually requires it.

## Operations

```text
application-lifecycle plan
application-lifecycle apply
application-lifecycle verify
application-lifecycle upgrade
application-lifecycle rollback-plan
application-lifecycle rollback-apply
```

`apply` creates the first published application release and refuses to overwrite an existing
release; `upgrade` requires an existing published release. Successful convergence is a NOOP on the
next observation.

Rollback is digest-authorized and re-observed. The VM keeps exactly one previous application bundle
and one previous `edge-agent` artifact as recovery material. This is runtime recovery metadata, not
a second desired-state database.

No canonical production application JSON is committed here until the production VM desired-state
composition is explicitly accepted.
