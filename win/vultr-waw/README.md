# Vultr WAW Stack

## Current role

This directory contains only canonical Linux host/bootstrap and application
bundle inputs for the Warsaw edge VM.

Server lifecycle authority is intentionally outside Windows:

- `.github/workflows/vultr-lifecycle.yml` owns VM create, observe, actions,
  destroy-plan, destroy-apply, and support-resource cleanup.
- `.github/workflows/vm-application-lifecycle.yml` owns exact edge-agent and
  application bundle apply, verify, upgrade, and rollback.
- `edge-provider-vultr` is the only Vultr HTTP/provider adapter.
- Windows automation owns only the Windows-local controller, configuration,
  selectors, and local sing-box runtime.

There is no supported direct PowerShell VM create/delete/SSH deployment path.

## Inputs kept here

- `cloud-init.yaml` — minimal host preparation used by the typed Vultr
  lifecycle.
- `stack/` — application bundle source:
  - Compose definition;
  - typed bootstrap script;
  - sing-box configuration templates;
  - Dockerfiles used only by accepted-main CI to build immutable images.

Production VM bootstrap never builds application images. Accepted-main CI
publishes exact image digests; application lifecycle injects those non-secret
digest references as `.images.env`; the VM only pulls and runs those exact
digests.

## Control flow

```text
accepted main
  -> Edge Platform CI verify
  -> one immutable release set
       edge-controller SHA-256
       edge-agent SHA-256
       edge-gateway image digest
       warp-egress image digest
  -> GitHub Vultr/Application lifecycle
  -> strict SSH transport
  -> edge-agent typed apply/bootstrap
  -> observed readiness
```

VM destruction is only:

```text
vultr-lifecycle destroy-plan
  -> exact digest authority
  -> vultr-lifecycle destroy-apply
  -> observed ABSENT
```

Do not reintroduce direct Windows Vultr API mutation, TOFU SSH enrollment,
runtime Docker builds, mutable image tags, or an external VM reaper.
