# Command inventory — canonical source audit (2026-10-17)

Source of truth: GitHub `iamaman11/sing-box`, PR #394. Command counts refer to Rust enum variants and are **not** counts of independently exposed user actions.

| Existing entry point | Variants | Meaning |
| --- | ---: | --- |
| edge-orchestrator top-level | 11 | ApplicationLifecycle, ApplicationAcceptance, ApplicationBundleBuild, ApplicationCleanup, CloudflareTargetPlane, CloudflareZeroTrust, Credentials, Host, Production, VultrLifecycle, VultrVpc |
| edge-orchestrator nested | 78 | Host (1), ApplicationLifecycle (1), Production (4), Credentials (24), CloudflareTargetPlane (7), CloudflareZeroTrust (1), MeshProfile (3), VultrLifecycle (29), VultrVpc (8) |
| edge-console Windows | 55 | Internal SCM/privileged install, rollback, credential transitions, proxy selectors, traces, status, diagnostics |
| edge-controller Windows | 13 | Serve/WindowsService, read status, start/stop/restart, selector, trace, deploy/destroy, bootstrap |
| edge-agent VM local | 24 | status/verify/diagnose, quality, credential attest/apply/transition, bundle, Mesh, bootstrap |
| edge-diagnostic Windows | 1 | doctor with optional --fast read-only depth |

## GitHub operator prefix inventory (8 active prefixes)

| Prefix | Current accepted verbs in workflow grammar | Direction |
| --- | --- | --- |
| `/host` | `status [machine-id] [--deep]` | One operator status interface for any registered machine; no implicit mutation |
| `/windows` | status, diagnose, offline-preflight, apply, quality-line1, converge, smoke, start, stop, restart-controller, repair, rollback, acceptance-reconcile, initial-pair-prepare, initial-pair-stage | Preserve as legacy low-level physical path pending typed host apply/recover replacement |
| `/production` | enroll-runtime, converge, verify, diagnose, quality-line2, rollback | Legacy fixed VM path; migration target is machine-id based |
| `/vm` | diagnose, quality-line2, credential-runtime-source, credential-initial-probe | Manifest-selected VM read-only path, internalized by host owner after acceptance |
| `/application` | mesh-profile-plan, mesh-profile-verify, mesh-profile-apply, acceptance, cleanup | App/Cloudflare operations, not generic machine selection |
| `/vultr` | doctor, inventory, plan, apply, cleanup-plan, cleanup, access-release, action-plan, start/halt/reboot, runner-bootstrap, owner-upgrade/rollback, destroy-plan/apply, initial-vm-install, initial-acceptance-resume, acceptance | Provider operations, no new operator facade |
| `/vpc` | inventory, plan, apply, attachment-plan/apply, verify, cleanup-plan/apply | Network provider operations |
| `/credentials` | verify, status, apply, recover, host-bootstrap-converge, rotate tunnel-auth/reality-identity/line2-proxy-auth, initial-pair-preflight/commit/recover | Single credential authority, journaled A/B: must not be replayed |

## Removed redundant commands in this PR

- Deleted public `/fleet inventory`, `/fleet status`, `/fleet inspect`, `/fleet fast`, `/fleet doctor` and Rust `fleet` root.
- Removed separate `edge-diagnostic fast` and `edge-agent local fast` variants; depth is now an option of existing doctor/status.
- One Git-owned typed `HostRegistry` in `infra/hosts/hosts.textproto`; it has an explicit unique machine ID and exact owner selector for any number of Windows/VM registrations.

## Convergence contract

- Status is read-only and can list all registered hosts. Each physical command binds **one exact machine_id**.
- Each mutation must be bound to an exact host (or an explicitly journaled paired A/B transaction), have an exclusive operation owner and refuse replay after an uncertain outcome.
- Do not expose `/host apply` or `/host recover` until the existing Windows SYSTEM and VM root paths are actually unified and physically accepted.
- Existing workflow branches and commands continue to work; removing them prematurely would delete unported functionality.
- The old `infra/windows/hosts.textproto` is still read by the credential workflow: retire this duplicate only when its consumers use HostRegistry. Existing fixed application/Vultr manifests are still present and are not yet unified.
- This inventory is source-level. It is not evidence that runner registration authorization, VM sudoers upgrades, multi-host physical operation, or original A/B BEGIN run 39004301614 has completed.
