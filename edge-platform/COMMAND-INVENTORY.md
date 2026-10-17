# Command inventory — canonical source audit (2026-10-17)

Source of truth: GitHub `iamaman11/sing-box`, PR #394. Command counts refer to Rust enum variants and are **not** counts of independently exposed user actions.

| Existing entry point | Variants | Meaning |
| --- | ---: | --- |
| edge-orchestrator top-level | 11 | ApplicationLifecycle, ApplicationAcceptance, ApplicationBundleBuild, ApplicationCleanup, CloudflareTargetPlane, CloudflareZeroTrust, Credentials, Host, Production, VultrLifecycle, VultrVpc |
| edge-orchestrator nested | 78 | Host (1, internal credential-peer selector flag), ApplicationLifecycle (1), Production (4), Credentials (24), CloudflareTargetPlane (7), CloudflareZeroTrust (1), MeshProfile (3), VultrLifecycle (29), VultrVpc (8) |
| edge-console Windows | 55 | Internal SCM/privileged install, rollback, credential transitions, proxy selectors, traces, status, diagnostics |
| edge-controller Windows | 13 | Serve/WindowsService, read status, start/stop/restart, selector, trace, deploy/destroy, bootstrap |
| edge-agent VM local | 24 | status/verify/diagnose, quality, credential attest/apply/transition, bundle, Mesh, bootstrap |
| edge-diagnostic Windows | 1 | doctor with optional --fast read-only depth |

## GitHub operator prefix inventory (8 active prefixes)

| Prefix | Current accepted verbs in workflow grammar | Direction |
| --- | --- | --- |
| `/host` | `status [machine-id] [--deep]` | One operator status interface for any registered machine; no implicit mutation |
| `/windows` | diagnose, offline-preflight, apply, quality-line1, converge, start, stop, restart-controller, repair, rollback, acceptance-reconcile, initial-pair-prepare, initial-pair-stage | Preserve distinct native physical operations until typed host apply/recover is complete; status and smoke aliases retired |
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
- The removed `infra/windows/hosts.textproto` is no longer read by the credential workflow. The credential workflow now selects the VM/Windows pair using the same verified Rust protobuf `HostRegistry` as `/host status`; the original application/provider manifest remains independently validated, without a duplicate registry parser. Existing application/Vultr manifests are separate desired resources.
- This inventory is source-level. It is not evidence that runner registration authorization, VM sudoers upgrades, multi-host physical operation, or original A/B BEGIN run 39004301614 has completed.

## Exact Rust CLI variant enumeration

Each name below is a real Rust Clap enum variant. These are code entry points, **not** additional operator permissions.

**edge-orchestrator — top level (11):**
`ApplicationLifecycle, ApplicationAcceptance, ApplicationBundleBuild, ApplicationCleanup, CloudflareTargetPlane, CloudflareZeroTrust, Credentials, Host, Production, VultrLifecycle, VultrVpc`.

**edge-orchestrator — subcommands (78):**
- Host (1): `Status` (with optional machine_id and --deep).
- ApplicationLifecycle (1): `Materialize`.
- Production (4): `Validate, Diagnose, DnsNoop, EnrollRuntime`.
- Credentials (24): `ContractVerify, ExistingJoinBeginPlan, ExistingJoinBeginReadback, ExistingJoinPlan, ExistingJoinReadback, ExistingJoinJournalInspect, ExistingJoinReconcile, InitialLine2ExternalWitness, InitialWorkerProofPlan, InitialWorkerProofUpgrade, InitialPairPreflight, InitialPairJournalObserve, InitialPairJournalReadback, InitialPairCommitPlan, InitialPairCommitReadback, InitialPairCommitReconcile, InitialPairRecoveryPlan, InitialPairRecoveryReadback, InitialPairJournalPlan, InitialPairPublish, InitialWindowsAcceptanceIssue, InitialWindowsAcceptanceCleanup, HostBootstrapConverge, RotateApplication`.
- CloudflareTargetPlane (7): `Inventory, Plan, Converge, ActiveConverge, Verify, VerifyActive, AcceptanceProfile`.
- CloudflareZeroTrust (1): `Doctor`.
- MeshProfile (3): `Plan, Apply, Verify`.
- VultrLifecycle (29): `Doctor, Inventory, Plan, Apply, SubstratePlan, SubstrateApply, SubstrateVerify, EndpointObserve, TransportProof, InitialDnsConverge, InitialPolicyStage, InitialHostProbe, InitialRuntimeApply, InitialRuntimeVerify, RunnerBootstrap, OwnerUpgrade, OwnerRollback, AcquireAccessPlan, AcquireAccess, LeaseAcquire, ReleaseAccessPlan, ReleaseAccess, LeaseRelease, ActionPlan, Action, DestroyPlan, DestroyApply, CleanupPlan, Cleanup`.
- VultrVpc (8): `Inventory, Plan, Apply, AttachmentPlan, AttachmentApply, Verify, CleanupPlan, CleanupApply`.

**edge-console — Windows (55):**
`Menu, EnsureController, Reconcile, Status, Doctor, CredentialState, CredentialInitialProbe, CredentialInitialAttest, CredentialInitialAcceptanceBootstrap, CredentialInitialAcceptanceStage, CredentialInitialLine1Witness, CredentialExistingLine1Witness, SmokeRuntime, Stage2Preflight, ProvisionRuntimeState, PrivilegedPing, PrivilegedRuntimeEvidence, PrivilegedActivate, PrivilegedRollbackPrevious, PrivilegedOfflineActivate, OfflineBootstrap, PrivilegedOfflineRollbackPrevious, PrivilegedReinstallAccepted, PrivilegedRestartControllerService, PrivilegedStartProxyOnlyController, PrivilegedStopProxyOnlyController, PrivilegedStageCredential, PrivilegedInitialCredentialCommit, PrivilegedInitialCredentialRecover, PrivilegedExistingPrepare, PrivilegedExistingJoin, CredentialTransition, RestartVerifyRuntime, VerifyRuntime, QualityLine1, PrivilegedPrepareCredentialAccess, PrivilegedInstallCredentialAccess, PrivilegedConvergeControllerService, PrivilegedDispatch, Secrets, GetSecret, SetSecret, StartLocal, StartLocalVisible, StopLocal, RestartLocal, RestartLocalVisible, GetSelector, GetUbuntuSelector, SetSelector, SetUbuntuSelector, Trace, TraceUbuntu, GetOperation, WatchOperation`.

**edge-controller — Windows (13):**
`Serve, WindowsService, GetStatus, ControllerBootstrapRuntime, BootstrapRuntime, StartLocal, StopLocal, RestartLocal, GetSelector, SetSelector, Trace, Deploy, Destroy`.

**edge-agent — VM local (24):**
`Status, Verify, Diagnose, QualityLine2, CredentialPublicEndpoint, CredentialRuntimeSource, BootstrapBase, BootstrapTunnel, BootstrapFull, BundleConverge, BundleStageInitial, BundleVerify, BundleRollback, MeshVerify, MeshCleanup, CredentialState, CredentialInitialProbe, CredentialInitialAttest, CredentialInitialApply, CredentialInitialVerify, CredentialInitialCommit, CredentialExistingJoin, CredentialStage, CredentialTransition`.
The separate `AcceptanceServe` and `Local` variants are dispatch groups; they do not increase the count of local verbs.

**edge-diagnostic — Windows (1):**
`doctor <current.pb> [--fast]`. The shallow/deep distinction is a parameter, not another command.

## Multi-machine behavior: explicit, not implicit

Multiple distinct `machine_id` records are valid in the same registry. An invocation with a `machine_id` may inspect only that machine and its exact controller/agent. Listing is read-only; it cannot trigger configuration on any machine. For later apply/recover, scope the mutation authority and durable cursor to the requested machine, and allow independent hosts to proceed separately when their resource/credential scopes do not overlap. A paired Windows/VM credential transaction is an explicitly journaled exception and must remain non-replayable.

## Git-owned desired configuration binding

Every registered machine has one `desired_spec_path` in the existing HostRegistry
wire-compatible protobuf (field 6 on the legacy on-wire message). The reference
selects an **existing** Git-owned desired state; it is not a second configuration,
does not contain credentials, and does not imply a change in running state.
Rust validates per-kind spec families and rejects traversal or unset targets.
The host route publishes this exact reference with its validated runner identity.

This is the shared identity/configuration foundation only. A completed `host apply`
must execute the native SYSTEM Windows owner or VM root/Bollard owner, compare
the real observed state to the exact ReleaseSet, and use the original durable
journal to prevent mutations while the A/B BEGIN remains unresolved.
Do not report `apply/recover` as accepted until they are implemented and
physically exercised. The existing legacy operator commands are deliberately
preserved until then.

## Command and CI consolidation — 17 October 2026

- Public `/windows status` and `/windows smoke` were exact aliases of
  `/windows diagnose` and `/windows converge`, respectively. The aliases
  are deleted from the router and the physical workflow; the implementations
  are preserved.
- Removed the **Windows read-only GH journal integration** job from the
  mandatory PR CI graph. The full negative journal fixture suite remains
  in hosted Source checks, including malformed/partial-page and count failures.
  A PR build no longer depends on the user's physical Windows runner.
- Windows program-apply and first-use program-prepare now invoke the same
  read-only complete Issue #26 journal reader. It has no mutation verbs;
  on an incomplete/ambiguous GitHub API response it stops before BEGIN.
- `host status <machine>` can dispatch read-only to the exact Git-owned
  machine labels even if GitHub runner Administration:read is unavailable.
  Unverified runner registration is visibly `UNPROVEN`, not PASS; the
  machine still checks exact RUNNER_NAME. This exception applies **only**
  to read-only observation, never credentials or installation.
- No user-facing command family, daemon, credential store or operator profile
  was added. Pending `host apply/recover` is not treated as implemented.
  Do not remove remaining physical commands before those paths are ported,
  tested and recoverable.

## Independent production protobuf (source capability, not physical acceptance)

The existing shared production loader supports a **pinned external binary protobuf** without rebuilding Rust. A trusted native host process sets **both** `EDGE_PRODUCTION_STATE_PB` (local regular-file path) and `EDGE_PRODUCTION_STATE_SHA256` (exact lowercase SHA-256 from protected Git). Missing/partial, oversized, malformed or mismatched state fails closed. Without either variable, previously installed releases retain their embedded state. Git is the sole source of configuration; the Worker remains exclusively responsible for secrets. The deployment owner must still materialize, check and activate the pinned protobuf before this is a physically accepted configuration workflow.

FAST snapshots now report observation Unix timestamp, reason and next action without claiming unprobed network or credential health. Sub-second/2-second timing and full runtime correctness require physical measurements; no claim is made from CI alone.

## Second integrated source slice: one typed credential host resolver

Credential authorization keeps its original protected GitHub/Worker authority and original A/B journal. The credential workflow reads application/provider resources, but passes the **same pinned binary protobuf** used by `/host status` to the existing Rust orchestrator. An internal hidden status option produces verified exact Windows runner identity and VM machine ID through `GITHUB_OUTPUT` (not diagnostic text parsing). Ambiguous multi-Windows selection requires an explicit machine ID. This is read-only selection, NOT an A/B replay or physical installation.
