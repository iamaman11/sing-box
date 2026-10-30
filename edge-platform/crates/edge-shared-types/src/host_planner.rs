//! One pure typed desired -> observed transition planner for Windows and VM.
//!
//! A plan is NOT an executable authorization. The caller can copy/forge
//! observation protobuf bytes. Native owner identity, Worker authorization,
//! durable journal admission and physical readback are separate requirements.
use crate::{
    FleetHost, FleetHostKind, FleetHostMode, FleetHostPlanReason, FleetHostPlannedStep,
    FleetHostRunState, FleetHostTransitionPlan, FleetNativeObservation, FleetNativeOwnerState,
    FleetNativeReleaseProof, host_lifecycle::validate_native_observation,
};

fn plan(
    host: &FleetHost,
    step: FleetHostPlannedStep,
    reason: FleetHostPlanReason,
    expected: &[u8],
    observed: &[u8],
) -> FleetHostTransitionPlan {
    FleetHostTransitionPlan {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        step: step as i32,
        reason_code: reason
            .as_str_name()
            .strip_prefix("FLEET_HOST_PLAN_REASON_")
            .expect("protobuf host reason prefix")
            .to_owned(),
        reason: reason as i32,
        expected_release_digest: expected.to_vec(),
        observed_release_digest: observed.to_vec(),
        owner_attested: false,
        mutation_authorized: false,
    }
}

/// Compute a deterministic and strictly non-authorizing proposal. Windows
/// compares the activation ReleaseSet digest; VM compares the logical
/// bundle digest derived from the verified exact ApplyBundleRequest,
/// NEVER the transport digest or the whole ReleaseSet digest.
pub fn propose_host_transition(
    host: &FleetHost,
    observed: Option<&FleetNativeObservation>,
    expected_release_set_sha256: &[u8],
    expected_vm_bundle_sha256: &[u8],
    now_unix: u64,
) -> FleetHostTransitionPlan {
    use FleetHostPlannedStep::{Blocked, Install, Noop, ReplaceRelease, Start, Stop};
    let kind = match FleetHostKind::try_from(host.kind) {
        Ok(FleetHostKind::Windows) => FleetHostKind::Windows,
        Ok(FleetHostKind::Vm) => FleetHostKind::Vm,
        _ => {
            return plan(
                host,
                Blocked,
                FleetHostPlanReason::HostKindInvalid,
                &[],
                &[],
            );
        }
    };
    let expected = if kind == FleetHostKind::Windows {
        expected_release_set_sha256
    } else {
        expected_vm_bundle_sha256
    };
    if expected.len() != 32 || !expected.iter().any(|b| *b != 0) {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::ExpectedReleaseUnproven,
            expected,
            &[],
        );
    }
    let target = match &host.target {
        Some(target) => target,
        None => {
            return plan(
                host,
                Blocked,
                FleetHostPlanReason::TargetUnsetObserveOnly,
                expected,
                &[],
            );
        }
    };
    let desired_run = match FleetHostRunState::try_from(target.run_state) {
        Ok(FleetHostRunState::Running) => FleetHostRunState::Running,
        Ok(FleetHostRunState::Stopped) => FleetHostRunState::Stopped,
        _ => {
            return plan(
                host,
                Blocked,
                FleetHostPlanReason::TargetRunStateUnproven,
                expected,
                &[],
            );
        }
    };
    let desired_mode = match FleetHostMode::try_from(target.windows_mode) {
        Ok(mode) => mode,
        _ => {
            return plan(
                host,
                Blocked,
                FleetHostPlanReason::TargetModeUnproven,
                expected,
                &[],
            );
        }
    };
    // Never block an emergency STOP merely because the recorded target
    // describes ManagedTun. Stopped is safe; START/INSTALL/CONFIGURE still
    // require the independent native route-capture admission.
    if kind == FleetHostKind::Windows
        && desired_mode == FleetHostMode::ManagedTun
        && desired_run != FleetHostRunState::Stopped
    {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::TunSeparatePhysicalGateRequired,
            expected,
            &[],
        );
    }
    if kind == FleetHostKind::Windows
        && !matches!(
            desired_mode,
            FleetHostMode::ProxyOnly | FleetHostMode::ManagedTun
        )
        || kind == FleetHostKind::Vm && desired_mode != FleetHostMode::Unspecified
    {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::TargetModeKindMismatch,
            expected,
            &[],
        );
    }
    let observed = match observed {
        Some(observed) => observed,
        None => {
            return plan(
                host,
                Blocked,
                FleetHostPlanReason::NativeReadbackRequired,
                expected,
                &[],
            );
        }
    };
    let actual = observed.observed_release_sha256.as_slice();
    if validate_native_observation(observed).is_err() || observed.host_kind != host.kind {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::NativeReadbackInvalidOrWrongKind,
            expected,
            actual,
        );
    }
    if observed.observed_at_unix > now_unix.saturating_add(60)
        || now_unix.saturating_sub(observed.observed_at_unix) > 300
    {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::NativeReadbackStale,
            expected,
            actual,
        );
    }
    // A known degraded datapath or an EXACT native-owned partial resource
    // readback permits only a proposal to converge a DIFFERENT VM bundle.
    // A generic 'stopped' observation cannot satisfy this gate. The existing
    // pre-BEGIN resource effector must independently verify all Docker IDs.
    let vm_known_resource_bundle_drift = kind == FleetHostKind::Vm
        && desired_run == FleetHostRunState::Running
        && observed.release_proof == FleetNativeReleaseProof::ApplicationBundle as i32
        && actual.len() == 32
        && actual.iter().any(|byte| *byte != 0)
        && actual != expected
        && !observed.reason_codes.is_empty()
        && ((observed.owner_state == FleetNativeOwnerState::Running as i32
            && crate::host_lifecycle::known_runtime_only_historical_reasons(observed))
            || crate::host_lifecycle::known_partial_vm_resource_baseline(host, observed));
    let vm_known_same_release_runtime_defect = kind == FleetHostKind::Vm
        && desired_run == FleetHostRunState::Running
        && observed.owner_state == FleetNativeOwnerState::Running as i32
        && observed.release_proof == FleetNativeReleaseProof::ApplicationBundle as i32
        && actual == expected
        && crate::host_lifecycle::known_runtime_only_historical_reasons(observed);
    // An exact native readback of ONE lost owned network object may
    // request the existing VM scoped START step. This is only a pure
    // proposal; root preflight must independently prove the lost resource
    // and a fresh Worker-signed APPLY must pass durable BEGIN.
    let vm_known_same_release_network_loss = kind == FleetHostKind::Vm
        && desired_run == FleetHostRunState::Running
        && observed.owner_state == FleetNativeOwnerState::Running as i32
        && observed.release_proof == FleetNativeReleaseProof::ApplicationBundle as i32
        && actual == expected
        && observed.runtime_ready_proven
        && !observed.runtime_ready
        && observed.reason_codes.len() == 1
        && observed.reason_codes[0] == "VM_MANAGED_NETWORK_MISSING";
    if !observed.reason_codes.is_empty()
        && !vm_known_resource_bundle_drift
        && !vm_known_same_release_runtime_defect
        && !vm_known_same_release_network_loss
    {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::NativeReadbackDegraded,
            expected,
            actual,
        );
    }
    let state = match FleetNativeOwnerState::try_from(observed.owner_state) {
        Ok(value) => value,
        Err(_) => {
            return plan(
                host,
                Blocked,
                FleetHostPlanReason::NativeStateUnproven,
                expected,
                actual,
            );
        }
    };
    if matches!(
        state,
        FleetNativeOwnerState::Unproven | FleetNativeOwnerState::Transitioning
    ) {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::NativeStateUnproven,
            expected,
            actual,
        );
    }
    let proof = FleetNativeReleaseProof::try_from(observed.release_proof);
    // Fresh install is a different, typed state from a missing/unreadable
    // readback. This remains a proposal; no signed intent or root authority
    // can be inferred from an untrusted observation file.
    if proof == Ok(FleetNativeReleaseProof::VerifiedAbsent) {
        // RUNNING is the only explicit target that may request a fresh
        // installation. STOPPED means "do not start", not "install anyway".
        // Without a separate typed installation target, abstain rather than
        // invent a mutation for an intentionally stopped machine.
        return match (desired_run, state) {
            (FleetHostRunState::Running, FleetNativeOwnerState::Stopped) => plan(
                host,
                Install,
                FleetHostPlanReason::VerifiedAbsentInstallProposalOnly,
                expected,
                &[],
            ),
            (FleetHostRunState::Stopped, FleetNativeOwnerState::Stopped) => plan(
                host,
                Blocked,
                FleetHostPlanReason::AbsentInstallWithStoppedTarget,
                expected,
                &[],
            ),
            _ => plan(
                host,
                Blocked,
                FleetHostPlanReason::AbsenceOwnerStateConflict,
                expected,
                &[],
            ),
        };
    }
    let expected_proof = if kind == FleetHostKind::Windows {
        FleetNativeReleaseProof::ActivationRecord
    } else {
        FleetNativeReleaseProof::ApplicationBundle
    };
    if proof != Ok(expected_proof) {
        return plan(
            host,
            Blocked,
            FleetHostPlanReason::NativeReleaseProofUnproven,
            expected,
            actual,
        );
    }
    // STOPPED is a safety target, not permission to roll out a different
    // release to a running service. Even with a release mismatch, first
    // select STOP. A stopped host with a different release remains BLOCKED
    // until a distinct accepted installation target exists.
    if desired_run == FleetHostRunState::Stopped {
        return match state {
            FleetNativeOwnerState::Running => plan(
                host,
                Stop,
                FleetHostPlanReason::StopTargetOverridesReleaseMismatch,
                expected,
                actual,
            ),
            FleetNativeOwnerState::Stopped if actual != expected => plan(
                host,
                Blocked,
                FleetHostPlanReason::StoppedReleaseMismatchRequiresInstallTarget,
                expected,
                actual,
            ),
            FleetNativeOwnerState::Stopped => plan(
                host,
                Noop,
                FleetHostPlanReason::StoppedMatchesDesiredLocalOnly,
                expected,
                actual,
            ),
            _ => plan(
                host,
                Blocked,
                FleetHostPlanReason::NativeStateUnproven,
                expected,
                actual,
            ),
        };
    }
    if actual != expected {
        return plan(
            host,
            ReplaceRelease,
            FleetHostPlanReason::ReleaseMismatchProposalOnly,
            expected,
            actual,
        );
    }
    match (desired_run, state) {
        (FleetHostRunState::Running, FleetNativeOwnerState::Stopped) => plan(
            host,
            Start,
            FleetHostPlanReason::StartProposalOnly,
            expected,
            actual,
        ),
        (FleetHostRunState::Running, FleetNativeOwnerState::Running)
            if observed.runtime_ready_proven && observed.runtime_ready =>
        {
            plan(
                host,
                Noop,
                FleetHostPlanReason::RunningMatchesLocalNotExternal,
                expected,
                actual,
            )
        }
        (FleetHostRunState::Running, FleetNativeOwnerState::Running)
            if kind == FleetHostKind::Vm && observed.runtime_ready_proven =>
        {
            // A degraded VM may have only one stopped container. The root
            // Agent MUST independently inspect exact Compose IDs and prove a
            // stopped resource before BEGIN; no blind network-only restart.
            plan(
                host,
                Start,
                FleetHostPlanReason::VmDegradedRequiresScopedContainerPreadmission,
                expected,
                actual,
            )
        }
        _ => plan(
            host,
            Blocked,
            FleetHostPlanReason::RuntimeReadinessUnproven,
            expected,
            actual,
        ),
    }
}

/* Host and per-resource plans obey the same fail-closed contract: one
 * Protobuf reason, one planned step, no inferred privilege from observation.
 */
/// A freshly authorized APPLY may update a proven STOPPED Windows owner
/// while keeping it STOPPED. STOP/START/RECOVER never acquire this authority.
pub fn propose_signed_host_transition(
    host: &FleetHost,
    observed: &FleetNativeObservation,
    action: crate::FleetHostAction,
    expected_release: &[u8],
    expected_bundle: &[u8],
    now: u64,
) -> FleetHostTransitionPlan {
    let mut proposal =
        propose_host_transition(host, Some(observed), expected_release, expected_bundle, now);
    if host.kind == FleetHostKind::Windows as i32
        && action == crate::FleetHostAction::Apply
        && proposal.reason
            == FleetHostPlanReason::StoppedReleaseMismatchRequiresInstallTarget as i32
    {
        proposal = plan(
            host,
            FleetHostPlannedStep::ReplaceRelease,
            FleetHostPlanReason::ReleaseMismatchProposalOnly,
            expected_release,
            &observed.observed_release_sha256,
        );
    }
    proposal
}

pub fn validate_host_transition_plan(
    proposal: &FleetHostTransitionPlan,
    host: &FleetHost,
) -> Result<(), &'static str> {
    use crate::FleetHostPlanReason as Reason;
    if proposal.schema_version != 1
        || proposal.machine_id != host.machine_id
        || proposal.owner_attested
        || proposal.mutation_authorized
    {
        return Err("HOST_PLAN_SCOPE_OR_AUTHORITY_INVALID");
    }
    let reason = Reason::try_from(proposal.reason).map_err(|_| "HOST_PLAN_REASON_UNRECOGNIZED")?;
    if reason == Reason::Unspecified {
        return Err("HOST_PLAN_REASON_UNSPECIFIED");
    }
    let code = reason
        .as_str_name()
        .strip_prefix("FLEET_HOST_PLAN_REASON_")
        .ok_or("HOST_PLAN_REASON_INVALID")?;
    if proposal.reason_code != code {
        return Err("HOST_PLAN_REASON_CODE_MISMATCH");
    }
    let expected_step = match reason {
        Reason::HostKindInvalid
        | Reason::ExpectedReleaseUnproven
        | Reason::TargetUnsetObserveOnly
        | Reason::TargetRunStateUnproven
        | Reason::TargetModeUnproven
        | Reason::TunSeparatePhysicalGateRequired
        | Reason::TargetModeKindMismatch
        | Reason::NativeReadbackRequired
        | Reason::NativeReadbackInvalidOrWrongKind
        | Reason::NativeReadbackStale
        | Reason::NativeReadbackDegraded
        | Reason::NativeStateUnproven
        | Reason::AbsentInstallWithStoppedTarget
        | Reason::AbsenceOwnerStateConflict
        | Reason::NativeReleaseProofUnproven
        | Reason::StoppedReleaseMismatchRequiresInstallTarget
        | Reason::RuntimeReadinessUnproven => FleetHostPlannedStep::Blocked,
        Reason::VerifiedAbsentInstallProposalOnly => FleetHostPlannedStep::Install,
        Reason::StopTargetOverridesReleaseMismatch => FleetHostPlannedStep::Stop,
        Reason::StoppedMatchesDesiredLocalOnly | Reason::RunningMatchesLocalNotExternal => {
            FleetHostPlannedStep::Noop
        }
        Reason::ReleaseMismatchProposalOnly => FleetHostPlannedStep::ReplaceRelease,
        Reason::StartProposalOnly | Reason::VmDegradedRequiresScopedContainerPreadmission => {
            FleetHostPlannedStep::Start
        }
        Reason::StoppedConfigurationDrift => FleetHostPlannedStep::Configure,
        Reason::Unspecified => return Err("HOST_PLAN_REASON_UNSPECIFIED"),
    };
    if proposal.step != expected_step as i32 {
        return Err("HOST_PLAN_ACTION_REASON_CONFLICT");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_apply_updates_stopped_windows_without_implicitly_starting() {
        let h = host(
            FleetHostKind::Windows,
            FleetHostMode::ProxyOnly,
            FleetHostRunState::Stopped,
        );
        let o = observed(FleetHostKind::Windows, FleetNativeOwnerState::Stopped);
        for action in [
            crate::FleetHostAction::Start,
            crate::FleetHostAction::Stop,
            crate::FleetHostAction::Recover,
        ] {
            assert_eq!(
                propose_signed_host_transition(&h, &o, action, &[2; 32], &[2; 32], 1000).step,
                FleetHostPlannedStep::Blocked as i32
            );
        }
        let p = propose_signed_host_transition(
            &h,
            &o,
            crate::FleetHostAction::Apply,
            &[2; 32],
            &[2; 32],
            1000,
        );
        assert_eq!(p.step, FleetHostPlannedStep::ReplaceRelease as i32);
        validate_host_transition_plan(&p, &h).unwrap();
        let mut bad = o;
        bad.reason_codes.push("UNPROVEN".into());
        assert_eq!(
            propose_signed_host_transition(
                &h,
                &bad,
                crate::FleetHostAction::Apply,
                &[2; 32],
                &[2; 32],
                1000
            )
            .step,
            FleetHostPlannedStep::Blocked as i32
        );
    }
    use crate::{FleetHostTarget, managed_host};

    fn host(kind: FleetHostKind, mode: FleetHostMode, run: FleetHostRunState) -> FleetHost {
        FleetHost {
            machine_id: "host-1".into(),
            kind: kind as i32,
            owner: Some(match kind {
                FleetHostKind::Vm => managed_host::Owner::VmMachineId("host-1".into()),
                _ => managed_host::Owner::WindowsRunnerName("win-1".into()),
            }),
            windows_runner_label: if kind == FleetHostKind::Vm {
                String::new()
            } else {
                "win-1".into()
            },
            vm_containers: Vec::new(),
            desired_spec_path: "infra/production/production.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: run as i32,
                windows_mode: mode as i32,
            }),
            native_receipt_public_key: Vec::new(),
            vm_first_use_credential: None,
            worker_authority_public_key: Vec::new(),
            vm_provider_spec_path: String::new(),
        }
    }
    fn observed(kind: FleetHostKind, state: FleetNativeOwnerState) -> FleetNativeObservation {
        FleetNativeObservation {
            schema_version: 1,
            host_kind: kind as i32,
            observed_at_unix: 1000,
            owner_state: state as i32,
            release_proof: if kind == FleetHostKind::Vm {
                FleetNativeReleaseProof::ApplicationBundle as i32
            } else {
                FleetNativeReleaseProof::ActivationRecord as i32
            },
            observed_release_sha256: vec![1; 32],
            runtime_ready: state == FleetNativeOwnerState::Running,
            runtime_ready_proven: true,
            reason_codes: vec![],
            vm_recovery_resources: None,
            windows_config_sha256: Vec::new(),
        }
    }

    #[test]
    fn host_plan_rejects_forged_reason_step_and_authority() {
        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let proposal = propose_host_transition(&vm, None, &[1; 32], &[2; 32], 1000);
        assert_eq!(
            proposal.reason,
            FleetHostPlanReason::NativeReadbackRequired as i32
        );
        assert_eq!(proposal.reason_code, "NATIVE_READBACK_REQUIRED");
        assert_eq!(validate_host_transition_plan(&proposal, &vm), Ok(()));

        let mut forged = proposal.clone();
        forged.reason_code = "RUNTIME_READINESS_UNPROVEN".into();
        assert_eq!(
            validate_host_transition_plan(&forged, &vm),
            Err("HOST_PLAN_REASON_CODE_MISMATCH")
        );

        let mut forged = proposal.clone();
        forged.step = FleetHostPlannedStep::Install as i32;
        assert_eq!(
            validate_host_transition_plan(&forged, &vm),
            Err("HOST_PLAN_ACTION_REASON_CONFLICT")
        );

        let mut forged = proposal.clone();
        forged.reason = 9876;
        assert_eq!(
            validate_host_transition_plan(&forged, &vm),
            Err("HOST_PLAN_REASON_UNRECOGNIZED")
        );

        let mut forged = proposal.clone();
        forged.mutation_authorized = true;
        assert_eq!(
            validate_host_transition_plan(&forged, &vm),
            Err("HOST_PLAN_SCOPE_OR_AUTHORITY_INVALID")
        );
    }

    #[test]
    fn same_release_network_loss_requires_exact_native_readiness_failure() {
        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let mut live = observed(FleetHostKind::Vm, FleetNativeOwnerState::Running);
        live.runtime_ready = false;
        live.reason_codes = vec!["VM_MANAGED_NETWORK_MISSING".into()];
        let plan = propose_host_transition(&vm, Some(&live), &[1; 32], &[1; 32], 1000);
        assert_eq!(plan.step, FleetHostPlannedStep::Start as i32);
        assert!(!plan.owner_attested && !plan.mutation_authorized);

        live.runtime_ready_proven = false;
        assert_eq!(
            propose_host_transition(&vm, Some(&live), &[1; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
        live.runtime_ready_proven = true;
        live.reason_codes
            .push("VM_MANAGED_NETWORK_UNKNOWN_NO_REPLAY".into());
        assert_eq!(
            propose_host_transition(&vm, Some(&live), &[1; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
        live.reason_codes = vec!["VM_MANAGED_NETWORK_UNKNOWN_NO_REPLAY".into()];
        assert_eq!(
            propose_host_transition(&vm, Some(&live), &[1; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
    }

    #[test]
    fn same_release_known_runtime_failure_proposes_only_scoped_root_repair() {
        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let mut observed = observed(FleetHostKind::Vm, FleetNativeOwnerState::Running);
        observed.runtime_ready = false;
        observed.reason_codes = vec!["WARP_LINE1_CONSUMER_EGRESS_FAILED".into()];
        let proposal = propose_host_transition(&vm, Some(&observed), &[1; 32], &[1; 32], 1000);
        assert_eq!(proposal.step, FleetHostPlannedStep::Start as i32);
        assert!(!proposal.owner_attested);
        assert!(!proposal.mutation_authorized);
        observed.reason_codes = vec!["DOCKER_UNAVAILABLE".into()];
        let rejected = propose_host_transition(&vm, Some(&observed), &[1; 32], &[1; 32], 1000);
        assert_eq!(rejected.step, FleetHostPlannedStep::Blocked as i32);
    }

    #[test]
    fn proven_absent_vm_proposes_fresh_install_but_never_authorizes_it() {
        use crate::host_lifecycle::build_native_observation;
        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let absent = build_native_observation(
            FleetHostKind::Vm,
            FleetNativeOwnerState::Stopped,
            FleetNativeReleaseProof::VerifiedAbsent,
            None,
            Some(false),
            1000,
            &[],
        )
        .unwrap();
        let candidate = propose_host_transition(&vm, Some(&absent), &[1; 32], &[2; 32], 1000);
        assert_eq!(candidate.step, FleetHostPlannedStep::Install as i32);
        assert_eq!(
            candidate.reason_code,
            "VERIFIED_ABSENT_INSTALL_PROPOSAL_ONLY"
        );
        assert!(!candidate.owner_attested && !candidate.mutation_authorized);
        let stopped = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Stopped,
        );
        let stopped_plan =
            propose_host_transition(&stopped, Some(&absent), &[1; 32], &[2; 32], 1000);
        assert_eq!(stopped_plan.step, FleetHostPlannedStep::Blocked as i32);
        assert_eq!(
            stopped_plan.reason_code,
            "ABSENT_INSTALL_WITH_STOPPED_TARGET"
        );
        // A tampered observation cannot turn an existing/running installation
        // or an invented digest into VERIFIED_ABSENT.
        let mut running = absent.clone();
        running.owner_state = FleetNativeOwnerState::Running as i32;
        assert_eq!(
            propose_host_transition(&vm, Some(&running), &[1; 32], &[2; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32,
        );
        let mut forged_digest = absent.clone();
        forged_digest.observed_release_sha256 = vec![1; 32];
        assert_eq!(
            propose_host_transition(&vm, Some(&forged_digest), &[1; 32], &[2; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32,
        );

        let unproven = build_native_observation(
            FleetHostKind::Vm,
            FleetNativeOwnerState::Stopped,
            FleetNativeReleaseProof::Unproven,
            None,
            Some(false),
            1000,
            &["VM_BUNDLE_NOT_OBSERVED"],
        )
        .unwrap();
        let blocked = propose_host_transition(&vm, Some(&unproven), &[1; 32], &[2; 32], 1000);
        assert_eq!(blocked.step, FleetHostPlannedStep::Blocked as i32);
        assert_ne!(blocked.reason_code, "VERIFIED_ABSENT_INSTALL_PROPOSAL_ONLY");
    }

    #[test]
    fn native_stopped_without_runtime_probe_is_noop_not_blocked() {
        use crate::host_lifecycle::build_native_observation;
        // Exactly the real Windows SCM+activation evidence, where the
        // diagnostic intentionally cannot prove external runtime readiness.
        let win = host(
            FleetHostKind::Windows,
            FleetHostMode::ProxyOnly,
            FleetHostRunState::Stopped,
        );
        let win_observed = build_native_observation(
            FleetHostKind::Windows,
            FleetNativeOwnerState::Stopped,
            FleetNativeReleaseProof::ActivationRecord,
            Some(&"01".repeat(32)),
            None,
            1000,
            &[],
        )
        .unwrap();
        let proposal = propose_host_transition(&win, Some(&win_observed), &[1; 32], &[9; 32], 1000);
        assert_eq!(proposal.step, FleetHostPlannedStep::Noop as i32);
        assert_eq!(proposal.reason_code, "STOPPED_MATCHES_DESIRED_LOCAL_ONLY");
        assert!(!proposal.owner_attested && !proposal.mutation_authorized);

        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Stopped,
        );
        let vm_observed = build_native_observation(
            FleetHostKind::Vm,
            FleetNativeOwnerState::Stopped,
            FleetNativeReleaseProof::ApplicationBundle,
            Some(&"02".repeat(32)),
            Some(false),
            1000,
            &[],
        )
        .unwrap();
        let proposal = propose_host_transition(&vm, Some(&vm_observed), &[1; 32], &[2; 32], 1000);
        assert_eq!(proposal.step, FleetHostPlannedStep::Noop as i32);
        assert!(!proposal.owner_attested && !proposal.mutation_authorized);
    }

    #[test]
    fn missing_readiness_never_claims_running_healthy_or_hides_error() {
        use crate::host_lifecycle::build_native_observation;
        let win = host(
            FleetHostKind::Windows,
            FleetHostMode::ProxyOnly,
            FleetHostRunState::Running,
        );
        let mut observed = build_native_observation(
            FleetHostKind::Windows,
            FleetNativeOwnerState::Running,
            FleetNativeReleaseProof::ActivationRecord,
            Some(&"01".repeat(32)),
            None,
            1000,
            &[],
        )
        .unwrap();
        assert_eq!(
            propose_host_transition(&win, Some(&observed), &[1; 32], &[9; 32], 1000).reason_code,
            "RUNTIME_READINESS_UNPROVEN",
        );
        observed
            .reason_codes
            .push("WINDOWS_SCM_BINARY_MISMATCH".into());
        assert_eq!(
            propose_host_transition(&win, Some(&observed), &[1; 32], &[9; 32], 1000).reason_code,
            "NATIVE_READBACK_DEGRADED",
        );
        // A stopped target still requires valid SCM/release evidence;
        // ignoring missing readiness is not ignoring actual errors.
        let stopped = host(
            FleetHostKind::Windows,
            FleetHostMode::ProxyOnly,
            FleetHostRunState::Stopped,
        );
        observed.owner_state = FleetNativeOwnerState::Stopped as i32;
        assert_eq!(
            propose_host_transition(&stopped, Some(&observed), &[1; 32], &[9; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32,
        );
    }

    #[test]
    fn correct_readback_proposes_but_never_authorizes() {
        let win = host(
            FleetHostKind::Windows,
            FleetHostMode::ProxyOnly,
            FleetHostRunState::Stopped,
        );
        let mut o = observed(FleetHostKind::Windows, FleetNativeOwnerState::Running);
        let p = propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1000);
        assert_eq!(p.step, FleetHostPlannedStep::Stop as i32);
        assert!(!p.mutation_authorized && !p.owner_attested);
        o.owner_state = FleetNativeOwnerState::Stopped as i32;
        let p = propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1000);
        assert_eq!(p.step, FleetHostPlannedStep::Noop as i32);
        o.observed_release_sha256 = vec![2; 32];
        let p = propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1000);
        assert_eq!(p.step, FleetHostPlannedStep::Blocked as i32);
        assert_eq!(
            p.reason_code,
            "STOPPED_RELEASE_MISMATCH_REQUIRES_INSTALL_TARGET"
        );
        assert!(!p.mutation_authorized);
        o.owner_state = FleetNativeOwnerState::Running as i32;
        let p = propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1000);
        assert_eq!(p.step, FleetHostPlannedStep::Stop as i32);
        assert_eq!(p.reason_code, "STOP_TARGET_OVERRIDES_RELEASE_MISMATCH");
    }
    #[test]
    fn no_implicit_vm_start_and_no_tun_without_gate() {
        let mut vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let o = observed(FleetHostKind::Vm, FleetNativeOwnerState::Stopped);
        assert_eq!(
            propose_host_transition(&vm, Some(&o), &[9; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Start as i32
        );
        // Unlike Windows, the VM bundle must compare with bundle digest, not ReleaseSet.
        assert_eq!(
            propose_host_transition(&vm, Some(&o), &[1; 32], &[9; 32], 1000).step,
            FleetHostPlannedStep::ReplaceRelease as i32
        );
        vm.target = None;
        assert_eq!(
            propose_host_transition(&vm, Some(&o), &[1; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
        let win = host(
            FleetHostKind::Windows,
            FleetHostMode::ManagedTun,
            FleetHostRunState::Running,
        );
        assert_eq!(
            propose_host_transition(&win, None, &[1; 32], &[], 1000).reason_code,
            "TUN_SEPARATE_PHYSICAL_GATE_REQUIRED"
        );
    }
    #[test]
    fn stopped_managed_tun_target_permits_safe_stop_but_never_implicit_start() {
        let host = host(
            FleetHostKind::Windows,
            FleetHostMode::ManagedTun,
            FleetHostRunState::Stopped,
        );
        let running = observed(FleetHostKind::Windows, FleetNativeOwnerState::Running);
        let stop = propose_host_transition(&host, Some(&running), &[1; 32], &[], 1000);
        assert_eq!(stop.step, FleetHostPlannedStep::Stop as i32);
        validate_host_transition_plan(&stop, &host).unwrap();

        let stopped = observed(FleetHostKind::Windows, FleetNativeOwnerState::Stopped);
        let noop = propose_host_transition(&host, Some(&stopped), &[1; 32], &[], 1000);
        assert_eq!(noop.step, FleetHostPlannedStep::Noop as i32);
        validate_host_transition_plan(&noop, &host).unwrap();

        let mut starting = host.clone();
        starting.target.as_mut().unwrap().run_state = FleetHostRunState::Running as i32;
        let blocked = propose_host_transition(&starting, Some(&stopped), &[1; 32], &[], 1000);
        assert_eq!(blocked.reason_code, "TUN_SEPARATE_PHYSICAL_GATE_REQUIRED");
    }

    #[test]
    fn vm_bundle_drift_with_addressed_warp_consumer_can_propose_replace_only() {
        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let mut observed = observed(FleetHostKind::Vm, FleetNativeOwnerState::Running);
        observed.observed_release_sha256 = vec![1; 32];
        observed.runtime_ready = false;
        observed.runtime_ready_proven = true;
        observed.reason_codes = vec!["WARP_LINE1_CONSUMER_EGRESS_FAILED".into()];
        let proposal = propose_host_transition(&vm, Some(&observed), &[9; 32], &[2; 32], 1000);
        assert_eq!(proposal.step, FleetHostPlannedStep::ReplaceRelease as i32);
        assert_eq!(proposal.reason_code, "RELEASE_MISMATCH_PROPOSAL_ONLY");
        assert!(!proposal.owner_attested && !proposal.mutation_authorized);

        // Generic network failure, missing consumers/ports, unknown
        // resources and failed trust must never trigger another apply.
        // Same-release known datapath defect is now an explicitly scoped
        // START proposal only, not authorization or a replay.
        for fault in [
            "WARP_EGRESS_FAILED",
            "WARP_CONSUMERS_ABSENT",
            "WARP_CLIENT_CONNECTION_UNPROVEN",
            "TCP_PORTS_MISSING",
            "UDP_PORTS_MISSING",
            "CONTAINER_NOT_RUNNING",
            "EXACT_IMAGE_OR_CONTAINER_UNREADY",
            "DOCKER_UNAVAILABLE",
            "VM_DIAGNOSTIC_TRUNCATED",
            "OTHER_UNPROVEN",
        ] {
            observed.reason_codes = vec!["WARP_LINE1_CONSUMER_EGRESS_FAILED".into(), fault.into()];
            assert_eq!(
                propose_host_transition(&vm, Some(&observed), &[9; 32], &[2; 32], 1000).step,
                FleetHostPlannedStep::Blocked as i32
            );
        }
        observed.reason_codes = vec!["WARP_LINE2_CONSUMER_EGRESS_FAILED".into()];
        assert_eq!(
            propose_host_transition(&vm, Some(&observed), &[9; 32], &[2; 32], 1000).step,
            FleetHostPlannedStep::ReplaceRelease as i32
        );
        assert_eq!(
            propose_host_transition(&vm, Some(&observed), &[9; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Start as i32
        );
        observed.owner_state = FleetNativeOwnerState::Unproven as i32;
        assert_eq!(
            propose_host_transition(&vm, Some(&observed), &[9; 32], &[2; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
        observed.owner_state = FleetNativeOwnerState::Running as i32;
        observed.runtime_ready_proven = false;
        assert_eq!(
            propose_host_transition(&vm, Some(&observed), &[9; 32], &[2; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
        observed.runtime_ready_proven = true;
        observed.observed_release_sha256 = vec![0; 32];
        assert_eq!(
            propose_host_transition(&vm, Some(&observed), &[9; 32], &[2; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
    }

    #[test]
    fn degraded_vm_start_is_only_a_proposal_and_requires_scoped_owner_proof() {
        let vm = host(
            FleetHostKind::Vm,
            FleetHostMode::Unspecified,
            FleetHostRunState::Running,
        );
        let mut observed = observed(FleetHostKind::Vm, FleetNativeOwnerState::Running);
        observed.runtime_ready = false;
        let proposal = propose_host_transition(&vm, Some(&observed), &[1; 32], &[1; 32], 1000);
        assert_eq!(proposal.step, FleetHostPlannedStep::Start as i32);
        assert_eq!(
            proposal.reason_code,
            "VM_DEGRADED_REQUIRES_SCOPED_CONTAINER_PREADMISSION"
        );
        assert!(!proposal.owner_attested && !proposal.mutation_authorized);
        observed.runtime_ready_proven = false;
        assert_eq!(
            propose_host_transition(&vm, Some(&observed), &[1; 32], &[1; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
    }
    #[test]
    fn forged_or_stale_readback_cannot_become_pass() {
        let win = host(
            FleetHostKind::Windows,
            FleetHostMode::ProxyOnly,
            FleetHostRunState::Running,
        );
        let mut o = observed(FleetHostKind::Windows, FleetNativeOwnerState::Running);
        o.runtime_ready = true;
        o.runtime_ready_proven = false;
        assert_eq!(
            propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1000).step,
            FleetHostPlannedStep::Blocked as i32
        );
        o.runtime_ready_proven = true;
        assert_eq!(
            propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1400).reason_code,
            "NATIVE_READBACK_STALE"
        );
        o.observed_at_unix = 1400;
        o.host_kind = FleetHostKind::Vm as i32;
        assert_eq!(
            propose_host_transition(&win, Some(&o), &[1; 32], &[3; 32], 1400).step,
            FleetHostPlannedStep::Blocked as i32
        );
    }
}
