//! One pure typed desired -> observed transition planner for Windows and VM.
//!
//! A plan is NOT an executable authorization. The caller can copy/forge
//! observation protobuf bytes. Native owner identity, Worker authorization,
//! durable journal admission and physical readback are separate requirements.
use crate::{
    FleetHost, FleetHostKind, FleetHostMode, FleetHostPlannedStep, FleetHostRunState,
    FleetHostTransitionPlan, FleetNativeObservation, FleetNativeOwnerState,
    FleetNativeReleaseProof, host_lifecycle::validate_native_observation,
};

fn plan(
    host: &FleetHost,
    step: FleetHostPlannedStep,
    reason: &str,
    expected: &[u8],
    observed: &[u8],
) -> FleetHostTransitionPlan {
    FleetHostTransitionPlan {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        step: step as i32,
        reason_code: reason.to_owned(),
        expected_release_digest: expected.to_vec(),
        observed_release_digest: observed.to_vec(),
        owner_attested: false,
        mutation_authorized: false,
    }
}

/// Compute a deterministic and strictly non-authorizing proposal. Windows
/// compares the activation ReleaseSet digest; VM compares the exact immutable
/// ApplyBundleRequest digest, NEVER the whole ReleaseSet digest.
pub fn propose_host_transition(
    host: &FleetHost,
    observed: Option<&FleetNativeObservation>,
    expected_release_set_sha256: &[u8],
    expected_vm_bundle_sha256: &[u8],
    now_unix: u64,
) -> FleetHostTransitionPlan {
    use FleetHostPlannedStep::{Blocked, Noop, ReplaceRelease, Start, Stop};
    let kind = match FleetHostKind::try_from(host.kind) {
        Ok(FleetHostKind::Windows) => FleetHostKind::Windows,
        Ok(FleetHostKind::Vm) => FleetHostKind::Vm,
        _ => return plan(host, Blocked, "HOST_KIND_INVALID", &[], &[]),
    };
    let expected = if kind == FleetHostKind::Windows {
        expected_release_set_sha256
    } else {
        expected_vm_bundle_sha256
    };
    if expected.len() != 32 || !expected.iter().any(|b| *b != 0) {
        return plan(host, Blocked, "EXPECTED_RELEASE_UNPROVEN", expected, &[]);
    }
    let target = match &host.target {
        Some(target) => target,
        None => return plan(host, Blocked, "TARGET_UNSET_OBSERVE_ONLY", expected, &[]),
    };
    let desired_run = match FleetHostRunState::try_from(target.run_state) {
        Ok(FleetHostRunState::Running) => FleetHostRunState::Running,
        Ok(FleetHostRunState::Stopped) => FleetHostRunState::Stopped,
        _ => return plan(host, Blocked, "TARGET_RUN_STATE_UNPROVEN", expected, &[]),
    };
    let desired_mode = match FleetHostMode::try_from(target.windows_mode) {
        Ok(mode) => mode,
        _ => return plan(host, Blocked, "TARGET_MODE_UNPROVEN", expected, &[]),
    };
    if kind == FleetHostKind::Windows && desired_mode == FleetHostMode::ManagedTun {
        return plan(
            host,
            Blocked,
            "TUN_SEPARATE_PHYSICAL_GATE_REQUIRED",
            expected,
            &[],
        );
    }
    if kind == FleetHostKind::Windows && desired_mode != FleetHostMode::ProxyOnly
        || kind == FleetHostKind::Vm && desired_mode != FleetHostMode::Unspecified
    {
        return plan(host, Blocked, "TARGET_MODE_KIND_MISMATCH", expected, &[]);
    }
    let observed = match observed {
        Some(observed) => observed,
        None => return plan(host, Blocked, "NATIVE_READBACK_REQUIRED", expected, &[]),
    };
    let actual = observed.observed_release_sha256.as_slice();
    if validate_native_observation(observed).is_err() || observed.host_kind != host.kind {
        return plan(
            host,
            Blocked,
            "NATIVE_READBACK_INVALID_OR_WRONG_KIND",
            expected,
            actual,
        );
    }
    if observed.observed_at_unix > now_unix.saturating_add(60)
        || now_unix.saturating_sub(observed.observed_at_unix) > 300
    {
        return plan(host, Blocked, "NATIVE_READBACK_STALE", expected, actual);
    }
    if !observed.reason_codes.is_empty() {
        return plan(host, Blocked, "NATIVE_READBACK_DEGRADED", expected, actual);
    }
    let state = match FleetNativeOwnerState::try_from(observed.owner_state) {
        Ok(value) => value,
        Err(_) => return plan(host, Blocked, "NATIVE_STATE_UNPROVEN", expected, actual),
    };
    if matches!(
        state,
        FleetNativeOwnerState::Unproven | FleetNativeOwnerState::Transitioning
    ) {
        return plan(host, Blocked, "NATIVE_STATE_UNPROVEN", expected, actual);
    }
    let proof = FleetNativeReleaseProof::try_from(observed.release_proof);
    let expected_proof = if kind == FleetHostKind::Windows {
        FleetNativeReleaseProof::ActivationRecord
    } else {
        FleetNativeReleaseProof::ApplicationBundle
    };
    if proof != Ok(expected_proof) {
        return plan(
            host,
            Blocked,
            "NATIVE_RELEASE_PROOF_UNPROVEN",
            expected,
            actual,
        );
    }
    if actual != expected {
        return plan(
            host,
            ReplaceRelease,
            "RELEASE_MISMATCH_PROPOSAL_ONLY",
            expected,
            actual,
        );
    }
    match (desired_run, state) {
        (FleetHostRunState::Stopped, FleetNativeOwnerState::Running) => {
            plan(host, Stop, "STOP_PROPOSAL_ONLY", expected, actual)
        }
        (FleetHostRunState::Running, FleetNativeOwnerState::Stopped) => {
            plan(host, Start, "START_PROPOSAL_ONLY", expected, actual)
        }
        (FleetHostRunState::Stopped, FleetNativeOwnerState::Stopped) => plan(
            host,
            Noop,
            "STOPPED_MATCHES_DESIRED_LOCAL_ONLY",
            expected,
            actual,
        ),
        (FleetHostRunState::Running, FleetNativeOwnerState::Running)
            if observed.runtime_ready_proven && observed.runtime_ready =>
        {
            plan(
                host,
                Noop,
                "RUNNING_MATCHES_LOCAL_NOT_EXTERNAL",
                expected,
                actual,
            )
        }
        _ => plan(
            host,
            Blocked,
            "RUNTIME_READINESS_UNPROVEN",
            expected,
            actual,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            desired_spec_path: "infra/production/production.textproto".into(),
            target: Some(FleetHostTarget {
                run_state: run as i32,
                windows_mode: mode as i32,
            }),
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
        }
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
        assert_eq!(p.step, FleetHostPlannedStep::ReplaceRelease as i32);
        assert!(!p.mutation_authorized);
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
