//! One typed, bounded VM resource diagnostic. Data from the runner is
//! STRUCTURAL EVIDENCE only, not authenticated native owner attestation.
use crate::{FleetHost, FleetHostKind, FleetVmResourceReadback, FleetVmResourceReport};
use prost::Message;

pub const MAX_VM_RESOURCE_REPORT_BYTES: usize = 32768;

pub fn validate_vm_resource_report(
    report: &FleetVmResourceReport,
    host: &FleetHost,
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || report.schema_version != 1
        || report.remote_attested
        || report.machine_id != host.machine_id
        || report.observed_at_unix == 0
        || host.vm_containers.is_empty()
        || report.resources.len() != host.vm_containers.len()
        || report.encode_to_vec().len() > MAX_VM_RESOURCE_REPORT_BYTES
    {
        return Err("VM_RESOURCE_REPORT_SCOPE_INVALID");
    }
    for (row, expected) in report.resources.iter().zip(host.vm_containers.iter()) {
        if row.resource.as_ref() != Some(expected)
            || row.image.len() > 256
            || !row.image.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b':' | b'.' | b'_' | b'-' | b'@')
            })
            || row.health.len() > 32
            || !row
                .health
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || (row.present
                && !row.ownership_proven
                && (!row.container_id.is_empty()
                    || !row.image.is_empty()
                    || !row.health.is_empty()
                    || row.running
                    || row.running_proven
                    || row.restart_count_proven))
            || (!row.present && (row.ownership_proven || row.running_proven || row.running))
            || (row.running && !row.running_proven)
            || (row.ownership_proven && !valid_container_id(&row.container_id))
            || (!row.ownership_proven && !row.container_id.is_empty())
            || (row.restart_count != 0 && !row.restart_count_proven)
            || !reason_consistent(row)
        {
            return Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID");
        }
    }
    Ok(())
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn reason_consistent(row: &FleetVmResourceReadback) -> bool {
    match row.reason_code.as_str() {
        "CONTAINER_ABSENT" => !row.present,
        "DOCKER_UNAVAILABLE" | "INSPECT_UNAVAILABLE" => !row.present,
        "FOREIGN_OWNER" => row.present && !row.ownership_proven,
        "STATE_UNPROVEN" => row.present && row.ownership_proven && !row.running_proven,
        "HEALTHY" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "HEALTHY"
        }
        "HEALTH_STARTING" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "STARTING"
        }
        "HEALTH_UNHEALTHY" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "UNHEALTHY"
        }
        "RUNNING_NO_HEALTHCHECK" | "HEALTH_UNPROVEN" => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health.is_empty()
        }
        "STOPPED" => row.present && row.ownership_proven && row.running_proven && !row.running,
        _ => false,
    }
}

pub fn decode_vm_resource_report(
    bytes: &[u8],
    host: &FleetHost,
) -> Result<FleetVmResourceReport, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_VM_RESOURCE_REPORT_BYTES {
        return Err("VM_RESOURCE_REPORT_SIZE_INVALID");
    }
    let report =
        FleetVmResourceReport::decode(bytes).map_err(|_| "VM_RESOURCE_REPORT_PROTO_INVALID")?;
    if report.encode_to_vec() != bytes {
        return Err("VM_RESOURCE_REPORT_NONCANONICAL");
    }
    validate_vm_resource_report(&report, host)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FleetHostKind, FleetVmContainer};
    fn fixture() -> (FleetHost, FleetVmResourceReport) {
        let resource = FleetVmContainer {
            container_name: "my-proxy".into(),
            compose_project: "my-app".into(),
            compose_service: "proxy".into(),
        };
        let host = FleetHost {
            machine_id: "vm-a".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: vec![resource.clone()],
            ..Default::default()
        };
        let report = FleetVmResourceReport {
            schema_version: 1,
            machine_id: "vm-a".into(),
            observed_at_unix: 100,
            resources: vec![FleetVmResourceReadback {
                resource: Some(resource),
                present: true,
                ownership_proven: true,
                running: true,
                running_proven: true,
                container_id: "a".repeat(64),
                reason_code: "HEALTHY".into(),
                health: "HEALTHY".into(),
                ..Default::default()
            }],
            remote_attested: false,
        };
        (host, report)
    }
    #[test]
    fn resource_report_fails_closed_on_forgery_and_foreign_owner() {
        let (host, mut report) = fixture();
        let bytes = report.encode_to_vec();
        assert_eq!(decode_vm_resource_report(&bytes, &host).unwrap(), report);
        report.remote_attested = true;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.remote_attested = false;
        report.resources[0]
            .resource
            .as_mut()
            .unwrap()
            .compose_project = "foreign".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].resource = host.vm_containers.first().cloned();
        report.resources[0].ownership_proven = false;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].container_id.clear();
        report.resources[0].health.clear();
        report.resources[0].running_proven = false;
        report.resources[0].running = false;
        report.resources[0].reason_code = "FOREIGN_OWNER".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "HEALTHY".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report = fixture().1;
        report.resources[0].reason_code = "HEALTH_STARTING".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].health = "STARTING".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].health.clear();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        let mut invalid = bytes;
        invalid.extend_from_slice(&[0x08, 0x01]); // noncanonical duplicate field
        assert!(decode_vm_resource_report(&invalid, &host).is_err());
    }
}

/*
 * One deterministic, strictly non-authorizing proposal per VM container.
 * We deliberately do NOT treat Docker health as proof of matching config,
 * image digest, network, DNS or TLS. All config/release mutations remain
 * blocked until native owner-side bundle/resource comparison is wired.
 */
pub fn propose_vm_resource_transitions(
    host: &FleetHost,
    report: &FleetVmResourceReport,
) -> Result<crate::FleetVmResourceTransitionPlan, &'static str> {
    use crate::{
        FleetHostPlannedStep as Step, FleetHostRunState, FleetVmResourceTransition,
        FleetVmResourceTransitionPlan,
    };
    validate_vm_resource_report(report, host)?;
    let desired = host
        .target
        .as_ref()
        .and_then(|target| FleetHostRunState::try_from(target.run_state).ok());
    let mut resources = Vec::with_capacity(report.resources.len());
    for row in &report.resources {
        let (step, reason) = match desired {
            None | Some(FleetHostRunState::Unspecified) => {
                (Step::Blocked, "TARGET_UNSET_OBSERVE_ONLY")
            }
            Some(FleetHostRunState::Stopped)
                if !row.present && row.reason_code == "CONTAINER_ABSENT" =>
            {
                (Step::Noop, "ABSENT_AS_DESIRED")
            }
            Some(FleetHostRunState::Running)
                if !row.present && row.reason_code == "CONTAINER_ABSENT" =>
            {
                (Step::Install, "CONTAINER_ABSENT_INSTALL_REQUIRED")
            }
            Some(_) if !row.present || !row.ownership_proven || !row.running_proven => {
                (Step::Blocked, "RESOURCE_IDENTITY_OR_STATE_UNPROVEN")
            }
            Some(FleetHostRunState::Stopped) if row.running => {
                (Step::Stop, "CONTAINER_RUNNING_BUT_TARGET_STOPPED")
            }
            Some(FleetHostRunState::Stopped) => (Step::Noop, "STOPPED_AS_DESIRED"),
            Some(FleetHostRunState::Running) if !row.running => {
                (Step::Start, "CONTAINER_STOPPED_BUT_TARGET_RUNNING")
            }
            Some(FleetHostRunState::Running)
                if matches!(
                    row.reason_code.as_str(),
                    "HEALTHY" | "RUNNING_NO_HEALTHCHECK"
                ) =>
            {
                // An already-running container requires no START. Docker
                // health is NOT proof of configuration or network readiness.
                (Step::Noop, "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN")
            }
            Some(FleetHostRunState::Running) => {
                (Step::Blocked, "RUNTIME_HEALTH_OR_CONFIG_UNPROVEN")
            }
        };
        resources.push(FleetVmResourceTransition {
            resource: row.resource.clone(),
            step: step as i32,
            reason_code: reason.to_owned(),
        });
    }
    Ok(FleetVmResourceTransitionPlan {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        owner_attested: false,
        mutation_authorized: false,
    })
}

/// A runtime NOOP is not evidence of configuration convergence. Keep that
/// distinction visible in the *same* operator diagnostic and typed planner.
pub fn vm_resource_requires_attention(transition: &crate::FleetVmResourceTransition) -> bool {
    transition.step != crate::FleetHostPlannedStep::Noop as i32
        || transition.reason_code == "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
}

#[cfg(test)]
mod resource_planning_tests {
    use super::*;
    use crate::{
        FleetHostMode, FleetHostPlannedStep, FleetHostRunState, FleetHostTarget, FleetVmContainer,
        FleetVmResourceReadback,
    };

    fn fixture() -> (FleetHost, FleetVmResourceReport) {
        let resource = FleetVmContainer {
            container_name: "vultr-line2-proxy".into(),
            compose_project: "vultr-edge".into(),
            compose_service: "line2-proxy".into(),
        };
        let host = FleetHost {
            machine_id: "vm-test".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: vec![resource.clone()],
            target: Some(FleetHostTarget {
                run_state: FleetHostRunState::Running as i32,
                windows_mode: FleetHostMode::Unspecified as i32,
            }),
            ..Default::default()
        };
        let report = FleetVmResourceReport {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            observed_at_unix: 100,
            resources: vec![FleetVmResourceReadback {
                resource: Some(resource),
                present: true,
                ownership_proven: true,
                running: true,
                running_proven: true,
                container_id: "a".repeat(64),
                reason_code: "HEALTHY".into(),
                health: "HEALTHY".into(),
                ..Default::default()
            }],
            remote_attested: false,
        };
        (host, report)
    }

    fn step(host: &FleetHost, report: &FleetVmResourceReport) -> FleetHostPlannedStep {
        let result = propose_vm_resource_transitions(host, report).unwrap();
        assert!(!result.owner_attested && !result.mutation_authorized);
        FleetHostPlannedStep::try_from(result.resources[0].step).unwrap()
    }

    #[test]
    fn independent_runtime_states_never_fake_config_or_owner_authority() {
        let (mut host, mut report) = fixture();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        assert_eq!(
            propose_vm_resource_transitions(&host, &report)
                .unwrap()
                .resources[0]
                .reason_code,
            "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
        );
        report.resources[0].health.clear();
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        assert_eq!(
            propose_vm_resource_transitions(&host, &report)
                .unwrap()
                .resources[0]
                .reason_code,
            "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
        );

        report.resources[0].running = false;
        report.resources[0].reason_code = "STOPPED".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Start);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        report.resources[0].running = true;
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Stop);

        host.target = None;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Blocked);
        host.target = Some(FleetHostTarget {
            run_state: FleetHostRunState::Running as i32,
            windows_mode: FleetHostMode::Unspecified as i32,
        });
        report.resources[0].ownership_proven = false;
        report.resources[0].container_id.clear();
        report.resources[0].running = false;
        report.resources[0].running_proven = false;
        report.resources[0].reason_code = "FOREIGN_OWNER".into();
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Blocked);
    }

    #[test]
    fn running_noop_never_conceals_unproven_config() {
        let (host, report) = fixture();
        let plan = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(plan.resources[0].step, FleetHostPlannedStep::Noop as i32);
        assert!(vm_resource_requires_attention(&plan.resources[0]));
        let mut stopped = host;
        stopped.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        let mut report = report;
        report.resources[0].running = false;
        report.resources[0].health.clear();
        report.resources[0].reason_code = "STOPPED".into();
        let plan = propose_vm_resource_transitions(&stopped, &report).unwrap();
        assert!(!vm_resource_requires_attention(&plan.resources[0]));
    }

    #[test]
    fn absence_and_untrusted_reports_are_not_recovery_authority() {
        let (mut host, mut report) = fixture();
        report.resources[0] = FleetVmResourceReadback {
            resource: host.vm_containers.first().cloned(),
            reason_code: "CONTAINER_ABSENT".into(),
            ..Default::default()
        };
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Install);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        report.remote_attested = true;
        assert!(propose_vm_resource_transitions(&host, &report).is_err());
        report.remote_attested = false;
        report.machine_id = "foreign-vm".into();
        assert!(propose_vm_resource_transitions(&host, &report).is_err());
    }
}
