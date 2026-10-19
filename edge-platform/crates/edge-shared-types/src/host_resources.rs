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
            || row.health.len() > 32
            || !row.health.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || (row.present && !row.ownership_proven && (!row.container_id.is_empty()
                || !row.image.is_empty() || !row.health.is_empty() || row.running
                || row.running_proven || row.restart_count_proven))
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
        "RUNNING" | "HEALTH_DEGRADED" =>
            row.present && row.ownership_proven && row.running_proven && row.running,
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
    let report = FleetVmResourceReport::decode(bytes)
        .map_err(|_| "VM_RESOURCE_REPORT_PROTO_INVALID")?;
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
                reason_code: "RUNNING".into(),
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
        report.resources[0].resource.as_mut().unwrap().compose_project = "foreign".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].resource = host.vm_containers.first().cloned();
        report.resources[0].ownership_proven = false;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].container_id.clear();
        report.resources[0].running_proven = false;
        report.resources[0].running = false;
        report.resources[0].reason_code = "FOREIGN_OWNER".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "RUNNING".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        let mut invalid = bytes;
        invalid.extend_from_slice(&[0x08, 0x01]); // noncanonical duplicate field
        assert!(decode_vm_resource_report(&invalid, &host).is_err());
    }
}
