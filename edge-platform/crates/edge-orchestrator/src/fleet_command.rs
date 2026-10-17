use crate::cli::FleetCommand;
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::{FleetHostKind, decode_fleet_desired_state, fleet_host};
use ring::digest::{SHA256, digest};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_INVENTORY_BYTES: u64 = 65_536;

/// Read a protobuf rendered from the canonical Git textproto at the exact
/// checked-out revision. It is NOT embedded in the executable: enrolling
/// another host changes the inventory but never the runtime binary.
pub(crate) fn run(
    command: FleetCommand,
    release: &OrchestrationContext,
    inventory_path: &Path,
    expected_sha256: &str,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    File::open(inventory_path)
        .map_err(|_| "fleet inventory file unavailable".to_owned())?
        .take(MAX_INVENTORY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "fleet inventory unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err("fleet inventory exceeds bounded protobuf size".to_owned());
    }
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
    {
        return Err("fleet Git inventory SHA-256 must be exact lowercase hex".to_owned());
    }
    let digest = digest(&SHA256, &bytes);
    let inventory_sha = digest
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
    if inventory_sha != expected_sha256 {
        return Err("fleet protobuf differs from protected Git inventory SHA-256".to_owned());
    }
    let desired = decode_fleet_desired_state(&bytes)?;
    match command {
        FleetCommand::Inventory => {
            println!("fleet_schema=1");
            println!("fleet_host_count={}", desired.hosts.len());
            println!("fleet_inventory_sha256={inventory_sha}");
            println!(
                "release_set_sha256={}",
                release.release().release_set_sha256
            );
            for host in &desired.hosts {
                println!("fleet_machine_id={}", host.machine_id);
            }
            println!("fleet_host_reachability=UNPROVEN");
            println!("fleet_host_runtime=UNPROVEN");
            println!("fleet_mutations=0");
            Ok(())
        }
        FleetCommand::Inspect { machine_id } => {
            let host = desired
                .hosts
                .iter()
                .find(|host| host.machine_id == machine_id)
                .ok_or_else(|| {
                    "fleet machine not registered in protected Git desired state".to_owned()
                })?;
            let kind = FleetHostKind::try_from(host.kind)
                .map_err(|_| "fleet host kind invalid".to_owned())?;
            let owner = match host.owner.as_ref() {
                Some(fleet_host::Owner::WindowsRunnerName(name)) => name,
                Some(fleet_host::Owner::VmMachineId(name)) => name,
                None => return Err("fleet owner missing".to_owned()),
            };
            println!("fleet_machine_id={machine_id}");
            println!(
                "fleet_host_kind={}",
                match kind {
                    FleetHostKind::Windows => "WINDOWS",
                    FleetHostKind::Vm => "VM",
                    FleetHostKind::Unspecified => {
                        return Err("fleet host kind unspecified".to_owned());
                    }
                }
            );
            println!("fleet_owner_selector={owner}");
            // GitHub runner selectors are derived only from the validated
            // exact Git inventory. They never grant privilege by themselves:
            // the selected host must still attest its installed native owner.
            let label_json = runner_labels(kind, owner)?;
            println!("fleet_runner_labels_json={label_json}");
            println!("fleet_inventory_sha256={inventory_sha}");
            println!(
                "release_set_sha256={}",
                release.release().release_set_sha256
            );
            println!("fleet_runtime_observation=UNPROVEN");
            println!("fleet_owner_reachability=UNPROVEN");
            println!("fleet_mutations=0");
            Ok(())
        }
    }
}

/// A single Rust-owned mapping from typed host kind to GitHub's existing
/// self-hosted owner labels; no workflow-specific second inventory or parser.
fn runner_labels(kind: FleetHostKind, owner: &str) -> Result<String, String> {
    let labels: Vec<&str> = match kind {
        FleetHostKind::Windows => vec!["self-hosted", "Windows", "X64", owner],
        FleetHostKind::Vm => {
            vec!["self-hosted", "Linux", "X64", "sing-box-production-vm", owner]
        }
        FleetHostKind::Unspecified => return Err("fleet host kind unspecified".to_owned()),
    };
    serde_json::to_string(&labels)
        .map_err(|_| "fleet runner selection encoding failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_host_kind_selects_only_existing_native_owners() {
        assert_eq!(
            runner_labels(FleetHostKind::Windows, "sing-box-windows-lab").unwrap(),
            r#"["self-hosted","Windows","X64","sing-box-windows-lab"]"#
        );
        assert_eq!(
            runner_labels(FleetHostKind::Vm, "production-1").unwrap(),
            r#"["self-hosted","Linux","X64","sing-box-production-vm","production-1"]"#
        );
        assert!(runner_labels(FleetHostKind::Unspecified, "unknown").is_err());
    }
}
