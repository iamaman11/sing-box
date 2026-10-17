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
    let desired = decode_fleet_desired_state(&bytes)?;
    let digest = digest(&SHA256, &bytes);
    let inventory_sha = digest
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
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
