use crate::cli::FleetCommand;
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::{FleetHostKind, canonical_fleet_desired_state, fleet_host};

/// Pure Git-owned selectors. Privileged diagnostics and actions must be routed
/// through the existing authenticated Windows SYSTEM / Linux root owners,
/// never inferred from inventory or a GitHub runner label.
pub(crate) fn run(command: FleetCommand, release: &OrchestrationContext) -> Result<(), String> {
    let desired = canonical_fleet_desired_state()?;
    match command {
        FleetCommand::Inventory => {
            println!("fleet_schema=1");
            println!("fleet_host_count={}", desired.hosts.len());
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
