use crate::cli::FleetCommand;
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::{FleetHostKind, decode_fleet_desired_state, fleet_host};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const MAX_INVENTORY_BYTES: u64 = 65_536;
const MAX_RUNNER_BYTES: u64 = 1_048_576;

#[derive(Deserialize)]
struct RunnerApiPage {
    total_count: usize,
    runners: Vec<RunnerApiEntry>,
}

#[derive(Deserialize)]
struct RunnerApiEntry {
    id: u64,
    name: String,
    status: String,
    busy: bool,
    labels: Vec<RunnerApiLabel>,
}

#[derive(Deserialize)]
struct RunnerApiLabel {
    name: String,
}

/// Official registration only; historical workflow-job assignments never prove availability.
fn official_runner_id(
    path: &Path,
    kind: FleetHostKind,
    owner: &str,
    windows_label: &str,
) -> Result<u64, String> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| "RUNNER_API_UNAVAILABLE".to_owned())?
        .take(MAX_RUNNER_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| "RUNNER_API_UNAVAILABLE".to_owned())?;
    if data.len() as u64 > MAX_RUNNER_BYTES {
        return Err("RUNNER_API_TOO_LARGE".to_owned());
    }
    inspect_runner_registration(&data, kind, owner, windows_label)
}

fn inspect_runner_registration(
    data: &[u8],
    kind: FleetHostKind,
    owner: &str,
    windows_label: &str,
) -> Result<u64, String> {
    let pages: Vec<RunnerApiPage> =
        serde_json::from_slice(data).map_err(|_| "RUNNER_API_MALFORMED".to_owned())?;
    if pages.is_empty()
        || pages.iter().any(|p| p.total_count != pages[0].total_count)
        || pages.iter().map(|p| p.runners.len()).sum::<usize>() != pages[0].total_count
        || pages[0].total_count > 10_000
    {
        return Err("RUNNER_API_INCOMPLETE".to_owned());
    }
    let name = match kind {
        FleetHostKind::Windows => owner.to_owned(),
        FleetHostKind::Vm => format!("sing-box-production-{owner}"),
        FleetHostKind::Unspecified => return Err("RUNNER_KIND_INVALID".to_owned()),
    };
    let required: &[&str] = match kind {
        FleetHostKind::Windows => &["self-hosted", "Windows", "X64", windows_label],
        FleetHostKind::Vm => &[
            "self-hosted",
            "Linux",
            "X64",
            "sing-box-production-vm",
            owner,
        ],
        FleetHostKind::Unspecified => return Err("RUNNER_KIND_INVALID".to_owned()),
    };
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut selected = None;
    for runner in pages.into_iter().flat_map(|p| p.runners) {
        if runner.id == 0 || !ids.insert(runner.id) || !names.insert(runner.name.clone()) {
            return Err("RUNNER_API_DUPLICATE_IDENTITY".to_owned());
        }
        if runner.name == name {
            selected = Some(runner);
        }
    }
    let runner = selected.ok_or_else(|| "RUNNER_UNREGISTERED".to_owned())?;
    let labels = runner
        .labels
        .iter()
        .map(|l| l.name.as_str())
        .collect::<BTreeSet<_>>();
    if required.iter().any(|r| !labels.contains(r)) {
        return Err("RUNNER_LABELS_MISMATCH".to_owned());
    }
    if runner.status != "online" {
        return Err(if runner.status == "offline" {
            "RUNNER_OFFLINE".to_owned()
        } else {
            "RUNNER_STATUS_UNKNOWN".to_owned()
        });
    }
    if runner.busy {
        return Err("RUNNER_BUSY".to_owned());
    }
    Ok(runner.id)
}

/// Runner registration is an admission signal, not evidence of machine or app health.
/// Unregistered, offline, and busy are legitimate observed states for status,
/// whereas an invalid/incomplete API response cannot be reported as valid evidence.
fn runner_status(
    path: &Path,
    kind: FleetHostKind,
    owner: &str,
    windows_label: &str,
) -> Result<String, String> {
    match official_runner_id(path, kind, owner, windows_label) {
        Ok(id) => Ok(format!("READY_FOR_DISPATCH:{id}")),
        Err(reason)
            if matches!(
                reason.as_str(),
                "RUNNER_UNREGISTERED"
                    | "RUNNER_OFFLINE"
                    | "RUNNER_BUSY"
                    | "RUNNER_LABELS_MISMATCH"
                    | "RUNNER_STATUS_UNKNOWN"
            ) =>
        {
            Ok(reason)
        }
        Err(reason) => Err(reason),
    }
}

/// Read a protobuf rendered from the canonical Git textproto at the exact
/// checked-out revision. It is NOT embedded in the executable: enrolling
/// another host changes the inventory but never the runtime binary.
pub(crate) fn run(
    command: FleetCommand,
    release: &OrchestrationContext,
    inventory_path: &Path,
    expected_sha256: &str,
    github_output: Option<&Path>,
    runner_inventory_json: Option<&Path>,
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
        FleetCommand::Status => {
            println!("fleet_schema=1");
            println!("fleet_host_count={}", desired.hosts.len());
            println!("fleet_inventory_sha256={inventory_sha}");
            println!(
                "release_set_sha256={}",
                release.release().release_set_sha256
            );
            for host in &desired.hosts {
                let kind = FleetHostKind::try_from(host.kind)
                    .map_err(|_| "fleet host kind invalid".to_owned())?;
                let owner = match host.owner.as_ref() {
                    Some(fleet_host::Owner::WindowsRunnerName(name)) => name,
                    Some(fleet_host::Owner::VmMachineId(name)) => name,
                    None => return Err("fleet owner missing".to_owned()),
                };
                let registration = if let Some(path) = runner_inventory_json {
                    runner_status(path, kind, owner, &host.windows_runner_label)?
                } else {
                    "UNPROVEN".to_owned()
                };
                println!("fleet_host_begin={}", host.machine_id);
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
                println!("fleet_runner_registration={registration}");
                println!("fleet_host_runtime=UNPROVEN");
                println!("fleet_host_end={}", host.machine_id);
            }
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
            if kind == FleetHostKind::Windows {
                println!("fleet_runner_label={}", host.windows_runner_label);
            }
            // GitHub runner selectors are derived only from the validated
            // exact Git inventory. They never grant privilege by themselves:
            // the selected host must still attest its installed native owner.
            let label_json = runner_labels(kind, owner, &host.windows_runner_label)?;
            println!("fleet_runner_labels_json={label_json}");
            if let Some(path) = runner_inventory_json {
                let runner_id = official_runner_id(path, kind, owner, &host.windows_runner_label)?;
                println!("fleet_runner_id={runner_id}");
                println!("fleet_owner_reachability=READY_FOR_DISPATCH");
            }
            if let Some(path) = github_output {
                append_control_outputs(path, &machine_id, kind, owner, &label_json)?;
            }
            println!("fleet_inventory_sha256={inventory_sha}");
            println!(
                "release_set_sha256={}",
                release.release().release_set_sha256
            );
            println!("fleet_runtime_observation=UNPROVEN");
            if runner_inventory_json.is_none() {
                println!("fleet_owner_reachability=UNPROVEN");
            }
            println!("fleet_mutations=0");
            Ok(())
        }
    }
}

/// A single Rust-owned mapping from typed host kind to GitHub's existing
/// self-hosted owner labels; no workflow-specific second inventory or parser.
fn runner_labels(
    kind: FleetHostKind,
    owner: &str,
    windows_runner_label: &str,
) -> Result<String, String> {
    let labels: Vec<&str> = match kind {
        FleetHostKind::Windows => vec!["self-hosted", "Windows", "X64", windows_runner_label],
        FleetHostKind::Vm => {
            vec![
                "self-hosted",
                "Linux",
                "X64",
                "sing-box-production-vm",
                owner,
            ]
        }
        FleetHostKind::Unspecified => return Err("fleet host kind unspecified".to_owned()),
    };
    serde_json::to_string(&labels).map_err(|_| "fleet runner selection encoding failed".to_owned())
}

/// Publishes exact protobuf-validated host selection to the *existing*
/// GitHub Actions outputs file. Never create a path or parse diagnostic logs:
/// the runner owns this file and the only data is non-secret host selectors.
fn append_control_outputs(
    path: &Path,
    machine_id: &str,
    kind: FleetHostKind,
    owner: &str,
    labels: &str,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "Fleet GitHub output destination unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("Fleet GitHub output must be an existing regular file".to_owned());
    }
    let name = match kind {
        FleetHostKind::Windows => "WINDOWS",
        FleetHostKind::Vm => "VM",
        FleetHostKind::Unspecified => return Err("Fleet GitHub output kind invalid".to_owned()),
    };
    let values =
        format!("machine_id={machine_id}\nkind={name}\nowner={owner}\nrunner_labels={labels}\n");
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut target| target.write_all(values.as_bytes()))
        .map_err(|_| "Fleet GitHub output write failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_runner_registration_rejects_alias_offline_busy_and_mismatch() {
        fn report(status: &str, busy: bool, last_label: &str) -> Vec<u8> {
            let labels = [
                "self-hosted",
                "Linux",
                "X64",
                "sing-box-production-vm",
                last_label,
            ]
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect::<Vec<_>>();
            serde_json::to_vec(&serde_json::json!([{
                "total_count":1,"runners":[{
                    "id":24,"name":"sing-box-production-application-acceptance-1",
                    "status":status,"busy":busy,"labels":labels
                }]
            }]))
            .unwrap()
        }
        let success = report("online", false, "application-acceptance-1");
        let call = |data: &[u8]| {
            inspect_runner_registration(data, FleetHostKind::Vm, "application-acceptance-1", "")
        };
        assert_eq!(call(&success).unwrap(), 24);
        assert_eq!(
            inspect_runner_registration(&success, FleetHostKind::Vm, "production-1", "")
                .unwrap_err(),
            "RUNNER_UNREGISTERED"
        );
        assert_eq!(
            call(&report("offline", false, "application-acceptance-1")).unwrap_err(),
            "RUNNER_OFFLINE"
        );
        assert_eq!(
            call(&report("online", true, "application-acceptance-1")).unwrap_err(),
            "RUNNER_BUSY"
        );
        assert_eq!(
            call(&report("online", false, "production-1")).unwrap_err(),
            "RUNNER_LABELS_MISMATCH"
        );
        assert_eq!(call(b"[]").unwrap_err(), "RUNNER_API_INCOMPLETE");
        assert_eq!(call(b"malformed").unwrap_err(), "RUNNER_API_MALFORMED");
        let temp_path = std::env::temp_dir().join(format!(
            "fleet-runner-status-{}",
            std::process::id()
        ));
        std::fs::write(&temp_path, report("offline", false, "application-acceptance-1"))
            .unwrap();
        assert_eq!(
            runner_status(&temp_path, FleetHostKind::Vm, "application-acceptance-1", "")
                .unwrap(),
            "RUNNER_OFFLINE"
        );
        assert_eq!(
            runner_status(&temp_path, FleetHostKind::Vm, "production-1", "").unwrap(),
            "RUNNER_UNREGISTERED"
        );
        std::fs::write(&temp_path, b"[]").unwrap();
        assert_eq!(
            runner_status(&temp_path, FleetHostKind::Vm, "production-1", "").unwrap_err(),
            "RUNNER_API_INCOMPLETE"
        );
        std::fs::remove_file(temp_path).unwrap();
    }

    #[test]
    fn native_owner_selection_writes_exact_host_fields_without_log_parsing() {
        let path = std::env::temp_dir().join(format!("fleet-gh-output-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let labels = runner_labels(
            FleetHostKind::Windows,
            "DESKTOP-0E1F6UQ",
            "sing-box-windows-lab",
        )
        .unwrap();
        append_control_outputs(
            &path,
            "sing-box-windows-lab",
            FleetHostKind::Windows,
            "DESKTOP-0E1F6UQ",
            &labels,
        )
        .unwrap();
        let observed = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            observed,
            format!(
                "machine_id=sing-box-windows-lab\nkind=WINDOWS\nowner=DESKTOP-0E1F6UQ\nrunner_labels={labels}\n"
            )
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            append_control_outputs(
                &path,
                "sing-box-windows-lab",
                FleetHostKind::Windows,
                "DESKTOP-0E1F6UQ",
                &labels,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_host_kind_selects_only_existing_native_owners() {
        assert_eq!(
            runner_labels(
                FleetHostKind::Windows,
                "DESKTOP-0E1F6UQ",
                "sing-box-windows-lab"
            )
            .unwrap(),
            r#"["self-hosted","Windows","X64","sing-box-windows-lab"]"#
        );
        assert_eq!(
            runner_labels(FleetHostKind::Vm, "production-1", "").unwrap(),
            r#"["self-hosted","Linux","X64","sing-box-production-vm","production-1"]"#
        );
        assert_eq!(
            runner_labels(FleetHostKind::Vm, "application-acceptance-1", "").unwrap(),
            r#"["self-hosted","Linux","X64","sing-box-production-vm","application-acceptance-1"]"#
        );
        assert!(runner_labels(FleetHostKind::Unspecified, "unknown", "").is_err());
    }
}
