use crate::cli::HostCommand;
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::{HostRegistry, ManagedHostKind, decode_host_registry, managed_host};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
    kind: ManagedHostKind,
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
    kind: ManagedHostKind,
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
        ManagedHostKind::Windows => owner.to_owned(),
        ManagedHostKind::Vm => format!("sing-box-production-{owner}"),
        ManagedHostKind::Unspecified => return Err("RUNNER_KIND_INVALID".to_owned()),
    };
    let required: &[&str] = match kind {
        ManagedHostKind::Windows => &["self-hosted", "Windows", "X64", windows_label],
        ManagedHostKind::Vm => &[
            "self-hosted",
            "Linux",
            "X64",
            "sing-box-production-vm",
            owner,
        ],
        ManagedHostKind::Unspecified => return Err("RUNNER_KIND_INVALID".to_owned()),
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
    kind: ManagedHostKind,
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
    command: HostCommand,
    release: &OrchestrationContext,
    inventory_path: &Path,
    expected_sha256: &str,
    github_output: Option<&Path>,
    runner_inventory_json: Option<&Path>,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    File::open(inventory_path)
        .map_err(|_| "host inventory file unavailable".to_owned())?
        .take(MAX_INVENTORY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "host inventory unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err("host inventory exceeds bounded protobuf size".to_owned());
    }
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
    {
        return Err("host Git inventory SHA-256 must be exact lowercase hex".to_owned());
    }
    let digest = digest(&SHA256, &bytes);
    let inventory_sha = digest
        .as_ref()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
    if inventory_sha != expected_sha256 {
        return Err("host protobuf differs from protected Git inventory SHA-256".to_owned());
    }
    let desired = decode_host_registry(&bytes)?;
    if let HostCommand::Status {
        machine_id: Some(vm_id),
        deep: false,
        credential_pair_windows: Some(windows_id),
    } = &command
    {
        let output = github_output.ok_or("HOST_CREDENTIAL_OUTPUT_REQUIRED")?;
        let (runner_name, runner_label) = resolve_credential_peer(&desired, vm_id, windows_id)?;
        append_credential_peer_outputs(output, vm_id, &runner_name, &runner_label)?;
        println!("host_credential_pair_resolution=READ_ONLY_TYPED");
        println!("host_mutations=0");
        return Ok(());
    }
    match command {
        HostCommand::Status {
            machine_id,
            deep,
            credential_pair_windows,
        } => {
            if credential_pair_windows.is_some() {
                return Err("HOST_CREDENTIAL_PEER_REQUIRES_EXACT_VM_AND_FAST".to_owned());
            }
            if deep && machine_id.is_none() {
                return Err("HOST_DEEP_REQUIRES_EXACT_MACHINE".to_owned());
            }
            println!("host_schema=1");
            println!("host_count={}", desired.hosts.len());
            println!("host_registry_sha256={inventory_sha}");
            println!(
                "release_set_sha256={}",
                release.release().release_set_sha256
            );
            let selected = desired
                .hosts
                .iter()
                .filter(|host| machine_id.as_ref().is_none_or(|id| id == &host.machine_id))
                .collect::<Vec<_>>();
            if selected.is_empty() {
                return Err("HOST_NOT_REGISTERED".to_owned());
            }
            // A native Git-owned matrix avoids hard-coded names, copied
            // runner routing and one diagnostic workflow per host.
            let mut observation_targets = Vec::new();
            for host in selected {
                let kind = ManagedHostKind::try_from(host.kind)
                    .map_err(|_| "HOST_KIND_INVALID".to_owned())?;
                let owner = match host.owner.as_ref() {
                    Some(managed_host::Owner::WindowsRunnerName(name)) => name,
                    Some(managed_host::Owner::VmMachineId(name)) => name,
                    None => return Err("HOST_OWNER_MISSING".to_owned()),
                };
                println!("host_machine_id={}", host.machine_id);
                println!("host_desired_spec_path={}", host.desired_spec_path);
                println!(
                    "host_kind={}",
                    match kind {
                        ManagedHostKind::Windows => "WINDOWS",
                        ManagedHostKind::Vm => "VM",
                        ManagedHostKind::Unspecified =>
                            return Err("HOST_KIND_UNSPECIFIED".to_owned()),
                    }
                );
                let labels = runner_labels(kind, owner, &host.windows_runner_label)?;
                if machine_id.is_some() {
                    // Runner API is advisory for read-only observation. A
                    // missing Administration:read grant must not block
                    // diagnostics on an existing exact-label runner. The
                    // physical owner verifies RUNNER_NAME again on the host.
                    // If the API returns an authoritative negative result,
                    // do not enqueue a job that cannot run.
                    let registration = if let Some(path) = runner_inventory_json {
                        runner_status(path, kind, owner, &host.windows_runner_label)?
                    } else {
                        "UNPROVEN".to_owned()
                    };
                    println!("host_runner_registration={registration}");
                    let can_dispatch = registration == "UNPROVEN"
                        || registration.starts_with("READY_FOR_DISPATCH:");
                    if !can_dispatch {
                        println!("host_dispatch=NOT_SCHEDULED");
                        continue;
                    }
                    println!("host_dispatch=READ_ONLY_EXACT_OWNER");
                    observation_targets.push(observation_target(
                        &host.machine_id,
                        kind,
                        owner,
                        &labels,
                    )?);
                    println!(
                        "host_observation_depth={}",
                        if deep { "DEEP" } else { "FAST" }
                    );
                    if let Some(path) = github_output {
                        append_control_outputs(
                            path,
                            &host.machine_id,
                            kind,
                            owner,
                            &labels,
                            &host.windows_runner_label,
                            &host.desired_spec_path,
                        )?;
                    }
                } else {
                    let registration = if let Some(path) = runner_inventory_json {
                        runner_status(path, kind, owner, &host.windows_runner_label)?
                    } else {
                        "UNPROVEN".to_owned()
                    };
                    println!("host_runner_registration={registration}");
                    // Missing GitHub Administration:read is not evidence
                    // that a registered native owner is offline. Exact
                    // Git-owned read-only targets may be dispatched even
                    // without runner API; GitHub queue/physical owner still
                    // cannot claim PASS until the native diagnostic runs.
                    // Authoritative offline/invalid labels are NOT dispatched.
                    if registration == "UNPROVEN" || registration.starts_with("READY_FOR_DISPATCH:")
                    {
                        observation_targets.push(observation_target(
                            &host.machine_id,
                            kind,
                            owner,
                            &labels,
                        )?);
                    }
                }
                println!("host_runtime=UNPROVEN");
            }
            println!("host_observation_targets={}", observation_targets.len());
            if let Some(output) = github_output {
                append_observation_matrix(output, &observation_targets)?;
            }
            println!("host_mutations=0");
            Ok(())
        }
        HostCommand::Apply { machine_id } => host_lifecycle_admission(
            &desired,
            &machine_id,
            HostLifecycleOperation::Apply,
            &release.release().release_set_sha256,
            runner_inventory_json,
            github_output,
        ),
        HostCommand::Recover { machine_id } => host_lifecycle_admission(
            &desired,
            &machine_id,
            HostLifecycleOperation::Recover,
            &release.release().release_set_sha256,
            runner_inventory_json,
            github_output,
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostLifecycleOperation {
    Apply,
    Recover,
}

/// A new typed Host action must never depend on old A/B journals.
/// No native installer contract has yet passed physical acceptance, so an
/// APPLY or RECOVER produces ONE read-only native owner preflight, not a
/// historical installer invocation or a fabricated mutation receipt.
fn host_lifecycle_admission(
    desired: &HostRegistry,
    machine_id: &str,
    operation: HostLifecycleOperation,
    expected_release_set_sha256: &str,
    runner_json: Option<&Path>,
    output: Option<&Path>,
) -> Result<(), String> {
    let selected = desired
        .hosts
        .iter()
        .find(|host| host.machine_id == machine_id)
        .ok_or("HOST_NOT_REGISTERED")?;
    let kind =
        ManagedHostKind::try_from(selected.kind).map_err(|_| "HOST_KIND_INVALID".to_owned())?;
    let owner = match (kind, selected.owner.as_ref()) {
        (ManagedHostKind::Windows, Some(managed_host::Owner::WindowsRunnerName(name))) => name,
        (ManagedHostKind::Vm, Some(managed_host::Owner::VmMachineId(name))) => name,
        _ => return Err("HOST_OWNER_MISMATCH".to_owned()),
    };
    let registration = if let Some(json) = runner_json {
        runner_status(json, kind, owner, &selected.windows_runner_label)?
    } else {
        "UNPROVEN_NATIVE_OWNER_MUST_VERIFY".to_owned()
    };
    println!("host_machine_id={machine_id}");
    println!("host_kind={kind:?}");
    println!("host_runner_registration={registration}");
    println!("host_lifecycle_contract=FRESH_TYPED_ONLY");
    println!("host_expected_release_set_sha256={expected_release_set_sha256}");
    println!("host_desired_spec_path={}", selected.desired_spec_path);
    println!(
        "host_requested_operation={}",
        match operation {
            HostLifecycleOperation::Apply => "APPLY",
            HostLifecycleOperation::Recover => "RECOVER",
        }
    );
    println!("host_historical_journal_authority=FORBIDDEN");
    println!("host_native_install_authority=NOT_YET_ACCEPTED");
    println!("host_next_action=NEED_NATIVE_TYPED_INSTALLER_AND_RELEASE_BOUND_RECEIPTS");
    println!("host_mutations=0");
    let output = output.ok_or("HOST_PREFLIGHT_OUTPUT_REQUIRED")?;
    let labels = runner_labels(kind, owner, &selected.windows_runner_label)?;
    append_control_outputs(
        output,
        machine_id,
        kind,
        owner,
        &labels,
        &selected.windows_runner_label,
        &selected.desired_spec_path,
    )?;
    append_action_output(
        output,
        match operation {
            HostLifecycleOperation::Apply => "APPLY_PREFLIGHT",
            HostLifecycleOperation::Recover => "RECOVER_PREFLIGHT",
        },
    )?;
    let targets = if matches!(
        registration.as_str(),
        "RUNNER_OFFLINE" | "RUNNER_UNREGISTERED" | "RUNNER_LABELS_MISMATCH"
    ) {
        Vec::new()
    } else {
        vec![observation_target(machine_id, kind, owner, &labels)?]
    };
    append_observation_matrix(output, &targets)?;
    println!("host_observation_targets={}", targets.len());
    Ok(())
}

/// Expiring GitHub admission: queued/offline self-hosted jobs must not
/// turn into deferred mutations after a host unexpectedly reconnects.
fn append_admission_timestamp(path: &Path, admitted_at: u64) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "HOST_OUTPUT_UNAVAILABLE".to_owned())?;
    if !metadata.file_type().is_file() || !(1_700_000_000..4_102_444_800).contains(&admitted_at) {
        return Err("HOST_ADMISSION_INVALID".to_owned());
    }
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut file| writeln!(file, "admitted_at_unix={admitted_at}"))
        .map_err(|_| "HOST_ADMISSION_OUTPUT_FAILED".to_owned())
}

fn append_action_output(path: &Path, action: &str) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "HOST_OUTPUT_UNAVAILABLE".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("HOST_OUTPUT_NOT_REGULAR".to_owned());
    }
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut file| writeln!(file, "operation={action}"))
        .map_err(|_| "HOST_ACTION_OUTPUT_WRITE_FAILED".to_owned())
}

/// A single Rust-owned mapping from typed host kind to GitHub's existing
/// self-hosted owner labels; no workflow-specific second inventory or parser.
fn runner_labels(
    kind: ManagedHostKind,
    owner: &str,
    windows_runner_label: &str,
) -> Result<String, String> {
    let labels: Vec<&str> = match kind {
        ManagedHostKind::Windows => vec!["self-hosted", "Windows", "X64", windows_runner_label],
        ManagedHostKind::Vm => {
            vec![
                "self-hosted",
                "Linux",
                "X64",
                "sing-box-production-vm",
                owner,
            ]
        }
        ManagedHostKind::Unspecified => return Err("host host kind unspecified".to_owned()),
    };
    serde_json::to_string(&labels).map_err(|_| "host runner selection encoding failed".to_owned())
}

/// A dispatch target comes exclusively from the protected protobuf registry.
fn observation_target(
    machine_id: &str,
    kind: ManagedHostKind,
    owner: &str,
    labels: &str,
) -> Result<serde_json::Value, String> {
    let runner_labels: Vec<String> =
        serde_json::from_str(labels).map_err(|_| "HOST_MATRIX_LABELS_INVALID".to_owned())?;
    let expected_labels = match kind {
        ManagedHostKind::Windows => 4,
        ManagedHostKind::Vm => 5,
        ManagedHostKind::Unspecified => return Err("HOST_MATRIX_KIND_INVALID".to_owned()),
    };
    if runner_labels.len() != expected_labels || runner_labels.iter().any(|s| s.is_empty()) {
        return Err("HOST_MATRIX_LABELS_INVALID".to_owned());
    }
    let kind = match kind {
        ManagedHostKind::Windows => "WINDOWS",
        ManagedHostKind::Vm => "VM",
        ManagedHostKind::Unspecified => return Err("HOST_MATRIX_KIND_INVALID".to_owned()),
    };
    Ok(serde_json::json!({
        "machine_id": machine_id,
        "kind": kind,
        "owner": owner,
        "runner_labels": runner_labels,
    }))
}

/// One bounded GitHub matrix for both targeted and fleet-wide native diagnosis.
/// It is transport metadata, not runtime decision authority or an observed PASS.
fn append_observation_matrix(path: &Path, targets: &[serde_json::Value]) -> Result<(), String> {
    if targets.len() > 64 {
        return Err("HOST_MATRIX_TOO_LARGE".to_owned());
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "HOST_MATRIX_OUTPUT_UNAVAILABLE".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("HOST_MATRIX_OUTPUT_NOT_REGULAR".to_owned());
    }
    let matrix = serde_json::json!({"include": targets});
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut target| {
            writeln!(target, "host_matrix={matrix}")?;
            writeln!(target, "host_targets_present={}", !targets.is_empty())
        })
        .map_err(|_| "HOST_MATRIX_OUTPUT_WRITE_FAILED".to_owned())
}

/// Publishes exact protobuf-validated host selection to the *existing*
/// GitHub Actions outputs file. Never create a path or parse diagnostic logs:
/// the runner owns this file and the only data is non-secret host selectors.
fn append_control_outputs(
    path: &Path,
    machine_id: &str,
    kind: ManagedHostKind,
    owner: &str,
    labels: &str,
    windows_runner_label: &str,
    desired_spec_path: &str,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "Host GitHub output destination unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("Host GitHub output must be an existing regular file".to_owned());
    }
    let name = match kind {
        ManagedHostKind::Windows => "WINDOWS",
        ManagedHostKind::Vm => "VM",
        ManagedHostKind::Unspecified => return Err("Host GitHub output kind invalid".to_owned()),
    };
    let values = format!(
        "machine_id={machine_id}\nkind={name}\nowner={owner}\nrunner_labels={labels}\nwindows_runner_label={windows_runner_label}\ndesired_spec_path={desired_spec_path}\n"
    );
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut target| target.write_all(values.as_bytes()))
        .map_err(|_| "Host GitHub output write failed".to_owned())
}

fn resolve_credential_peer(
    desired: &HostRegistry,
    vm_id: &str,
    windows_id: &str,
) -> Result<(String, String), String> {
    let vm = desired
        .hosts
        .iter()
        .find(|host| host.machine_id == vm_id)
        .ok_or("HOST_CREDENTIAL_VM_UNKNOWN")?;
    if ManagedHostKind::try_from(vm.kind) != Ok(ManagedHostKind::Vm)
        || !matches!(
            vm.owner.as_ref(),
            Some(managed_host::Owner::VmMachineId(owner)) if owner == vm_id
        )
        || vm.desired_spec_path != "infra/application/disposable-acceptance.json"
    {
        return Err("HOST_CREDENTIAL_VM_ORIGIN_INVALID".to_owned());
    }
    let eligible = desired
        .hosts
        .iter()
        .filter(|host| ManagedHostKind::try_from(host.kind) == Ok(ManagedHostKind::Windows))
        .collect::<Vec<_>>();
    let chosen = if windows_id == "auto" {
        if eligible.len() != 1 {
            return Err("HOST_CREDENTIAL_WINDOWS_EXPLICIT_ID_REQUIRED".to_owned());
        }
        eligible[0]
    } else {
        eligible
            .into_iter()
            .find(|host| host.machine_id == windows_id)
            .ok_or("HOST_CREDENTIAL_WINDOWS_UNKNOWN")?
    };
    let name = match chosen.owner.as_ref() {
        Some(managed_host::Owner::WindowsRunnerName(name)) => name.clone(),
        _ => return Err("HOST_CREDENTIAL_WINDOWS_OWNER_INVALID".to_owned()),
    };
    Ok((name, chosen.windows_runner_label.clone()))
}

fn append_credential_peer_outputs(
    path: &Path,
    vm_id: &str,
    windows_runner_name: &str,
    windows_runner_label: &str,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "HOST_CREDENTIAL_OUTPUT_UNAVAILABLE".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("HOST_CREDENTIAL_OUTPUT_NOT_REGULAR".to_owned());
    }
    let values = format!(
        "machine_id={vm_id}\nwindows_runner_name={windows_runner_name}\nwindows_runner_label={windows_runner_label}\n"
    );
    OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut output| output.write_all(values.as_bytes()))
        .map_err(|_| "HOST_CREDENTIAL_OUTPUT_WRITE_FAILED".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::ManagedHost;

    #[test]
    fn credential_peer_is_selected_from_typed_registry_not_textproto_regex() {
        let registry = HostRegistry {
            schema_version: 1,
            hosts: vec![
                ManagedHost {
                    machine_id: "application-acceptance-1".to_owned(),
                    kind: ManagedHostKind::Vm as i32,
                    owner: Some(managed_host::Owner::VmMachineId(
                        "application-acceptance-1".to_owned(),
                    )),
                    windows_runner_label: String::new(),
                    desired_spec_path: "infra/application/disposable-acceptance.json".to_owned(),
                },
                ManagedHost {
                    machine_id: "sing-box-windows-lab".to_owned(),
                    kind: ManagedHostKind::Windows as i32,
                    owner: Some(managed_host::Owner::WindowsRunnerName(
                        "DESKTOP-0E1F6UQ".to_owned(),
                    )),
                    windows_runner_label: "sing-box-windows-lab".to_owned(),
                    desired_spec_path: "infra/production/production.textproto".to_owned(),
                },
            ],
        };
        assert_eq!(
            resolve_credential_peer(&registry, "application-acceptance-1", "auto").unwrap(),
            (
                "DESKTOP-0E1F6UQ".to_owned(),
                "sing-box-windows-lab".to_owned()
            )
        );
        assert_eq!(
            resolve_credential_peer(&registry, "production-1", "auto").unwrap_err(),
            "HOST_CREDENTIAL_VM_UNKNOWN"
        );
        assert_eq!(
            resolve_credential_peer(&registry, "application-acceptance-1", "not-enrolled")
                .unwrap_err(),
            "HOST_CREDENTIAL_WINDOWS_UNKNOWN"
        );
        let mut two_windows = registry.clone();
        two_windows.hosts.push(ManagedHost {
            machine_id: "other-windows".to_owned(),
            kind: ManagedHostKind::Windows as i32,
            owner: Some(managed_host::Owner::WindowsRunnerName(
                "OTHER-PC".to_owned(),
            )),
            windows_runner_label: "other-label".to_owned(),
            desired_spec_path: "infra/production/production.textproto".to_owned(),
        });
        assert_eq!(
            resolve_credential_peer(&two_windows, "application-acceptance-1", "auto").unwrap_err(),
            "HOST_CREDENTIAL_WINDOWS_EXPLICIT_ID_REQUIRED"
        );
    }

    #[test]
    fn host_rejects_malformed_original_ab_rather_than_inventing_terminal_proof() {
        // The authoritative positive BEGIN/COMMIT_INTENT and negative
        // duplicate/orphan fixtures live beside the shared journal inspector.
        let malformed = serde_json::json!([{
            "body": "<!-- sing-box-credential-existing-join-begin/v1 -->\\n{\"schema\":\"sing-box.credential-existing-join-begin/v1\",\"run_id\":39004301614}"
        }]).to_string();
        assert!(
            crate::credential_existing_join::host_admission_status(malformed.as_bytes()).is_err()
        );
        assert_eq!(
            crate::credential_existing_join::host_admission_status(b"[]").unwrap_err(),
            "HOST_JOURNAL_EMPTY"
        );
        let normal = serde_json::json!([{"body":"read-only observation"}]).to_string();
        assert_eq!(
            crate::credential_existing_join::host_admission_status(normal.as_bytes()).unwrap(),
            "NO_BEGIN_NO_MUTATION_AUTHORITY"
        );
    }

    #[test]
    fn host_observation_matrix_is_bound_to_one_typed_owner() {
        let win = observation_target(
            "windows-02",
            ManagedHostKind::Windows,
            "DESKTOP-EXAMPLE",
            r#"["self-hosted","Windows","X64","windows-02"]"#,
        )
        .unwrap();
        let vm = observation_target(
            "vm-02",
            ManagedHostKind::Vm,
            "vm-02",
            r#"["self-hosted","Linux","X64","sing-box-production-vm","vm-02"]"#,
        )
        .unwrap();
        assert_eq!(win["kind"], "WINDOWS");
        assert_eq!(vm["machine_id"], "vm-02");
        assert!(observation_target("x", ManagedHostKind::Unspecified, "y", "[]").is_err());
        assert!(observation_target("x", ManagedHostKind::Windows, "y", "[]").is_err());
        let file =
            std::env::temp_dir().join(format!("sing-box-host-matrix-{}", std::process::id()));
        std::fs::write(&file, "").unwrap();
        append_observation_matrix(&file, &[win, vm]).unwrap();
        let contents = std::fs::read_to_string(&file).unwrap();
        assert!(contents.contains("host_targets_present=true"));
        assert!(contents.contains(r#""machine_id":"windows-02""#));
        assert!(contents.contains(r#""machine_id":"vm-02""#));
        std::fs::remove_file(file).unwrap();
    }

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
            inspect_runner_registration(data, ManagedHostKind::Vm, "application-acceptance-1", "")
        };
        assert_eq!(call(&success).unwrap(), 24);
        assert_eq!(
            inspect_runner_registration(&success, ManagedHostKind::Vm, "production-1", "")
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
        let temp_path =
            std::env::temp_dir().join(format!("host-runner-status-{}", std::process::id()));
        std::fs::write(
            &temp_path,
            report("offline", false, "application-acceptance-1"),
        )
        .unwrap();
        assert_eq!(
            runner_status(
                &temp_path,
                ManagedHostKind::Vm,
                "application-acceptance-1",
                ""
            )
            .unwrap(),
            "RUNNER_OFFLINE"
        );
        assert_eq!(
            runner_status(&temp_path, ManagedHostKind::Vm, "production-1", "").unwrap(),
            "RUNNER_UNREGISTERED"
        );
        std::fs::write(&temp_path, b"[]").unwrap();
        assert_eq!(
            runner_status(&temp_path, ManagedHostKind::Vm, "production-1", "").unwrap_err(),
            "RUNNER_API_INCOMPLETE"
        );
        std::fs::remove_file(temp_path).unwrap();
    }

    #[test]
    fn native_owner_selection_writes_exact_host_fields_without_log_parsing() {
        let path = std::env::temp_dir().join(format!("host-gh-output-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let labels = runner_labels(
            ManagedHostKind::Windows,
            "DESKTOP-0E1F6UQ",
            "sing-box-windows-lab",
        )
        .unwrap();
        append_control_outputs(
            &path,
            "sing-box-windows-lab",
            ManagedHostKind::Windows,
            "DESKTOP-0E1F6UQ",
            &labels,
            "sing-box-windows-lab",
            "infra/production/production.textproto",
        )
        .unwrap();
        let observed = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            observed,
            format!(
                "machine_id=sing-box-windows-lab\nkind=WINDOWS\nowner=DESKTOP-0E1F6UQ\nrunner_labels={labels}\nwindows_runner_label=sing-box-windows-lab\ndesired_spec_path=infra/production/production.textproto\n"
            )
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            append_control_outputs(
                &path,
                "sing-box-windows-lab",
                ManagedHostKind::Windows,
                "DESKTOP-0E1F6UQ",
                &labels,
                "sing-box-windows-lab",
                "infra/production/production.textproto",
            )
            .is_err()
        );
    }

    #[test]
    fn exact_host_kind_selects_only_existing_native_owners() {
        assert_eq!(
            runner_labels(
                ManagedHostKind::Windows,
                "DESKTOP-0E1F6UQ",
                "sing-box-windows-lab"
            )
            .unwrap(),
            r#"["self-hosted","Windows","X64","sing-box-windows-lab"]"#
        );
        assert_eq!(
            runner_labels(ManagedHostKind::Vm, "production-1", "").unwrap(),
            r#"["self-hosted","Linux","X64","sing-box-production-vm","production-1"]"#
        );
        assert_eq!(
            runner_labels(ManagedHostKind::Vm, "application-acceptance-1", "").unwrap(),
            r#"["self-hosted","Linux","X64","sing-box-production-vm","application-acceptance-1"]"#
        );
        assert!(runner_labels(ManagedHostKind::Unspecified, "unknown", "").is_err());
    }
}
