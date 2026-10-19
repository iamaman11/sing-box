use crate::cli::HostCommand;
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::{
    FleetHostAction, FleetHostIntent, FleetHostMode, HostRegistry, ManagedHostKind,
    decode_host_registry,
    host_lifecycle::{
        MAX_NATIVE_OBSERVATION_BYTES, decode_host_intent, decode_host_result,
        decode_native_observation, prepared_host_result, validate_host_intent,
        validate_host_result, validate_intent_against_target, validate_unattested_native_result,
    },
    managed_host,
};
use prost::Message;
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
    source_comment_id: Option<u64>,
    intent_output: Option<&Path>,
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
                print_host_target(host)?;
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
        HostCommand::Readback {
            machine_id,
            observation_path,
            resources_path,
        } => {
            let selected = desired
                .hosts
                .iter()
                .find(|host| host.machine_id == machine_id)
                .ok_or("HOST_NOT_REGISTERED")?;
            let metadata = std::fs::symlink_metadata(&observation_path)
                .map_err(|_| "HOST_NATIVE_READBACK_MISSING")?;
            if !metadata.file_type().is_file()
                || metadata.len() == 0
                || metadata.len() > MAX_NATIVE_OBSERVATION_BYTES as u64
            {
                return Err("HOST_NATIVE_READBACK_FILE_INVALID".to_owned());
            }
            let mut bytes = Vec::new();
            File::open(&observation_path)
                .map_err(|_| "HOST_NATIVE_READBACK_UNREADABLE")?
                .take(MAX_NATIVE_OBSERVATION_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "HOST_NATIVE_READBACK_UNREADABLE")?;
            let observed = decode_native_observation(&bytes).map_err(str::to_owned)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "HOST_CLOCK_UNAVAILABLE")?
                .as_secs();
            let release_sha = exact_hex_sha256(&release.release().release_set_sha256)?;
            let verified = verified_release_set_from_resolver(release)?;
            // Resolve VM transport->logical identity once for both summary and
            // planner so no status can contradict its typed proposal.
            let native_bundle_sha = if selected.kind == ManagedHostKind::Vm as i32 {
                verified_vm_runtime_digest_from_resolver(&verified)?
            } else {
                Vec::new()
            };
            let summary = validate_readback_scope(
                selected,
                &observed,
                &release.release().release_set_sha256,
                (selected.kind == ManagedHostKind::Vm as i32)
                    .then_some(native_bundle_sha.as_slice()),
                now,
            )?;
            println!("host_machine_id={machine_id}");
            println!("host_native_readback_schema=1");
            println!("host_native_observed_at_unix={}", observed.observed_at_unix);
            println!(
                "host_native_owner_state={:?}",
                edge_shared_types::FleetNativeOwnerState::try_from(observed.owner_state)
                    .map_err(|_| "HOST_NATIVE_OWNER_STATE_INVALID")?
            );
            println!(
                "host_native_release_scope={:?}",
                edge_shared_types::FleetNativeReleaseProof::try_from(observed.release_proof)
                    .map_err(|_| "HOST_NATIVE_RELEASE_PROOF_INVALID")?
            );
            println!("host_native_readback_verdict={summary}");
            // Pure typed reconcile: this is NEVER a privileged mutation
            // decision until Worker + native owner independently attest.
            // Reuse the same independently release-bound VM digest for the
            // detailed reconciliation proposal printed below.
            let proposed = edge_shared_types::host_planner::propose_host_transition(
                selected,
                Some(&observed),
                &release_sha,
                &native_bundle_sha,
                now,
            );
            println!(
                "host_reconcile_step={:?}",
                edge_shared_types::FleetHostPlannedStep::try_from(proposed.step)
                    .map_err(|_| "HOST_PLAN_STEP_INVALID")?
            );
            println!("host_reconcile_reason={}", proposed.reason_code);
            println!("host_plan_owner_attested={}", proposed.owner_attested);
            println!(
                "host_plan_mutation_authorized={}",
                proposed.mutation_authorized
            );
            if let Some(path) = resources_path {
                if selected.kind != ManagedHostKind::Vm as i32 {
                    return Err("HOST_VM_RESOURCES_ON_NON_VM".to_owned());
                }
                let meta = std::fs::symlink_metadata(&path)
                    .map_err(|_| "HOST_VM_RESOURCES_TRANSPORT_MISSING")?;
                if !meta.file_type().is_file()
                    || meta.len() == 0
                    || meta.len()
                        > edge_shared_types::host_resources::MAX_VM_RESOURCE_REPORT_BYTES as u64
                {
                    return Err("HOST_VM_RESOURCES_TRANSPORT_INVALID".into());
                }
                let mut bytes = Vec::new();
                File::open(&path)
                    .map_err(|_| "HOST_VM_RESOURCES_TRANSPORT_UNREADABLE")?
                    .take(
                        edge_shared_types::host_resources::MAX_VM_RESOURCE_REPORT_BYTES as u64 + 1,
                    )
                    .read_to_end(&mut bytes)
                    .map_err(|_| "HOST_VM_RESOURCES_TRANSPORT_UNREADABLE")?;
                let report =
                    edge_shared_types::host_resources::decode_vm_resource_report(&bytes, selected)
                        .map_err(str::to_owned)?;
                if report.observed_at_unix > now.saturating_add(60)
                    || now.saturating_sub(report.observed_at_unix) > 300
                {
                    return Err("HOST_VM_RESOURCES_READBACK_STALE".into());
                }
                let resource_plan =
                    edge_shared_types::host_resources::propose_vm_resource_transitions(
                        selected, &report,
                    )
                    .map_err(str::to_owned)?;
                let installed_hierarchy = report
                    .installed_policy_graph
                    .as_ref()
                    .map(|policy| {
                        edge_shared_types::host_resources::derive_vm_resource_hierarchy(
                            selected, policy,
                        )
                    })
                    .transpose()
                    .map_err(str::to_owned)?;
                let problems = resource_plan
                    .resources
                    .iter()
                    .filter(|entry| {
                        edge_shared_types::host_resources::vm_resource_requires_attention(entry)
                    })
                    .count();
                let config_unproven = resource_plan
                    .resources
                    .iter()
                    .filter(|entry| {
                        entry.reason
                            == edge_shared_types::FleetVmResourceReason::RunningRuntimeOnlyConfigUnproven
                                as i32
                    })
                    .count();
                if let Some(network) = report.network.as_ref() {
                    println!("host_vm_network_kernel_observed={}", network.ipv4.is_some());
                    if let Some(ipv4) = &network.ipv4 {
                        println!("host_vm_network_ipv4_links={}", ipv4.links.len());
                        println!("host_vm_network_ipv4_addresses={}", ipv4.addresses.len());
                        println!("host_vm_network_ipv4_routes={}", ipv4.routes.len());
                        let mut default_routes = ipv4.routes.iter().filter(|route| {
                            route.destination == "0.0.0.0" && route.prefix_length == 0
                        });
                        let default = default_routes.next();
                        let exact = default.is_some() && default_routes.next().is_none();
                        println!("host_vm_network_unique_default_route={exact}");
                        if let Some(route) = default {
                            let owner = ipv4
                                .links
                                .iter()
                                .find(|link| link.interface_index == route.output_interface_index)
                                .map(|link| link.name.as_str())
                                .unwrap_or("UNPROVEN");
                            println!("host_vm_network_default_route_interface={owner}");
                        }
                    }
                    println!(
                        "host_vm_dns_configuration_observed={}",
                        network.dns_configuration_observed
                    );
                    println!(
                        "host_vm_dns_configured_nameservers={}",
                        network.dns_nameservers.join(",")
                    );
                    println!("host_vm_dns_resolution_proven=false");
                    println!(
                        "host_vm_nft_ruleset_observed={}",
                        network.nft_ruleset_observed
                    );
                    println!("host_vm_nft_rule_count={}", network.nft_rule_count);
                    println!("host_vm_firewall_desired_converged=false");
                    println!("host_vm_routes_desired_converged=false");
                } else {
                    println!("host_vm_network_observation=UNAVAILABLE");
                }
                println!("host_vm_resources_schema=1");
                println!(
                    "host_vm_installed_policy_hierarchy_origin={}",
                    if installed_hierarchy.is_some() {
                        "RUNNER_COPIED_UNAUTHENTICATED"
                    } else {
                        "UNPROVEN"
                    }
                );
                println!("host_vm_desired_hierarchy_release_proven=false");
                println!(
                    "host_vm_installed_policy_status={:?}",
                    edge_shared_types::FleetVmInstalledPolicyStatus::try_from(
                        report.installed_policy_status
                    )
                    .map_err(|_| "HOST_VM_INSTALLED_POLICY_STATUS_INVALID")?
                );
                println!(
                    "host_vm_installed_policy_error_code={}",
                    if report.installed_policy_error_code.is_empty() {
                        "NONE"
                    } else {
                        &report.installed_policy_error_code
                    }
                );
                println!("host_vm_installed_policy_authorizes_mutation=false");
                if let Some(graph) = installed_hierarchy.as_ref() {
                    println!("host_vm_hierarchy_nodes={}", graph.nodes.len());
                    for node in &graph.nodes {
                        println!(
                            "host_vm_hierarchy_node={} kind={:?} parent={} owner={:?} declared_dependencies={} policy_sha256={}",
                            node.resource_id,
                            edge_shared_types::FleetResourceKind::try_from(node.kind)
                                .map_err(|_| "HOST_VM_HIERARCHY_KIND_INVALID")?,
                            node.parent_resource_id,
                            edge_shared_types::FleetResourceOwner::try_from(node.owner)
                                .map_err(|_| "HOST_VM_HIERARCHY_OWNER_INVALID")?,
                            node.dependency_ids.join(","),
                            node.expected_policy_sha256
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>(),
                        );
                    }
                } else {
                    println!("host_vm_hierarchy_nodes=UNPROVEN");
                }
                println!("host_vm_resources_count={}", report.resources.len());
                println!("host_vm_resources_problem_count={problems}");
                println!("host_vm_resources_config_unproven_count={config_unproven}");
                for (resource, proposal) in report.resources.iter().zip(&resource_plan.resources) {
                    let identity = resource
                        .resource
                        .as_ref()
                        .ok_or("HOST_VM_RESOURCES_IDENTITY_MISSING")?;
                    let resource_id = proposal.resource_id.as_str();
                    let dependencies = installed_hierarchy
                        .as_ref()
                        .and_then(|hierarchy| {
                            hierarchy
                                .nodes
                                .iter()
                                .find(|node| node.resource_id == resource_id)
                        })
                        .map(|node| node.dependency_ids.join(","))
                        .unwrap_or_else(|| "UNPROVEN".to_owned());
                    println!(
                        "host_vm_resource={} resource_id={} resource_kind=DOCKER_CONTAINER resource_owner=VM_ROOT_AGENT resource_parent=host/{} installed_policy_dependencies={} installed_policy_proven=false reason={} step={:?} plan_reason={} present={} owned={} running={} running_proven={} image={} health={} config_proof={:?} config_sha256={} restarts={}",
                        identity.container_name,
                        resource_id,
                        selected.machine_id,
                        dependencies,
                        edge_shared_types::FleetVmObservedReason::try_from(
                            resource.observed_reason
                        )
                        .map_err(|_| "HOST_VM_OBSERVED_REASON_INVALID")?
                        .as_str_name()
                        .strip_prefix("FLEET_VM_OBSERVED_REASON_")
                        .ok_or("HOST_VM_OBSERVED_REASON_INVALID")?,
                        edge_shared_types::FleetHostPlannedStep::try_from(proposal.step)
                            .map_err(|_| "HOST_VM_RESOURCE_PLAN_STEP_INVALID")?,
                        proposal.reason_code,
                        resource.present,
                        resource.ownership_proven,
                        resource.running,
                        resource.running_proven,
                        resource.image,
                        resource.health,
                        edge_shared_types::FleetVmConfigProof::try_from(resource.config_proof)
                            .map_err(|_| "HOST_VM_CONFIG_PROOF_INVALID")?,
                        if resource.config_sha256.is_empty() {
                            "UNPROVEN".to_owned()
                        } else {
                            resource
                                .config_sha256
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        },
                        if resource.restart_count_proven {
                            resource.restart_count.to_string()
                        } else {
                            "UNPROVEN".to_owned()
                        }
                    );
                }
                println!("host_vm_resources_plan_scope=RUNTIME_ONLY_CONFIG_UNPROVEN");
                println!("host_vm_resources_plan_owner_attested=false");
                println!("host_vm_resources_plan_mutation_authorized=false");
                println!("host_vm_resources_origin=RUNNER_COPIED_UNAUTHENTICATED");
                println!("host_vm_resources_authorize_mutation=false");
            }
            println!("host_native_readback_source=RUNNER_COPIED_UNAUTHENTICATED");
            println!("host_native_readback_authorizes_mutation=false");
            println!("host_mutations=0");
            Ok(())
        }
        HostCommand::NativeResult {
            machine_id,
            intent_path,
            result_path,
        } => {
            // Runner-copied bytes are untrusted even when both protobufs
            // correlate with immutable Git. This is an audit, not a receipt.
            let read_bounded = |path: &Path, max: u64| -> Result<Vec<u8>, String> {
                let meta = std::fs::symlink_metadata(path)
                    .map_err(|_| "HOST_NATIVE_TRANSPORT_FILE_MISSING")?;
                if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max {
                    return Err("HOST_NATIVE_TRANSPORT_FILE_INVALID".to_owned());
                }
                let mut bytes = Vec::new();
                File::open(path)
                    .map_err(|_| "HOST_NATIVE_TRANSPORT_FILE_UNREADABLE")?
                    .take(max + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "HOST_NATIVE_TRANSPORT_FILE_UNREADABLE")?;
                if bytes.len() as u64 > max {
                    return Err("HOST_NATIVE_TRANSPORT_FILE_TOO_LARGE".to_owned());
                }
                Ok(bytes)
            };
            let intent =
                decode_host_intent(&read_bounded(&intent_path, 4096)?).map_err(str::to_owned)?;
            let result =
                decode_host_result(&read_bounded(&result_path, 4096)?).map_err(str::to_owned)?;
            let selected = desired
                .hosts
                .iter()
                .find(|host| host.machine_id == machine_id && host.kind == intent.kind)
                .ok_or("HOST_NATIVE_TRANSPORT_MACHINE_UNREGISTERED")?;
            if intent.machine_id != machine_id {
                return Err("HOST_NATIVE_TRANSPORT_MACHINE_MISMATCH".to_owned());
            }
            let spec_path = Path::new(&selected.desired_spec_path);
            let exact_spec = read_bounded(spec_path, 1_048_576)?;
            let desired_sha =
                edge_shared_types::host_lifecycle::digest_host_desired(selected, &exact_spec)
                    .map_err(str::to_owned)?;
            let release_sha = exact_hex_sha256(&release.release().release_set_sha256)?;
            validate_host_intent(
                &intent,
                &desired,
                digest.as_ref(),
                &desired_sha,
                &release_sha,
            )
            .map_err(str::to_owned)?;
            validate_intent_against_target(&intent, &desired).map_err(str::to_owned)?;
            validate_unattested_native_result(&result, &intent).map_err(str::to_owned)?;
            println!("host_machine_id={machine_id}");
            println!("host_operation_id={}", intent.operation_id);
            println!("host_native_result_correlation=EXACT");
            println!(
                "host_native_result_claimed_state={:?}",
                edge_shared_types::FleetHostResultState::try_from(result.state)
                    .map_err(|_| "HOST_NATIVE_RESULT_STATE_INVALID")?
            );
            println!("host_native_result_origin=RUNNER_COPIED_UNAUTHENTICATED");
            println!("host_native_result_authenticated=false");
            println!("host_native_result_remote_acceptance=UNPROVEN");
            println!("host_mutations=0");
            Ok(())
        }
        HostCommand::Apply {
            machine_id,
            resource_id,
        } => host_lifecycle_admission(
            &desired,
            &machine_id,
            HostLifecycleOperation::Apply,
            &release.release().release_set_sha256,
            digest.as_ref(),
            runner_inventory_json,
            github_output,
            source_comment_id,
            intent_output,
            resource_id.as_deref(),
        ),
        HostCommand::Recover { machine_id } => host_lifecycle_admission(
            &desired,
            &machine_id,
            HostLifecycleOperation::Recover,
            &release.release().release_set_sha256,
            digest.as_ref(),
            runner_inventory_json,
            github_output,
            source_comment_id,
            intent_output,
            None,
        ),
    }
}

/// Re-read the exact immutable ReleaseSet downloaded by the existing resolver.
/// VM compares its application bundle digest only to vm_runtime's bundle
/// digest, NEVER to the ReleaseSet hash (the hashes represent different bytes).
fn verified_release_set_bytes(
    path: &Path,
    expected_sha256: &str,
) -> Result<edge_shared_types::ReleaseSet, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "HOST_RELEASESET_BYTES_MISSING")?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 131_072 {
        return Err("HOST_RELEASESET_BYTES_NOT_REGULAR_OR_TOO_LARGE".to_owned());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "HOST_RELEASESET_BYTES_UNREADABLE")?
        .take(131_073)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_RELEASESET_BYTES_UNREADABLE")?;
    if bytes.is_empty() || bytes.len() > 131_072 {
        return Err("HOST_RELEASESET_BYTES_INVALID".to_owned());
    }
    let actual_sha = digest(&SHA256, &bytes);
    if actual_sha.as_ref() != exact_hex_sha256(expected_sha256)?.as_slice() {
        return Err("HOST_RELEASESET_DIGEST_MISMATCH".to_owned());
    }
    edge_shared_types::ReleaseSet::decode(bytes.as_slice())
        .map_err(|_| "HOST_RELEASESET_PROTO_INVALID".to_owned())
}

fn verified_release_set_from_resolver(
    context: &OrchestrationContext,
) -> Result<edge_shared_types::ReleaseSet, String> {
    let context_file =
        std::env::var_os("EDGE_RELEASE_CONTEXT_PATH").ok_or("HOST_RELEASE_CONTEXT_PATH_MISSING")?;
    let directory = Path::new(&context_file)
        .parent()
        .ok_or("HOST_RELEASE_CONTEXT_PARENT_MISSING")?;
    verified_release_set_bytes(
        &directory.join("release-set.pb"),
        &context.release().release_set_sha256,
    )
}

/// Only read the exact published ReleaseSet's adjacent bundle artifact.
/// Its transport hash is verified before extracting the logical VM marker.
/// This stays read-only and never authenticates a runner-provided observation.
fn verified_vm_runtime_digest_from_resolver(
    release: &edge_shared_types::ReleaseSet,
) -> Result<Vec<u8>, String> {
    let context_file =
        std::env::var_os("EDGE_RELEASE_CONTEXT_PATH").ok_or("HOST_RELEASE_CONTEXT_PATH_MISSING")?;
    let directory = Path::new(&context_file)
        .parent()
        .ok_or("HOST_RELEASE_CONTEXT_PARENT_MISSING")?;
    let path = directory.join("application-bundle.pb");
    let meta = std::fs::symlink_metadata(&path).map_err(|_| "HOST_APPLICATION_BUNDLE_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 8 * 1024 * 1024 {
        return Err("HOST_APPLICATION_BUNDLE_INVALID_FILE".to_owned());
    }
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|_| "HOST_APPLICATION_BUNDLE_UNREADABLE")?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_APPLICATION_BUNDLE_UNREADABLE")?;
    edge_shared_types::host_lifecycle::native_vm_bundle_runtime_digest(release, &bytes)
        .map_err(str::to_owned)
}

/// Read-only scope validation. This intentionally never authenticates the
/// runner copy: native attestation is a separate, still-unimplemented gate.
fn validate_readback_scope(
    host: &edge_shared_types::FleetHost,
    observed: &edge_shared_types::FleetNativeObservation,
    expected_release_set_sha256: &str,
    expected_vm_logical_sha256: Option<&[u8]>,
    now: u64,
) -> Result<&'static str, String> {
    use edge_shared_types::{FleetNativeOwnerState, FleetNativeReleaseProof};
    if host.kind != observed.host_kind {
        return Err("HOST_READBACK_KIND_MISMATCH".to_owned());
    }
    if observed.observed_at_unix > now.saturating_add(60)
        || now.saturating_sub(observed.observed_at_unix) > 300
    {
        return Err("HOST_READBACK_STALE_OR_FUTURE".to_owned());
    }
    let kind = ManagedHostKind::try_from(host.kind).map_err(|_| "HOST_READBACK_KIND_INVALID")?;
    let proof = FleetNativeReleaseProof::try_from(observed.release_proof)
        .map_err(|_| "HOST_READBACK_PROOF_INVALID")?;
    let owner = FleetNativeOwnerState::try_from(observed.owner_state)
        .map_err(|_| "HOST_READBACK_OWNER_INVALID")?;
    if owner == FleetNativeOwnerState::Unproven
        || proof == FleetNativeReleaseProof::Unproven
        || !observed.reason_codes.is_empty()
    {
        return Ok("UNPROVEN_NATIVE_OWNER_OR_RUNTIME");
    }
    if kind == ManagedHostKind::Windows {
        if proof != FleetNativeReleaseProof::ActivationRecord {
            return Ok("WINDOWS_ACTIVATION_UNPROVEN");
        }
        let expected = exact_hex_sha256(expected_release_set_sha256)?;
        if observed.observed_release_sha256 != expected {
            return Ok("WINDOWS_RELEASESET_MISMATCH");
        }
    } else if proof == FleetNativeReleaseProof::VerifiedAbsent {
        return Ok("VM_RELEASE_ABSENT_LOCAL_ONLY");
    } else if proof == FleetNativeReleaseProof::ApplicationBundle {
        let expected = match expected_vm_logical_sha256 {
            Some(digest) if digest.len() == 32 => digest,
            _ => return Ok("VM_EXPECTED_BUNDLE_UNPROVEN"),
        };
        if observed.observed_release_sha256 != expected {
            return Ok("VM_BUNDLE_LOGICAL_DIGEST_MISMATCH");
        }
    } else {
        return Ok("VM_RELEASE_PROOF_UNPROVEN");
    }
    if !observed.runtime_ready_proven || !observed.runtime_ready {
        return Ok("UNPROVEN_RUNTIME_READINESS");
    }
    Ok("LOCAL_OBSERVATION_ONLY_NOT_PHYSICAL_ACCEPTANCE")
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
    exact_registry_sha256: &[u8],
    runner_json: Option<&Path>,
    output: Option<&Path>,
    source_comment_id: Option<u64>,
    intent_output: Option<&Path>,
    resource_id: Option<&str>,
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
    let comment_id = source_comment_id
        .filter(|id| *id != 0)
        .ok_or("HOST_SOURCE_COMMENT_REQUIRED")?;
    let intent_path = intent_output.ok_or("HOST_INTENT_OUTPUT_REQUIRED")?;
    // Read *the checked-out protected Git spec*, not an operator-supplied file.
    // This binds the intent to the exact desired bytes; JSON remains an
    // explicit conversion debt for acceptance hosts, not an alternative source.
    let spec_path = Path::new(&selected.desired_spec_path);
    let meta = std::fs::symlink_metadata(spec_path).map_err(|_| "HOST_DESIRED_SPEC_MISSING")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 1_048_576 {
        return Err("HOST_DESIRED_SPEC_INVALID_FILE".to_owned());
    }
    let spec_bytes = std::fs::read(spec_path).map_err(|_| "HOST_DESIRED_SPEC_UNREADABLE")?;
    let desired_sha = edge_shared_types::host_lifecycle::digest_host_desired(selected, &spec_bytes)
        .map_err(str::to_owned)?;
    let release_sha = exact_hex_sha256(expected_release_set_sha256)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "HOST_CLOCK_UNAVAILABLE")?
        .as_secs();
    let intent = FleetHostIntent {
        schema_version: 1,
        machine_id: machine_id.to_owned(),
        kind: kind as i32,
        resource_id: resource_id.unwrap_or("sing-box").to_owned(),
        operation_id: format!("issue1-comment-{comment_id}"),
        action: match operation {
            HostLifecycleOperation::Apply => FleetHostAction::Apply as i32,
            HostLifecycleOperation::Recover => FleetHostAction::Recover as i32,
        },
        registry_sha256: exact_registry_sha256.to_vec(),
        desired_sha256: desired_sha.clone(),
        release_set_sha256: release_sha.clone(),
        requested_mode: FleetHostMode::Unspecified as i32,
        requested_at_unix: now,
    };
    validate_host_intent(
        &intent,
        desired,
        exact_registry_sha256,
        &desired_sha,
        &release_sha,
    )
    .map_err(str::to_owned)?;
    // The same durable Git target is checked at PREPARE and again by
    // the native root/SYSTEM owner before any action. An observe-only VM
    // must never issue a misleading APPLY_PREPARED intent.
    validate_intent_against_target(&intent, desired).map_err(str::to_owned)?;
    let prepared = prepared_host_result(&intent);
    validate_host_result(&prepared, &intent).map_err(str::to_owned)?;
    let bytes = intent.encode_to_vec();
    // Exclusive create: an uncertain or duplicate request cannot clobber
    // an existing typed intent/receipt. No SYSTEM/root action is invoked.
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(intent_path)
        .map_err(|_| "HOST_INTENT_ALREADY_EXISTS_OR_UNWRITABLE")?;
    writer
        .write_all(&bytes)
        .map_err(|_| "HOST_INTENT_WRITE_FAILED")?;
    writer.sync_all().map_err(|_| "HOST_INTENT_SYNC_FAILED")?;
    let receipt_path = intent_path.with_extension("receipt.pb");
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)
        .map_err(|_| "HOST_PREPARED_RECEIPT_EXISTS_OR_UNWRITABLE")?;
    receipt
        .write_all(&prepared.encode_to_vec())
        .map_err(|_| "HOST_PREPARED_RECEIPT_WRITE_FAILED")?;
    receipt
        .sync_all()
        .map_err(|_| "HOST_PREPARED_RECEIPT_SYNC_FAILED")?;
    println!("host_intent_schema=1");
    println!("host_operation_id={}", intent.operation_id);
    println!(
        "host_intent_sha256={}",
        digest(&SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("host_intent_state=PREPARED_NOT_AUTHORIZED");
    println!("host_machine_id={machine_id}");
    println!("host_kind={kind:?}");
    println!("host_runner_registration={registration}");
    println!("host_lifecycle_contract=FRESH_TYPED_ONLY");
    println!("host_expected_release_set_sha256={expected_release_set_sha256}");
    println!("host_desired_spec_path={}", selected.desired_spec_path);
    print_host_target(selected)?;
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

fn print_host_target(host: &edge_shared_types::FleetHost) -> Result<(), String> {
    match &host.target {
        None => {
            println!("host_desired_run_state=UNSET_OBSERVE_ONLY");
            println!("host_desired_windows_mode=UNSET");
        }
        Some(target) => {
            use edge_shared_types::{FleetHostMode, FleetHostRunState};
            let state = FleetHostRunState::try_from(target.run_state)
                .map_err(|_| "HOST_TARGET_RUN_STATE_INVALID")?;
            let mode = FleetHostMode::try_from(target.windows_mode)
                .map_err(|_| "HOST_TARGET_MODE_INVALID")?;
            if state == FleetHostRunState::Unspecified {
                return Err("HOST_TARGET_RUN_STATE_REQUIRED".to_owned());
            }
            println!("host_desired_run_state={state:?}");
            println!("host_desired_windows_mode={mode:?}");
        }
    }
    Ok(())
}

fn exact_hex_sha256(value: &str) -> Result<Vec<u8>, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("HOST_RELEASE_SHA256_INVALID".to_owned());
    }
    (0..32)
        .map(|idx| {
            u8::from_str_radix(&value[idx * 2..idx * 2 + 2], 16)
                .map_err(|_| "HOST_RELEASE_SHA256_INVALID".to_owned())
        })
        .collect()
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
    fn release_set_bundle_digest_is_verified_by_exact_immutable_bytes() {
        let mut release = edge_shared_types::ReleaseSet::default();
        release.schema_version = 7;
        release.vm_runtime = Some(edge_shared_types::VmRuntime {
            application_bundle_sha256: vec![4; 32],
            ..Default::default()
        });
        let bytes = release.encode_to_vec();
        let sha = digest(&SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = std::env::temp_dir().join(format!(
            "sing-box-vm-release-set-test-{}.pb",
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let parsed = verified_release_set_bytes(&path, &sha).unwrap();
        assert_eq!(
            parsed.vm_runtime.unwrap().application_bundle_sha256,
            vec![4; 32]
        );
        assert_eq!(
            verified_release_set_bytes(&path, &"a".repeat(64)).unwrap_err(),
            "HOST_RELEASESET_DIGEST_MISMATCH"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn native_readback_never_authorizes_mutation_or_conflates_vm_digest() {
        use edge_shared_types::{
            FleetHost, FleetHostKind, FleetNativeObservation, FleetNativeOwnerState,
            FleetNativeReleaseProof,
        };
        let host = FleetHost {
            machine_id: "windows-1".into(),
            kind: FleetHostKind::Windows as i32,
            owner: Some(managed_host::Owner::WindowsRunnerName("WIN-1".into())),
            windows_runner_label: "windows-1".into(),
            vm_containers: Vec::new(),
            desired_spec_path: "infra/production/production.textproto".into(),
            target: None,
        };
        let mut o = FleetNativeObservation {
            schema_version: 1,
            host_kind: FleetHostKind::Windows as i32,
            observed_at_unix: 1000,
            owner_state: FleetNativeOwnerState::Running as i32,
            release_proof: FleetNativeReleaseProof::ActivationRecord as i32,
            observed_release_sha256: vec![0xaa; 32],
            runtime_ready: true,
            runtime_ready_proven: true,
            reason_codes: vec![],
        };
        assert_eq!(
            validate_readback_scope(&host, &o, &"a".repeat(64), None, 1000).unwrap(),
            "LOCAL_OBSERVATION_ONLY_NOT_PHYSICAL_ACCEPTANCE"
        );
        o.observed_release_sha256 = vec![0xbb; 32];
        assert_eq!(
            validate_readback_scope(&host, &o, &"a".repeat(64), None, 1000).unwrap(),
            "WINDOWS_RELEASESET_MISMATCH"
        );
        o.host_kind = FleetHostKind::Vm as i32;
        assert_eq!(
            validate_readback_scope(&host, &o, &"a".repeat(64), None, 1000).unwrap_err(),
            "HOST_READBACK_KIND_MISMATCH"
        );
        o.host_kind = FleetHostKind::Windows as i32;
        assert_eq!(
            validate_readback_scope(&host, &o, &"a".repeat(64), None, 1400).unwrap_err(),
            "HOST_READBACK_STALE_OR_FUTURE"
        );
        let vm_host = FleetHost {
            kind: FleetHostKind::Vm as i32,
            owner: Some(managed_host::Owner::VmMachineId("vm-1".into())),
            machine_id: "vm-1".into(),
            windows_runner_label: String::new(),
            ..host
        };
        o.host_kind = FleetHostKind::Vm as i32;
        o.release_proof = FleetNativeReleaseProof::ApplicationBundle as i32;
        o.observed_at_unix = 1400;
        assert_eq!(
            validate_readback_scope(&vm_host, &o, &"a".repeat(64), Some(&[0xbb; 32]), 1400)
                .unwrap(),
            "LOCAL_OBSERVATION_ONLY_NOT_PHYSICAL_ACCEPTANCE"
        );
        assert_eq!(
            validate_readback_scope(&vm_host, &o, &"a".repeat(64), Some(&[0xaa; 32]), 1400)
                .unwrap(),
            "VM_BUNDLE_LOGICAL_DIGEST_MISMATCH"
        );
        assert_eq!(
            validate_readback_scope(&vm_host, &o, &"a".repeat(64), None, 1400).unwrap(),
            "VM_EXPECTED_BUNDLE_UNPROVEN"
        );
    }

    #[test]
    fn fresh_host_apply_and_recover_never_admit_historical_mutation() {
        let spec = std::env::temp_dir().join(format!("sing-box-host-spec-{}", std::process::id()));
        std::fs::write(&spec, b"schema_version: 1\\n").unwrap();
        let desired = HostRegistry {
            schema_version: 1,
            hosts: vec![ManagedHost {
                machine_id: "windows-test".to_owned(),
                kind: ManagedHostKind::Windows as i32,
                owner: Some(managed_host::Owner::WindowsRunnerName(
                    "DESKTOP-TEST".to_owned(),
                )),
                windows_runner_label: "windows-test".to_owned(),
                vm_containers: Vec::new(),
                desired_spec_path: spec.to_string_lossy().into_owned(),
                target: Some(edge_shared_types::FleetHostTarget {
                    run_state: edge_shared_types::FleetHostRunState::Stopped as i32,
                    windows_mode: FleetHostMode::ProxyOnly as i32,
                }),
            }],
        };
        let release = "a".repeat(64);
        let registry_sha = vec![3u8; 32];
        let intent_path =
            std::env::temp_dir().join(format!("sing-box-host-intent-{}.pb", std::process::id()));
        let file = std::env::temp_dir().join(format!(
            "sing-box-host-fresh-preflight-{}",
            std::process::id()
        ));
        std::fs::write(&file, "").unwrap();
        // Absence of Git target is OBSERVE_ONLY, even if a healthy runner
        // has registered itself or an older VM deployment exists.
        let mut blocked = desired.clone();
        blocked.hosts[0].target = None;
        assert_eq!(
            host_lifecycle_admission(
                &blocked,
                "windows-test",
                HostLifecycleOperation::Apply,
                &release,
                &registry_sha,
                None,
                Some(&file),
                Some(122),
                Some(&intent_path),
                None,
            )
            .unwrap_err(),
            "HOST_TARGET_UNSET_OBSERVE_ONLY"
        );
        assert!(!intent_path.exists());
        // An invalid mode/kind must not emit any proposal either.
        blocked.hosts[0].target = Some(edge_shared_types::FleetHostTarget {
            run_state: edge_shared_types::FleetHostRunState::Stopped as i32,
            windows_mode: FleetHostMode::Unspecified as i32,
        });
        assert_eq!(
            host_lifecycle_admission(
                &blocked,
                "windows-test",
                HostLifecycleOperation::Apply,
                &release,
                &registry_sha,
                None,
                Some(&file),
                Some(122),
                Some(&intent_path),
                None,
            )
            .unwrap_err(),
            "HOST_TARGET_MODE_KIND_MISMATCH"
        );
        assert!(!intent_path.exists());
        host_lifecycle_admission(
            &desired,
            "windows-test",
            HostLifecycleOperation::Apply,
            &release,
            &registry_sha,
            None,
            Some(&file),
            Some(123),
            Some(&intent_path),
            None,
        )
        .unwrap();
        let apply = std::fs::read_to_string(&file).unwrap();
        assert!(apply.contains("operation=APPLY_PREFLIGHT"));
        assert!(apply.contains("host_targets_present=true"));
        assert!(!apply.contains("admitted_at_unix="));
        assert!(!apply.contains("operation=APPLY\\n"));
        let parsed = edge_shared_types::host_lifecycle::decode_host_intent(
            &std::fs::read(&intent_path).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.operation_id, "issue1-comment-123");
        assert_eq!(parsed.action, FleetHostAction::Apply as i32);
        std::fs::remove_file(&intent_path).unwrap();
        std::fs::remove_file(intent_path.with_extension("receipt.pb")).unwrap();
        std::fs::write(&file, "").unwrap();
        host_lifecycle_admission(
            &desired,
            "windows-test",
            HostLifecycleOperation::Recover,
            &release,
            &registry_sha,
            None,
            Some(&file),
            Some(124),
            Some(&intent_path),
            None,
        )
        .unwrap();
        let recover = std::fs::read_to_string(&file).unwrap();
        assert!(recover.contains("operation=RECOVER_PREFLIGHT"));
        assert!(!recover.contains("admitted_at_unix="));
        assert!(
            host_lifecycle_admission(
                &desired,
                "not-enrolled",
                HostLifecycleOperation::Apply,
                &release,
                &registry_sha,
                None,
                Some(&file),
                Some(125),
                Some(&intent_path),
                None,
            )
            .is_err()
        );
        std::fs::remove_file(file).unwrap();
        std::fs::remove_file(spec).unwrap();
        std::fs::remove_file(&intent_path).unwrap();
        std::fs::remove_file(intent_path.with_extension("receipt.pb")).unwrap();
    }

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
                    vm_containers: Vec::new(),
                    desired_spec_path: "infra/application/disposable-acceptance.json".to_owned(),
                    target: None,
                },
                ManagedHost {
                    machine_id: "sing-box-windows-lab".to_owned(),
                    kind: ManagedHostKind::Windows as i32,
                    owner: Some(managed_host::Owner::WindowsRunnerName(
                        "DESKTOP-0E1F6UQ".to_owned(),
                    )),
                    windows_runner_label: "sing-box-windows-lab".to_owned(),
                    vm_containers: Vec::new(),
                    desired_spec_path: "infra/production/production.textproto".to_owned(),
                    target: None,
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
            vm_containers: Vec::new(),
            desired_spec_path: "infra/production/production.textproto".to_owned(),
            target: None,
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
