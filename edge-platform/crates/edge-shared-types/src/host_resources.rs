//! One typed, bounded VM resource diagnostic. Data from the runner is
//! STRUCTURAL EVIDENCE only, not authenticated native owner attestation.
use crate::{
    FleetHost, FleetHostKind, FleetVmConfigProof, FleetVmDesiredGraph, FleetVmNetworkReadback,
    FleetVmResourceReadback, FleetVmResourceReport,
};
use prost::Message;
use std::net::IpAddr;

pub const MAX_VM_RESOURCE_REPORT_BYTES: usize = 32768;

/// Validate the exact per-resource graph that the existing root Agent
/// derives from installed Compose, image pins and templates. Validation
/// alone is not authorization to mutate any resource.
pub fn validate_vm_desired_graph(
    graph: &FleetVmDesiredGraph,
    host: &FleetHost,
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || graph.schema_version != 1
        || graph.machine_id != host.machine_id
        || graph.resources.is_empty()
        || graph.resources.len() != host.vm_containers.len()
        || graph.networks.is_empty()
        || graph.networks.len() > 16
        || graph.encode_to_vec().len() > 16384
    {
        return Err("VM_GRAPH_SCOPE_INVALID");
    }
    // All network membership is typed, bounded and tied to exact Compose
    // project ownership. Missing/default networks, foreign Mesh attachments,
    // duplicate names and unused networks cannot silently enter a release.
    let mut network_names = std::collections::BTreeSet::new();
    let mut network_membership = std::collections::BTreeSet::new();
    let project = &host.vm_containers[0].compose_project;
    for network in &graph.networks {
        if network.compose_project != *project
            || network.driver != "bridge"
            || network.network_name.is_empty()
            || network.network_name.len() > 64
            || !network
                .network_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || network.network_name == "mesh_net"
            || !network_names.insert(network.network_name.as_str())
            || network.attached_services.is_empty()
        {
            return Err("VM_GRAPH_NETWORK_SCOPE_INVALID");
        }
        let mut members = std::collections::BTreeSet::new();
        for service in &network.attached_services {
            if !host
                .vm_containers
                .iter()
                .any(|item| &item.compose_service == service)
                || !members.insert(service.as_str())
                || !network_membership.insert(service.as_str())
            {
                // Current native lifecycle deliberately permits one owned
                // network per registered container, never implicit multi-net.
                return Err("VM_GRAPH_NETWORK_MEMBERSHIP_INVALID");
            }
        }
    }
    if network_membership.len() != host.vm_containers.len() {
        return Err("VM_GRAPH_NETWORK_MEMBERSHIP_INCOMPLETE");
    }
    let mut unique = std::collections::BTreeSet::new();
    for (row, selector) in graph.resources.iter().zip(&host.vm_containers) {
        if row.resource.as_ref() != Some(selector)
            || !unique.insert(selector.compose_service.as_str())
            || row.image_ref.len() > 256
            || !row
                .image_ref
                .rsplit_once("@sha256:")
                .is_some_and(|(name, sha)| {
                    !name.is_empty()
                        && sha.len() == 64
                        && sha.bytes().all(|b| b.is_ascii_hexdigit())
                })
            || row.dependencies.len() > graph.resources.len()
        {
            return Err("VM_GRAPH_RESOURCE_INVALID");
        }
        match selector.compose_service.as_str() {
            "line1-gateway" | "line2-proxy"
                if row.config_template_sha256.len() != 32
                    || row.config_template_sha256.iter().all(|b| *b == 0) =>
            {
                return Err("VM_GRAPH_CONFIG_MISSING");
            }
            "warp-egress" if !row.config_template_sha256.is_empty() => {
                return Err("VM_GRAPH_WARP_CONFIG_FOREIGN");
            }
            _ if !row.config_template_sha256.is_empty()
                && (row.config_template_sha256.len() != 32
                    || row.config_template_sha256.iter().all(|b| *b == 0)) =>
            {
                return Err("VM_GRAPH_CONFIG_INVALID");
            }
            _ => {}
        }
        let mut deps = std::collections::BTreeSet::new();
        for dep in &row.dependencies {
            if dep == &selector.compose_service
                || !host
                    .vm_containers
                    .iter()
                    .any(|item| item.compose_service == *dep)
                || !deps.insert(dep)
            {
                return Err("VM_GRAPH_DEPENDENCY_INVALID");
            }
        }
    }
    let mut settled = std::collections::BTreeSet::new();
    while settled.len() < graph.resources.len() {
        let before = settled.len();
        for resource in &graph.resources {
            let name = resource.resource.as_ref().unwrap().compose_service.as_str();
            if !settled.contains(name)
                && resource
                    .dependencies
                    .iter()
                    .all(|dep| settled.contains(dep.as_str()))
            {
                settled.insert(name);
            }
        }
        if settled.len() == before {
            return Err("VM_GRAPH_DEPENDENCY_CYCLE");
        }
    }
    Ok(())
}

/// Stable hierarchical path of a registered VM resource. The identity is
/// derived from the sole FleetHost selector; a runner does not choose it.
pub fn vm_container_resource_id(
    host: &FleetHost,
    selector: &crate::FleetVmContainer,
) -> Result<String, &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || !host.vm_containers.contains(selector)
        || selector.compose_project.is_empty()
        || selector.compose_service.is_empty()
    {
        return Err("VM_RESOURCE_ID_NOT_REGISTERED");
    }
    Ok(format!(
        "container/{}/{}",
        selector.compose_project, selector.compose_service
    ))
}

fn vm_network_resource_id(project: &str, name: &str) -> String {
    format!("network/{project}/{name}")
}

fn vm_config_resource_id(project: &str, service: &str) -> String {
    format!("config/{project}/{service}")
}

fn vm_host_resource_id(host: &FleetHost) -> String {
    format!("host/{}", host.machine_id)
}

/// A PURE hierarchy projection: host -> networks/containers -> config
/// children. Container-to-network and Compose dependency edges remain
/// explicit and typed. A missing/foreign edge blocks the whole projection;
/// only known native owners appear and no mutation authority is conferred.
/// One Worker-owned CredentialRef is a real dependency of the two
/// sing-box gateways. It is NOT a second secret store, a generated value,
/// an owner attestation or a permission for the VM root to issue credentials.
fn vm_worker_credential_resource_id(host: &FleetHost) -> String {
    format!("credential/{}/application-v2", host.machine_id)
}

pub fn derive_vm_resource_hierarchy(
    host: &FleetHost,
    desired: &FleetVmDesiredGraph,
) -> Result<crate::FleetResourceHierarchy, &'static str> {
    use crate::FleetResourceHierarchy;
    validate_vm_desired_graph(desired, host)?;
    let nodes = project_vm_hierarchy_nodes_unchecked(host, desired)?;
    let graph = FleetResourceHierarchy {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        nodes,
        owner_attested: false,
        mutation_authorized: false,
    };
    validate_vm_resource_hierarchy(&graph, host, desired)?;
    Ok(graph)
}

/// Binds every reported node to the precise Git desired projection, not a
/// caller-supplied parent, dependency list, or a forged owner attestation.
pub fn validate_vm_resource_hierarchy(
    observed: &crate::FleetResourceHierarchy,
    host: &FleetHost,
    desired: &FleetVmDesiredGraph,
) -> Result<(), &'static str> {
    validate_vm_desired_graph(desired, host)?;
    if observed.schema_version != 1
        || observed.machine_id != host.machine_id
        || observed.nodes.is_empty()
        || observed.nodes.len() > 128
        || observed.owner_attested
        || observed.mutation_authorized
        || observed.encode_to_vec().len() > 32768
    {
        return Err("VM_HIERARCHY_SCOPE_OR_AUTHORITY_INVALID");
    }
    // Recompute from exact policy without another source of truth. This
    // internal builder does not call this validator, preventing recursion.
    let mut unique = std::collections::BTreeSet::new();
    let mut seen = std::collections::BTreeSet::new();
    let all_ids = observed
        .nodes
        .iter()
        .map(|node| node.resource_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for node in &observed.nodes {
        let expected_owner = if node.kind == crate::FleetResourceKind::CredentialRef as i32 {
            crate::FleetResourceOwner::WorkerSecrets
        } else {
            crate::FleetResourceOwner::VmRootAgent
        };
        if !unique.insert(node.resource_id.as_str())
            || node.owner != expected_owner as i32
            || crate::FleetResourceKind::try_from(node.kind).is_err()
            || node.kind == crate::FleetResourceKind::Unspecified as i32
        {
            return Err("VM_HIERARCHY_NODE_IDENTITY_INVALID");
        }
        if node.parent_resource_id.is_empty() {
            if node.resource_id != vm_host_resource_id(host)
                || node.kind != crate::FleetResourceKind::Host as i32
                || !node.dependency_ids.is_empty()
            {
                return Err("VM_HIERARCHY_ROOT_INVALID");
            }
        } else if !seen.contains(node.parent_resource_id.as_str()) {
            return Err("VM_HIERARCHY_PARENT_NOT_FOUND_OR_UNORDERED");
        }
        // Dependencies are graph edges, not serialization order. A gateway
        // may depend on WARP declared later in the inventory. Cycles are
        // already rejected by validate_vm_desired_graph above.
        for dep in &node.dependency_ids {
            if !all_ids.contains(dep.as_str()) || dep == &node.resource_id {
                return Err("VM_HIERARCHY_DEPENDENCY_UNREGISTERED");
            }
        }
        if !node.expected_policy_sha256.is_empty()
            && (node.expected_policy_sha256.len() != 32
                || node.expected_policy_sha256.iter().all(|byte| *byte == 0))
        {
            return Err("VM_HIERARCHY_DIGEST_INVALID");
        }
        seen.insert(node.resource_id.as_str());
    }
    if observed.nodes[0].resource_id != vm_host_resource_id(host)
        || observed.nodes.len()
            != 2 + desired.networks.len()
                + desired.resources.len()
                + desired
                    .resources
                    .iter()
                    .filter(|r| !r.config_template_sha256.is_empty())
                    .count()
    {
        return Err("VM_HIERARCHY_INCOMPLETE");
    }
    // Exact parent, order, owner and dependency enforcement for each
    // independently immutable resource, rather than merely validating form.
    let expected = project_vm_hierarchy_nodes_unchecked(host, desired)?;
    if observed.nodes != expected {
        return Err("VM_HIERARCHY_POLICY_DRIFT");
    }
    Ok(())
}

fn project_vm_hierarchy_nodes_unchecked(
    host: &FleetHost,
    desired: &FleetVmDesiredGraph,
) -> Result<Vec<crate::FleetResourceNode>, &'static str> {
    use crate::{FleetResourceKind as Kind, FleetResourceNode, FleetResourceOwner as Owner};
    let root = vm_host_resource_id(host);
    let mut result = vec![FleetResourceNode {
        resource_id: root.clone(),
        kind: Kind::Host as i32,
        parent_resource_id: String::new(),
        dependency_ids: Vec::new(),
        owner: Owner::VmRootAgent as i32,
        expected_policy_sha256: Vec::new(),
    }];
    // The Provider of the credential is the Worker; projection and
    // process binding belong to the SAME VM root owner used for INSTALL.
    let worker_credential = vm_worker_credential_resource_id(host);
    result.push(FleetResourceNode {
        resource_id: worker_credential.clone(),
        kind: Kind::CredentialRef as i32,
        parent_resource_id: root.clone(),
        dependency_ids: Vec::new(),
        owner: Owner::WorkerSecrets as i32,
        expected_policy_sha256: Vec::new(),
    });
    let mut networks = std::collections::BTreeMap::<&str, &str>::new();
    for network in &desired.networks {
        for service in &network.attached_services {
            networks.insert(service, &network.network_name);
        }
        result.push(FleetResourceNode {
            resource_id: vm_network_resource_id(&network.compose_project, &network.network_name),
            kind: Kind::DockerNetwork as i32,
            parent_resource_id: root.clone(),
            dependency_ids: Vec::new(),
            owner: Owner::VmRootAgent as i32,
            expected_policy_sha256: ring::digest::digest(
                &ring::digest::SHA256,
                &network.encode_to_vec(),
            )
            .as_ref()
            .to_vec(),
        });
    }
    for resource in &desired.resources {
        let selector = resource
            .resource
            .as_ref()
            .ok_or("VM_HIERARCHY_SELECTOR_MISSING")?;
        let id = vm_container_resource_id(host, selector)?;
        let network = networks
            .get(&selector.compose_service.as_str())
            .ok_or("VM_HIERARCHY_NETWORK_DEPENDENCY_MISSING")?;
        let mut dependencies = vec![vm_network_resource_id(&selector.compose_project, network)];
        if matches!(
            selector.compose_service.as_str(),
            "line1-gateway" | "line2-proxy"
        ) {
            dependencies.push(worker_credential.clone());
        }
        for dependency in &resource.dependencies {
            let s = host
                .vm_containers
                .iter()
                .find(|v| v.compose_service == *dependency)
                .ok_or("VM_HIERARCHY_FOREIGN_CONTAINER_DEPENDENCY")?;
            dependencies.push(vm_container_resource_id(host, s)?);
        }
        dependencies.sort();
        dependencies.dedup();
        result.push(FleetResourceNode {
            resource_id: id.clone(),
            kind: Kind::DockerContainer as i32,
            parent_resource_id: root.clone(),
            dependency_ids: dependencies,
            owner: Owner::VmRootAgent as i32,
            expected_policy_sha256: ring::digest::digest(
                &ring::digest::SHA256,
                &resource.encode_to_vec(),
            )
            .as_ref()
            .to_vec(),
        });
        if !resource.config_template_sha256.is_empty() {
            result.push(FleetResourceNode {
                resource_id: vm_config_resource_id(
                    &selector.compose_project,
                    &selector.compose_service,
                ),
                kind: Kind::SingboxConfig as i32,
                parent_resource_id: id.clone(),
                dependency_ids: vec![id],
                owner: Owner::VmRootAgent as i32,
                expected_policy_sha256: resource.config_template_sha256.clone(),
            });
        }
    }
    Ok(result)
}

/// Deterministic resource policy diff. "Installed" is the protected
/// root-local bundle, not Docker physical proof. "Desired" is independently
/// compiled from the immutable, Git-owned ReleaseSet. This function never
/// accepts a runner authority or performs mutations.
pub fn propose_vm_graph_reconcile(
    host: &FleetHost,
    installed: &FleetVmDesiredGraph,
    desired: &FleetVmDesiredGraph,
) -> Result<crate::FleetVmGraphReconcile, &'static str> {
    use crate::{
        FleetResourceKind as Kind, FleetResourceOwner as Owner, FleetVmGraphReconcile,
        FleetVmGraphResourceChange, FleetVmPolicyChange,
    };
    let installed_hierarchy = derive_vm_resource_hierarchy(host, installed)?;
    let desired_hierarchy = derive_vm_resource_hierarchy(host, desired)?;
    // The root and network dependency identities are an invariant across
    // this image/config-only effector. A new network/dependency needs its
    // own native operation rather than falling through to Compose.
    if installed_hierarchy.nodes.len() != desired_hierarchy.nodes.len() {
        return Err("VM_RECONCILE_HIERARCHY_SCOPE_CHANGED");
    }
    if installed.networks != desired.networks {
        return Err("VM_RECONCILE_NETWORK_POLICY_REQUIRES_NATIVE_HANDLER");
    }
    // The source container order is the single canonical fleet order.
    // A dependency delta needs its own typed Docker/network lifecycle and
    // must never sneak through a config-only or image-only effector.
    let mut old_consumers = std::collections::BTreeMap::<&str, Vec<usize>>::new();
    let mut resources = Vec::with_capacity(desired.resources.len());
    for (index, (before, after)) in installed
        .resources
        .iter()
        .zip(&desired.resources)
        .enumerate()
    {
        if before.resource != after.resource || before.dependencies != after.dependencies {
            return Err("VM_RECONCILE_DEPENDENCY_OR_IDENTITY_CHANGED");
        }
        old_consumers
            .entry(&before.image_ref)
            .or_default()
            .push(index);
        let image_changed = before.image_ref != after.image_ref;
        let config_changed = before.config_template_sha256 != after.config_template_sha256;
        if image_changed && config_changed {
            return Err("VM_RECONCILE_COMBINED_IMAGE_AND_CONFIG_UNSUPPORTED");
        }
        let change = if image_changed {
            FleetVmPolicyChange::ImageReplaced
        } else if config_changed {
            FleetVmPolicyChange::ConfigTemplateReplaced
        } else {
            FleetVmPolicyChange::NoChange
        };
        let selector = after
            .resource
            .as_ref()
            .ok_or("VM_RECONCILE_RESOURCE_MISSING")?;
        let (resource_id, resource_kind) = if change == FleetVmPolicyChange::ConfigTemplateReplaced
        {
            (
                vm_config_resource_id(&selector.compose_project, &selector.compose_service),
                Kind::SingboxConfig,
            )
        } else {
            (
                vm_container_resource_id(host, selector)?,
                Kind::DockerContainer,
            )
        };
        let exact_node = desired_hierarchy
            .nodes
            .iter()
            .find(|node| node.resource_id == resource_id)
            .ok_or("VM_RECONCILE_RESOURCE_NODE_NOT_IN_GRAPH")?;
        if exact_node.kind != resource_kind as i32
            || exact_node.owner != Owner::VmRootAgent as i32
            || (resource_kind == Kind::SingboxConfig
                && exact_node.parent_resource_id != vm_container_resource_id(host, selector)?)
            || (resource_kind == Kind::DockerContainer
                && exact_node.parent_resource_id != vm_host_resource_id(host))
        {
            return Err("VM_RECONCILE_NODE_OWNER_OR_PARENT_INVALID");
        }
        resources.push(FleetVmGraphResourceChange {
            resource: after.resource.clone(),
            change: change as i32,
            expected_image_ref: after.image_ref.clone(),
            expected_config_template_sha256: after.config_template_sha256.clone(),
            resource_id,
            resource_kind: resource_kind as i32,
        });
    }
    // When several services share an old OCI image, replacing a subset
    // could start mixed releases under one logical image resource. All
    // consumers must move to the SAME immutable digest in one transaction.
    for consumers in old_consumers.values() {
        if consumers.len() > 1 {
            let replacements = consumers
                .iter()
                .map(|&index| &desired.resources[index].image_ref)
                .collect::<std::collections::BTreeSet<_>>();
            if replacements.len() != 1 {
                return Err("VM_RECONCILE_SHARED_IMAGE_PARTIAL_REPLACE");
            }
        }
    }
    Ok(FleetVmGraphReconcile {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        owner_attested: false,
        mutation_authorized: false,
    })
}

/// Local credential evidence is strictly non-secret and does not imply
/// authorized Worker delivery, successful TLS, or an installed signer receipt.
pub fn validate_vm_credential_readback(
    readback: &crate::FleetVmCredentialReadback,
) -> Result<(), &'static str> {
    use crate::FleetVmCredentialState as State;
    let state = State::try_from(readback.state).map_err(|_| "VM_CREDENTIAL_STATE_INVALID")?;
    match state {
        State::ActiveLocalValid if readback.active_generation > 0 => Ok(()),
        State::CandidateOnly
            if readback.active_generation == 0 && readback.candidate_generation > 0 =>
        {
            Ok(())
        }
        State::StoreAbsent | State::LegacyPresent | State::Unproven
            if readback.active_generation == 0 && readback.candidate_generation == 0 =>
        {
            Ok(())
        }
        _ => Err("VM_CREDENTIAL_READBACK_INCONSISTENT"),
    }
}

/// A single typed explanation for first-use prerequisites. This never
/// authorizes provisioning, install or a new journal BEGIN.
pub fn vm_bootstrap_next_action(phase: crate::FleetVmBootstrapPhase) -> &'static str {
    use crate::FleetVmBootstrapPhase as Phase;
    match phase {
        Phase::Unspecified => "UPDATE_INSTALLED_NATIVE_OWNER_FOR_TYPED_BOOTSTRAP_EVIDENCE",
        Phase::TrustUnproven => "ENROLL_TRUST_THROUGH_EXISTING_ROOT_OWNER",
        Phase::JournalUnknownNoReplay => "RECONCILE_UNRESOLVED_NATIVE_JOURNAL_READ_ONLY",
        Phase::ReceiptKeyGitRegistrationRequired => {
            "REGISTER_NATIVE_RECEIPT_PUBLIC_KEY_IN_PROTECTED_GIT"
        }
        Phase::ReceiptKeyMismatchOrUnproven => "VERIFY_NATIVE_RECEIPT_IDENTITY_WITH_ROOT_OWNER",
        Phase::WorkerActiveCredentialRequired => {
            "COMPLETE_WORKER_V2_FIRST_USE_ACTIVE_CREDENTIAL_DELIVERY"
        }
        Phase::LocalPrerequisitesOnly => "VERIFY_WORKER_SIGNER_NATIVE_RECEIPT_AND_PHYSICAL_STATE",
        Phase::FirstUseWorkerSourceUnverified => {
            "VERIFY_GIT_PINNED_WORKER_BUNDLE_DURING_SIGNED_INSTALL"
        }
        Phase::FirstUseGitSourceRequired => {
            "PUBLISH_WORKER_BUNDLE_AND_PIN_FIRST_USE_IDENTITY_IN_GIT"
        }
        Phase::FirstUseWorkerSourceVerifiedLocal => {
            "REQUEST_FRESH_SIGNED_INSTALL_WITH_INDEPENDENT_NATIVE_RECEIPT"
        }
        Phase::FirstUseWorkerSourceMismatch => {
            "RECONCILE_WORKER_BUNDLE_AND_GIT_IDENTITY_WITHOUT_LOCAL_MUTATION"
        }
        Phase::FirstUseWorkerSourceUnavailable => "VERIFY_WORKER_ACCESS_OR_GENERATION_READ_ONLY",
    }
}

fn validate_vm_bootstrap_phase(
    phase: i32,
    host: &FleetHost,
    credential: &crate::FleetVmCredentialReadback,
) -> Result<(), &'static str> {
    use crate::{FleetVmBootstrapPhase as Phase, FleetVmCredentialState as State};
    let phase = Phase::try_from(phase).map_err(|_| "VM_BOOTSTRAP_PHASE_UNKNOWN")?;
    let git_key = host.native_receipt_public_key.as_slice();
    let git_pinned = git_key.len() == 32 && git_key.iter().any(|byte| *byte != 0);
    let active =
        credential.state == State::ActiveLocalValid as i32 && credential.active_generation > 0;
    let consistent = match phase {
        // Old installed owners only express unavailable bootstrap evidence.
        Phase::Unspecified | Phase::TrustUnproven | Phase::JournalUnknownNoReplay => true,
        // The locally installed root may still hold the pre-merge trust snapshot.
        // A read-only runner copy of that phase is valid after protected Git
        // registration, but never authenticates the owner or authorizes INSTALL.
        // An invalid nonempty Git key is still rejected.
        Phase::ReceiptKeyGitRegistrationRequired => git_key.is_empty() || git_pinned,
        Phase::ReceiptKeyMismatchOrUnproven => git_pinned,
        Phase::WorkerActiveCredentialRequired => {
            git_pinned && !active && credential.state != State::StoreAbsent as i32
        }
        Phase::LocalPrerequisitesOnly => git_pinned && active,
        Phase::FirstUseWorkerSourceUnverified
        | Phase::FirstUseWorkerSourceVerifiedLocal
        | Phase::FirstUseWorkerSourceMismatch
        | Phase::FirstUseWorkerSourceUnavailable => {
            git_pinned
                && credential.state == State::StoreAbsent as i32
                && host.vm_first_use_credential.is_some()
        }
        Phase::FirstUseGitSourceRequired => {
            git_pinned
                && credential.state == State::StoreAbsent as i32
                && host.vm_first_use_credential.is_none()
        }
    };
    if !consistent {
        return Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT");
    }
    Ok(())
}

/// Full /proc metadata is read-only, never a trusted remote receipt. Bound
/// size, sorted uniqueness and redacted error codes prevent a compromised
/// runner from injecting arbitrary text or claiming a complete scan.
pub fn validate_vm_process_snapshot(
    snapshot: &crate::FleetVmProcessSnapshot,
) -> Result<(), &'static str> {
    if snapshot.processes.len() > 4096
        || snapshot.observed_count < snapshot.processes.len() as u32
        || snapshot.truncated != (snapshot.observed_count > snapshot.processes.len() as u32)
        || (!snapshot.procfs_readable
            && (!snapshot.processes.is_empty() || snapshot.observed_count != 0))
        || snapshot.read_error_count > snapshot.processes.len() as u32
    {
        return Err("VM_PROCESS_SNAPSHOT_SCOPE_INVALID");
    }
    let mut prev = 0u32;
    let mut errors = 0u32;
    for process in &snapshot.processes {
        let ok_state = matches!(
            process.state_code.as_str(),
            "R" | "S" | "D" | "Z" | "T" | "I" | "X" | "W" | "K" | "P" | "?"
        );
        if process.pid == 0 || process.pid <= prev || !ok_state {
            return Err("VM_PROCESS_SNAPSHOT_ORDER_OR_STATE_INVALID");
        }
        prev = process.pid;
        if process.read_error_code.is_empty() {
            if process.command_name_sha256.len() != 32
                || process.command_name_sha256.iter().all(|b| *b == 0)
                || process.state_code == "?"
            {
                return Err("VM_PROCESS_SNAPSHOT_COMMAND_PROOF_INVALID");
            }
        } else {
            errors += 1;
            if !matches!(
                process.read_error_code.as_str(),
                "STAT_UNAVAILABLE" | "STAT_INVALID" | "METADATA_UNAVAILABLE"
            ) || !process.command_name_sha256.is_empty()
                || process.state_code != "?"
                || process.parent_pid != 0
            {
                return Err("VM_PROCESS_SNAPSHOT_ERROR_INVALID");
            }
        }
    }
    if errors != snapshot.read_error_count {
        return Err("VM_PROCESS_SNAPSHOT_ERROR_COUNT_INVALID");
    }
    Ok(())
}

pub fn validate_vm_resource_report(
    report: &FleetVmResourceReport,
    host: &FleetHost,
) -> Result<(), &'static str> {
    if host.kind != FleetHostKind::Vm as i32
        || report.schema_version != 2
        || report.remote_attested
        || report.machine_id != host.machine_id
        || report.observed_at_unix == 0
        || host.vm_containers.is_empty()
        || report.resources.len() != host.vm_containers.len()
        || report.encode_to_vec().len() > MAX_VM_RESOURCE_REPORT_BYTES
    {
        return Err("VM_RESOURCE_REPORT_SCOPE_INVALID");
    }
    if let Some(network) = report.network.as_ref() {
        validate_vm_network_readback(network)?;
    }
    if let Some(processes) = report.processes.as_ref() {
        validate_vm_process_snapshot(processes)?;
    }
    let credential = report
        .credential
        .as_ref()
        .ok_or("VM_CREDENTIAL_READBACK_REQUIRED")?;
    validate_vm_credential_readback(credential)?;
    validate_vm_bootstrap_phase(report.bootstrap_phase, host, credential)?;
    use crate::FleetVmInstalledPolicyStatus as Policy;
    let policy_status = Policy::try_from(report.installed_policy_status)
        .map_err(|_| "VM_INSTALLED_POLICY_STATUS_INVALID")?;
    match policy_status {
        Policy::Valid => {
            if !report.installed_policy_error_code.is_empty() {
                return Err("VM_INSTALLED_POLICY_SUCCESS_WITH_ERROR");
            }
            let installed = report
                .installed_policy_graph
                .as_ref()
                .ok_or("VM_INSTALLED_POLICY_GRAPH_MISSING")?;
            // Structural evidence only: this does not prove Git desired.
            derive_vm_resource_hierarchy(host, installed)?;
        }
        Policy::Unspecified => {
            if report.installed_policy_graph.is_some()
                || !report.installed_policy_error_code.is_empty()
            {
                return Err("VM_INSTALLED_POLICY_STATUS_UNPROVEN_CONFLICT");
            }
        }
        Policy::ComposeInvalid
        | Policy::ImageInvalid
        | Policy::NetworkInvalid
        | Policy::DependencyInvalid
        | Policy::ConfigInvalid
        | Policy::OtherInvalid => {
            if report.installed_policy_graph.is_some()
                || !valid_vm_policy_error_code(&report.installed_policy_error_code)
            {
                return Err("VM_INSTALLED_POLICY_FAILURE_INVALID");
            }
        }
    }
    // These bytes can be copied by an untrusted runner. Bound them and
    // reject foreign identities or claimed convergence without owner evidence.
    if report.managed_docker.len() > 64 {
        return Err("VM_MANAGED_DOCKER_READBACK_TOO_MANY");
    }
    let mut managed_names = std::collections::BTreeSet::new();
    for row in &report.managed_docker {
        if row.reason_code.is_empty()
            || row.reason_code.len() > 96
            || !row
                .reason_code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            || (row.present != row.ownership_proven)
            || (row.present != !row.fingerprint_sha256.is_empty())
            || (!row.fingerprint_sha256.is_empty() && row.fingerprint_sha256.len() != 32)
            || (row.converged && !row.reason_code.starts_with("DESIRED_"))
        {
            return Err("VM_MANAGED_DOCKER_EVIDENCE_INVALID");
        }
        if row.resource_name.is_empty() {
            if row.kind != 0
                || row.desired_state != 0
                || !row.manifest_sha256.is_empty()
                || row.present
                || row.converged
            {
                return Err("VM_MANAGED_DOCKER_UNSCOPED_EVIDENCE");
            }
        } else if !row
            .resource_name
            .starts_with(&format!("sb-{}-", host.machine_id))
            || row.resource_name.len() > 112
            || !managed_names.insert(row.resource_name.as_str())
            || row.manifest_sha256.len() != 32
            || !matches!(
                crate::FleetVmManagedDockerKind::try_from(row.kind),
                Ok(crate::FleetVmManagedDockerKind::LocalVolume
                    | crate::FleetVmManagedDockerKind::BridgeNetwork
                    | crate::FleetVmManagedDockerKind::Container)
            )
            || !matches!(
                crate::FleetVmManagedDockerDesiredState::try_from(row.desired_state),
                Ok(crate::FleetVmManagedDockerDesiredState::Present
                    | crate::FleetVmManagedDockerDesiredState::Absent
                    | crate::FleetVmManagedDockerDesiredState::Stopped)
            )
        {
            return Err("VM_MANAGED_DOCKER_RESOURCE_SCOPE_INVALID");
        }
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
            || (!row.last_exit_code_proven && row.last_exit_code != 0)
            || (!row.oom_killed_proven && row.oom_killed)
            || (!row.ownership_proven
                && (row.last_exit_code_proven
                    || row.oom_killed_proven
                    || row.docker_state_error_present
                    || row.runtime_failure_class
                        != crate::FleetVmRuntimeFailureClass::Unproven as i32))
            || (crate::FleetVmRuntimeFailureClass::try_from(row.runtime_failure_class).is_err())
            || (row.docker_state_error_present
                != (row.runtime_failure_class
                    != crate::FleetVmRuntimeFailureClass::Unproven as i32))
            || !config_proof_consistent(row, expected)
            || !reason_consistent(row)
        {
            return Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID");
        }
    }
    Ok(())
}

/// Strict bounds and relationships for runner-copied VM network bytes.
/// Structural validation NEVER authenticates their claimed source or proves
/// Internet/DNS/firewall policy convergence.
pub fn validate_vm_network_readback(network: &FleetVmNetworkReadback) -> Result<(), &'static str> {
    if network.dns_nameservers.len() > 8
        || network
            .dns_nameservers
            .iter()
            .any(|address| address.parse::<IpAddr>().is_err())
        || !network.dns_configuration_observed && !network.dns_nameservers.is_empty()
        || !network.nft_ruleset_observed
            && (!network.nft_ruleset_sha256.is_empty() || network.nft_rule_count != 0)
        || network.nft_ruleset_observed
            && (network.nft_ruleset_sha256.len() != 32
                || network.nft_ruleset_sha256.iter().all(|byte| *byte == 0))
    {
        return Err("VM_NETWORK_EVIDENCE_INVALID");
    }
    let mut nameservers = std::collections::BTreeSet::new();
    if network
        .dns_nameservers
        .iter()
        .any(|address| !nameservers.insert(address))
    {
        return Err("VM_NETWORK_DNS_DUPLICATE");
    }
    if let Some(kernel) = network.dual_stack.as_ref() {
        if !network.dual_stack_error_code.is_empty() {
            return Err("VM_DUAL_STACK_CONTRADICTORY_EVIDENCE");
        }
        validate_vm_dual_stack_network(kernel)?;
    } else if !network.dual_stack_error_code.is_empty()
        && (network.dual_stack_error_code.len() > 96
            || !network
                .dual_stack_error_code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    {
        return Err("VM_DUAL_STACK_ERROR_CODE_INVALID");
    }
    if let Some(ipv4) = &network.ipv4 {
        if ipv4.links.len() > 128
            || ipv4.addresses.len() > 256
            || ipv4.routes.len() > 512
            || ipv4.links.iter().any(|link| {
                link.interface_index == 0
                    || link.name.is_empty()
                    || link.name.len() > 64
                    || !link.name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'_' | b'.' | b'-' | b':' | b'@')
                    })
            })
            || ipv4.addresses.iter().any(|address| {
                address.address.parse::<std::net::Ipv4Addr>().is_err()
                    || address.prefix_length > 32
                    || !ipv4
                        .links
                        .iter()
                        .any(|link| link.interface_index == address.interface_index)
            })
            || ipv4.routes.iter().any(|route| {
                route.destination.parse::<std::net::Ipv4Addr>().is_err()
                    || route.prefix_length > 32
                    || route.output_interface_index != 0
                        && !ipv4
                            .links
                            .iter()
                            .any(|link| link.interface_index == route.output_interface_index)
                    || route
                        .preferred_source
                        .as_ref()
                        .is_some_and(|source| source.parse::<std::net::Ipv4Addr>().is_err())
            })
            || ipv4.encode_to_vec().len() > 24_576
        {
            return Err("VM_NETWORK_KERNEL_EVIDENCE_INVALID");
        }
    }
    Ok(())
}

/// Strict structural validator of untrusted runner-copied kernel data.
/// Real kernel provenance still requires a native signed owner receipt.
pub fn validate_vm_dual_stack_network(
    kernel: &crate::FleetVmDualStackNetwork,
) -> Result<(), &'static str> {
    use crate::FleetVmIpFamily as Family;
    if !kernel.ipv4_route_dump_complete
        || !kernel.ipv6_route_dump_complete
        || kernel.links.len() > 128
        || kernel.addresses.len() > 256
        || kernel.routes.len() > 512
        || kernel.encode_to_vec().len() > 24_576
    {
        return Err("VM_DUAL_STACK_DUMP_INCOMPLETE_OR_OVERSIZE");
    }
    let mut links = std::collections::BTreeSet::new();
    for link in &kernel.links {
        if link.interface_index == 0
            || link.name.is_empty()
            || link.name.len() > 64
            || !link
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':' | b'@'))
            || !links.insert(link.interface_index)
        {
            return Err("VM_DUAL_STACK_LINK_INVALID");
        }
    }
    let same_family =
        |family: i32, value: &str| match (Family::try_from(family), value.parse::<IpAddr>()) {
            (Ok(Family::V4), Ok(IpAddr::V4(_))) => true,
            (Ok(Family::V6), Ok(IpAddr::V6(_))) => true,
            _ => false,
        };
    for address in &kernel.addresses {
        if !links.contains(&address.interface_index)
            || !same_family(address.family, &address.address)
            || (address.family == Family::V4 as i32 && address.prefix_length > 32)
            || (address.family == Family::V6 as i32 && address.prefix_length > 128)
        {
            return Err("VM_DUAL_STACK_ADDRESS_INVALID");
        }
    }
    for route in &kernel.routes {
        if !same_family(route.family, &route.destination)
            || !route.gateway.is_empty() && !same_family(route.family, &route.gateway)
            || !route.preferred_source.is_empty()
                && !same_family(route.family, &route.preferred_source)
            || (route.family == Family::V4 as i32 && route.prefix_length > 32)
            || (route.family == Family::V6 as i32 && route.prefix_length > 128)
            || route.output_interface_index != 0 && !links.contains(&route.output_interface_index)
        {
            return Err("VM_DUAL_STACK_ROUTE_INVALID");
        }
    }
    Ok(())
}

fn valid_vm_policy_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code.starts_with("HOST_")
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn config_proof_consistent(
    row: &FleetVmResourceReadback,
    expected: &crate::FleetVmContainer,
) -> bool {
    let proof = FleetVmConfigProof::try_from(row.config_proof);
    let digest_valid =
        row.config_sha256.len() == 32 && row.config_sha256.iter().any(|byte| *byte != 0);
    match proof {
        Ok(FleetVmConfigProof::Unproven) => row.config_sha256.is_empty(),
        Ok(FleetVmConfigProof::NotApplicable) => {
            expected.compose_service == "warp-egress" && row.config_sha256.is_empty()
        }
        Ok(FleetVmConfigProof::NotRunning) => !row.running && row.config_sha256.is_empty(),
        Ok(FleetVmConfigProof::BoundRunningProcess) => {
            matches!(
                expected.compose_service.as_str(),
                "line1-gateway" | "line2-proxy"
            ) && row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && digest_valid
        }
        Err(_) => false,
    }
}

fn reason_consistent(row: &FleetVmResourceReadback) -> bool {
    use crate::FleetVmObservedReason as Reason;
    let reason = match Reason::try_from(row.observed_reason) {
        Ok(Reason::Unspecified) | Err(_) => return false,
        Ok(reason) => reason,
    };
    if row.reason_code
        != reason
            .as_str_name()
            .strip_prefix("FLEET_VM_OBSERVED_REASON_")
            .unwrap_or("")
    {
        return false;
    }
    match reason {
        Reason::ContainerAbsent => !row.present,
        Reason::DockerUnavailable | Reason::InspectUnavailable => !row.present,
        Reason::ForeignOwner => row.present && !row.ownership_proven,
        Reason::StateUnproven => row.present && row.ownership_proven && !row.running_proven,
        Reason::Healthy => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "HEALTHY"
        }
        Reason::HealthStarting => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "STARTING"
        }
        Reason::HealthUnhealthy => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health == "UNHEALTHY"
        }
        Reason::RunningNoHealthcheck | Reason::HealthUnproven => {
            row.present
                && row.ownership_proven
                && row.running_proven
                && row.running
                && row.health.is_empty()
        }
        Reason::Stopped => {
            row.present && row.ownership_proven && row.running_proven && !row.running
        }
        Reason::Unspecified => false,
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
            schema_version: 2,
            bootstrap_phase: crate::FleetVmBootstrapPhase::Unspecified as i32,
            processes: None,
            managed_docker: Vec::new(),
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
                observed_reason: crate::FleetVmObservedReason::Healthy as i32,
                health: "HEALTHY".into(),
                ..Default::default()
            }],
            remote_attested: false,
            network: None,
            installed_policy_graph: None,
            installed_policy_status: 0,
            installed_policy_error_code: String::new(),
            credential: Some(crate::FleetVmCredentialReadback {
                state: crate::FleetVmCredentialState::ActiveLocalValid as i32,
                active_generation: 42,
                ..Default::default()
            }),
        };
        (host, report)
    }
    #[test]
    fn container_exit_oom_and_failure_class_are_validated_as_closed_evidence() {
        use crate::FleetVmRuntimeFailureClass as Failure;
        let (host, mut report) = fixture();
        let row = &mut report.resources[0];
        row.last_exit_code = 137;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID")
        );
        let row = &mut report.resources[0];
        row.last_exit_code_proven = true;
        row.oom_killed = true;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID")
        );
        let row = &mut report.resources[0];
        row.oom_killed_proven = true;
        row.docker_state_error_present = true;
        row.runtime_failure_class = Failure::Permission as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].runtime_failure_class = 8888;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID")
        );
        report.resources[0].runtime_failure_class = Failure::Unproven as i32;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_RESOURCE_REPORT_EVIDENCE_INVALID")
        );
    }

    #[test]
    fn bootstrap_gate_is_typed_read_only_and_consistent_with_git_and_worker() {
        use crate::FleetVmBootstrapPhase as Phase;
        let (mut host, mut report) = fixture();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        assert_eq!(
            vm_bootstrap_next_action(Phase::Unspecified),
            "UPDATE_INSTALLED_NATIVE_OWNER_FOR_TYPED_BOOTSTRAP_EVIDENCE"
        );
        report.bootstrap_phase = Phase::ReceiptKeyGitRegistrationRequired as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.bootstrap_phase = Phase::LocalPrerequisitesOnly as i32;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT")
        );
        host.native_receipt_public_key = vec![9; 32];
        // A pre-refresh installed root still reports its own earlier local
        // receipt phase. Protected Git already has the key; this only validates
        // unauthenticated readback and does not grant any mutation authority.
        report.bootstrap_phase = Phase::ReceiptKeyGitRegistrationRequired as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        host.native_receipt_public_key = vec![9; 3];
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT")
        );
        host.native_receipt_public_key = vec![9; 32];
        report.bootstrap_phase = Phase::LocalPrerequisitesOnly as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        assert_eq!(
            vm_bootstrap_next_action(Phase::LocalPrerequisitesOnly),
            "VERIFY_WORKER_SIGNER_NATIVE_RECEIPT_AND_PHYSICAL_STATE"
        );
        report.credential.as_mut().unwrap().state =
            crate::FleetVmCredentialState::StoreAbsent as i32;
        report.credential.as_mut().unwrap().active_generation = 0;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT")
        );
        report.bootstrap_phase = Phase::WorkerActiveCredentialRequired as i32;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT")
        );
        report.bootstrap_phase = Phase::FirstUseGitSourceRequired as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        host.vm_first_use_credential = Some(crate::FleetVmFirstUseCredential {
            generation: 19,
            bundle_sha256: "b".repeat(64),
        });
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT")
        );
        report.bootstrap_phase = Phase::FirstUseWorkerSourceUnverified as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        assert_eq!(
            vm_bootstrap_next_action(Phase::FirstUseWorkerSourceUnverified),
            "VERIFY_GIT_PINNED_WORKER_BUNDLE_DURING_SIGNED_INSTALL"
        );
        for phase in [
            Phase::FirstUseWorkerSourceVerifiedLocal,
            Phase::FirstUseWorkerSourceMismatch,
            Phase::FirstUseWorkerSourceUnavailable,
        ] {
            report.bootstrap_phase = phase as i32;
            assert!(validate_vm_resource_report(&report, &host).is_ok());
        }
        assert_eq!(
            vm_bootstrap_next_action(Phase::FirstUseWorkerSourceVerifiedLocal),
            "REQUEST_FRESH_SIGNED_INSTALL_WITH_INDEPENDENT_NATIVE_RECEIPT"
        );
        host.vm_first_use_credential = None;
        report.bootstrap_phase = Phase::FirstUseWorkerSourceVerifiedLocal as i32;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_DEPENDENCY_CONFLICT")
        );
        host.vm_first_use_credential = Some(crate::FleetVmFirstUseCredential {
            generation: 19,
            bundle_sha256: "b".repeat(64),
        });
        report.bootstrap_phase = Phase::JournalUnknownNoReplay as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.bootstrap_phase = 7777;
        assert_eq!(
            validate_vm_resource_report(&report, &host),
            Err("VM_BOOTSTRAP_PHASE_UNKNOWN")
        );
    }

    #[test]
    fn credential_reference_cannot_claim_active_or_candidate_without_exact_generation() {
        use crate::{FleetVmCredentialReadback as Readback, FleetVmCredentialState as State};
        for (state, active, candidate, valid) in [
            (State::StoreAbsent, 0, 0, true),
            (State::ActiveLocalValid, 42, 0, true),
            (State::ActiveLocalValid, 42, 43, true),
            (State::CandidateOnly, 0, 9, true),
            (State::CandidateOnly, 0, 0, false),
            (State::ActiveLocalValid, 0, 9, false),
            (State::StoreAbsent, 42, 0, false),
            (State::Unproven, 0, 2, false),
        ] {
            let proof = Readback {
                state: state as i32,
                active_generation: active,
                candidate_generation: candidate,
            };
            assert_eq!(validate_vm_credential_readback(&proof).is_ok(), valid);
        }
    }

    #[test]
    fn installed_policy_readback_requires_exact_typed_hierarchy_not_arbitrary_dependencies() {
        let (host, mut report) = fixture();
        let resource = host.vm_containers[0].clone();
        let graph = FleetVmDesiredGraph {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources: vec![crate::FleetVmDesiredResource {
                resource: Some(resource.clone()),
                image_ref: format!("example/image@sha256:{}", "a".repeat(64)),
                config_template_sha256: vec![7; 32],
                ..Default::default()
            }],
            networks: vec![crate::FleetVmDesiredNetwork {
                compose_project: resource.compose_project.clone(),
                network_name: "edge_net".into(),
                driver: "bridge".into(),
                attached_services: vec![resource.compose_service.clone()],
            }],
        };
        report.installed_policy_graph = Some(graph.clone());
        report.installed_policy_status = crate::FleetVmInstalledPolicyStatus::Valid as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        let mut foreign = graph.clone();
        foreign.networks[0]
            .attached_services
            .push("foreign-mesh".into());
        report.installed_policy_graph = Some(foreign);
        assert!(validate_vm_resource_report(&report, &host).is_err());
        let mut cyclic = graph;
        cyclic.resources[0]
            .dependencies
            .push(resource.compose_service);
        report.installed_policy_graph = Some(cyclic);
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.installed_policy_graph = None;
        report.installed_policy_status = crate::FleetVmInstalledPolicyStatus::NetworkInvalid as i32;
        report.installed_policy_error_code = "HOST_VM_NETWORK_POLICY_UNSUPPORTED".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.installed_policy_error_code = "../etc/shadow".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.installed_policy_status = crate::FleetVmInstalledPolicyStatus::Valid as i32;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.installed_policy_status = 0;
        report.installed_policy_error_code.clear();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
    }

    #[test]
    fn native_reason_enum_rejects_forged_code_and_invalid_state() {
        let (host, mut report) = fixture();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].observed_reason = crate::FleetVmObservedReason::Stopped as i32;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].observed_reason = 0;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].observed_reason = 999;
        assert!(validate_vm_resource_report(&report, &host).is_err());
    }

    #[test]
    fn network_report_cannot_forge_dns_or_firewall_proof() {
        use crate::{Ipv4AddressObservation, Ipv4LinkObservation, Ipv4NetworkObservation};
        let network = FleetVmNetworkReadback {
            ipv4: Some(Ipv4NetworkObservation {
                links: vec![Ipv4LinkObservation {
                    interface_index: 2,
                    name: "ens3".into(),
                    up: true,
                    lower_up: true,
                    loopback: false,
                }],
                addresses: vec![Ipv4AddressObservation {
                    interface_index: 2,
                    address: "192.0.2.10".into(),
                    prefix_length: 24,
                    global_scope: true,
                }],
                ..Default::default()
            }),
            dns_nameservers: vec!["1.1.1.1".into()],
            dns_configuration_observed: true,
            nft_rule_count: 2,
            nft_ruleset_observed: true,
            nft_ruleset_sha256: vec![42; 32],
            dual_stack: None,
            dual_stack_error_code: String::new(),
        };
        assert!(validate_vm_network_readback(&network).is_ok());
        let mut forged = network.clone();
        forged.nft_ruleset_observed = false;
        assert!(validate_vm_network_readback(&forged).is_err());
        forged = network.clone();
        forged.dns_configuration_observed = false;
        assert!(validate_vm_network_readback(&forged).is_err());
        forged = network.clone();
        forged.ipv4.as_mut().unwrap().addresses[0].interface_index = 999;
        assert!(validate_vm_network_readback(&forged).is_err());
        forged = network.clone();
        forged.dns_nameservers.push("not-an-ip".into());
        assert!(validate_vm_network_readback(&forged).is_err());
    }

    #[test]
    fn typed_vm_graph_rejects_foreign_resources_and_dependency_cycles() {
        use crate::{FleetVmContainer, FleetVmDesiredResource};
        let selector = |name: &str| FleetVmContainer {
            container_name: format!("test-{name}"),
            compose_project: "test".into(),
            compose_service: name.into(),
        };
        let host = FleetHost {
            machine_id: "vm-test".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: vec![selector("line1-gateway"), selector("warp-egress")],
            ..Default::default()
        };
        let image = format!("repo/app@sha256:{}", "a".repeat(64));
        let mut graph = FleetVmDesiredGraph {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources: vec![
                FleetVmDesiredResource {
                    resource: Some(host.vm_containers[0].clone()),
                    image_ref: image.clone(),
                    dependencies: vec!["warp-egress".into()],
                    config_template_sha256: vec![9; 32],
                },
                FleetVmDesiredResource {
                    resource: Some(host.vm_containers[1].clone()),
                    image_ref: image.clone(),
                    ..Default::default()
                },
            ],
            networks: vec![crate::FleetVmDesiredNetwork {
                compose_project: "test".into(),
                network_name: "edge_net".into(),
                driver: "bridge".into(),
                attached_services: vec!["line1-gateway".into(), "warp-egress".into()],
            }],
        };
        assert!(validate_vm_desired_graph(&graph, &host).is_ok());
        let mut unknown_network = graph.clone();
        unknown_network.networks[0]
            .attached_services
            .push("cloudflare-mesh".into());
        assert_eq!(
            validate_vm_desired_graph(&unknown_network, &host),
            Err("VM_GRAPH_NETWORK_MEMBERSHIP_INVALID")
        );
        unknown_network = graph.clone();
        unknown_network.networks[0].driver = "host".into();
        assert_eq!(
            validate_vm_desired_graph(&unknown_network, &host),
            Err("VM_GRAPH_NETWORK_SCOPE_INVALID")
        );
        graph.resources[1].dependencies.push("line1-gateway".into());
        assert_eq!(
            validate_vm_desired_graph(&graph, &host),
            Err("VM_GRAPH_DEPENDENCY_CYCLE")
        );
        graph.resources[1].dependencies.clear();
        graph.resources[0].image_ref = "repo/app:latest".into();
        assert!(validate_vm_desired_graph(&graph, &host).is_err());
        graph.resources[0].image_ref = image;
        graph.resources[0]
            .resource
            .as_mut()
            .unwrap()
            .compose_service = "foreign".into();
        assert!(validate_vm_desired_graph(&graph, &host).is_err());
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
        report.resources[0].observed_reason = crate::FleetVmObservedReason::ForeignOwner as i32;
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "HEALTHY".into();
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report = fixture().1;
        report.resources[0].config_proof = FleetVmConfigProof::BoundRunningProcess as i32;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].config_sha256 = vec![7; 32];
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].config_proof = FleetVmConfigProof::Unproven as i32;
        report.resources[0].config_sha256.clear();
        report.resources[0].reason_code = "HEALTH_STARTING".into();
        report.resources[0].observed_reason = crate::FleetVmObservedReason::HealthStarting as i32;
        assert!(validate_vm_resource_report(&report, &host).is_err());
        report.resources[0].health = "STARTING".into();
        assert!(validate_vm_resource_report(&report, &host).is_ok());
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        report.resources[0].observed_reason =
            crate::FleetVmObservedReason::RunningNoHealthcheck as i32;
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
        FleetHostPlannedStep as Step, FleetHostRunState, FleetVmResourceReason as Reason,
        FleetVmResourceTransition, FleetVmResourceTransitionPlan,
    };
    validate_vm_resource_report(report, host)?;
    let desired = host
        .target
        .as_ref()
        .and_then(|target| FleetHostRunState::try_from(target.run_state).ok());
    let credential_ready = report.credential.as_ref().is_some_and(|credential| {
        credential.state == crate::FleetVmCredentialState::ActiveLocalValid as i32
    });
    // A VM with no local ACTIVE is not generally INSTALL-ready. A signed
    // first-use application install can only be PROPOSED when the root Agent
    // has observed the exact Git-pinned Worker source and ALL registered
    // containers are independently observed absent. A partial installation,
    // uncertain Docker readback or candidate-only credentials stay BLOCKED.
    // This remains a runner-copied, non-authorizing diagnostic projection:
    // the signed root owner repeats preflight before durable journal BEGIN.
    let first_use_install_proposal = !credential_ready
        && report.bootstrap_phase
            == crate::FleetVmBootstrapPhase::FirstUseWorkerSourceVerifiedLocal as i32
        && report.credential.as_ref().is_some_and(|credential| {
            credential.state == crate::FleetVmCredentialState::StoreAbsent as i32
        })
        && report.resources.iter().all(|row| {
            !row.present
                && row.observed_reason == crate::FleetVmObservedReason::ContainerAbsent as i32
        });
    let mut resources = Vec::with_capacity(report.resources.len());
    for row in &report.resources {
        let (step, reason) = match desired {
            // An explicit STOP is always allowed to address an already-owned
            // container; credential outages may NOT force continued running.
            Some(FleetHostRunState::Running) if first_use_install_proposal => (
                Step::Install,
                Reason::FirstUseWorkerVerifiedInstallProposalOnly,
            ),
            Some(FleetHostRunState::Running) if !credential_ready => {
                (Step::Blocked, Reason::CredentialDependencyUnproven)
            }
            None | Some(FleetHostRunState::Unspecified) => {
                (Step::Blocked, Reason::TargetUnsetObserveOnly)
            }
            Some(FleetHostRunState::Stopped)
                if !row.present
                    && row.observed_reason
                        == crate::FleetVmObservedReason::ContainerAbsent as i32 =>
            {
                (Step::Noop, Reason::AbsentAsDesired)
            }
            Some(FleetHostRunState::Running)
                if !row.present
                    && row.observed_reason
                        == crate::FleetVmObservedReason::ContainerAbsent as i32 =>
            {
                (Step::Install, Reason::ContainerAbsentInstallRequired)
            }
            Some(_) if !row.present || !row.ownership_proven || !row.running_proven => {
                (Step::Blocked, Reason::ResourceIdentityOrStateUnproven)
            }
            Some(FleetHostRunState::Stopped) if row.running => {
                (Step::Stop, Reason::ContainerRunningButTargetStopped)
            }
            Some(FleetHostRunState::Stopped) => (Step::Noop, Reason::StoppedAsDesired),
            Some(FleetHostRunState::Running) if !row.running => {
                (Step::Start, Reason::ContainerStoppedButTargetRunning)
            }
            Some(FleetHostRunState::Running)
                if matches!(
                    crate::FleetVmObservedReason::try_from(row.observed_reason),
                    Ok(crate::FleetVmObservedReason::Healthy
                        | crate::FleetVmObservedReason::RunningNoHealthcheck)
                ) =>
            {
                // An already-running container requires no START. Docker
                // health is NOT proof of configuration or network readiness.
                (Step::Noop, Reason::RunningRuntimeOnlyConfigUnproven)
            }
            Some(FleetHostRunState::Running) => {
                (Step::Blocked, Reason::RuntimeHealthOrConfigUnproven)
            }
        };
        let selector = row
            .resource
            .as_ref()
            .ok_or("VM_RESOURCE_PLAN_SELECTOR_MISSING")?;
        resources.push(FleetVmResourceTransition {
            resource: row.resource.clone(),
            resource_id: vm_container_resource_id(host, selector)?,
            step: step as i32,
            reason_code: reason
                .as_str_name()
                .strip_prefix("FLEET_VM_RESOURCE_REASON_")
                .expect("typed reason uses the stable protobuf prefix")
                .to_owned(),
            reason: reason as i32,
        });
    }
    let proposed = FleetVmResourceTransitionPlan {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        owner_attested: false,
        mutation_authorized: false,
    };
    validate_vm_resource_transition_plan(&proposed, host)?;
    Ok(proposed)
}

/// Contract validation is distinct from authorization: even a well-formed
/// runner-copied plan must never claim owner attestation or mutation rights.
/// Validate exact host scope, typed reason/action pairing and the backwards-
/// compatible reason_code projection. No new owner registry is introduced.
pub fn validate_vm_resource_transition_plan(
    plan: &crate::FleetVmResourceTransitionPlan,
    host: &FleetHost,
) -> Result<(), &'static str> {
    use crate::{FleetHostPlannedStep as Step, FleetVmResourceReason as Reason};
    if host.kind != FleetHostKind::Vm as i32
        || plan.schema_version != 1
        || plan.machine_id != host.machine_id
        || plan.resources.len() != host.vm_containers.len()
        || plan.owner_attested
        || plan.mutation_authorized
    {
        return Err("VM_RESOURCE_PLAN_SCOPE_OR_AUTHORITY_INVALID");
    }
    for (entry, selector) in plan.resources.iter().zip(&host.vm_containers) {
        if entry.resource.as_ref() != Some(selector)
            || entry.resource_id != vm_container_resource_id(host, selector)?
        {
            return Err("VM_RESOURCE_PLAN_IDENTITY_INVALID");
        }
        let reason =
            Reason::try_from(entry.reason).map_err(|_| "VM_RESOURCE_PLAN_REASON_UNRECOGNIZED")?;
        if reason == Reason::Unspecified {
            return Err("VM_RESOURCE_PLAN_REASON_UNSPECIFIED");
        }
        let code = reason
            .as_str_name()
            .strip_prefix("FLEET_VM_RESOURCE_REASON_")
            .ok_or("VM_RESOURCE_PLAN_REASON_INVALID")?;
        if entry.reason_code != code {
            return Err("VM_RESOURCE_PLAN_REASON_CODE_MISMATCH");
        }
        let expected_step = match reason {
            Reason::TargetUnsetObserveOnly
            | Reason::ResourceIdentityOrStateUnproven
            | Reason::RuntimeHealthOrConfigUnproven
            | Reason::CredentialDependencyUnproven => Step::Blocked,
            Reason::AbsentAsDesired
            | Reason::StoppedAsDesired
            | Reason::RunningRuntimeOnlyConfigUnproven => Step::Noop,
            Reason::ContainerAbsentInstallRequired
            | Reason::FirstUseWorkerVerifiedInstallProposalOnly => Step::Install,
            Reason::ContainerRunningButTargetStopped => Step::Stop,
            Reason::ContainerStoppedButTargetRunning => Step::Start,
            Reason::Unspecified => return Err("VM_RESOURCE_PLAN_REASON_UNSPECIFIED"),
        };
        if entry.step != expected_step as i32 {
            return Err("VM_RESOURCE_PLAN_ACTION_REASON_CONFLICT");
        }
    }
    Ok(())
}

/// Native START admission must consume the SAME immutable hierarchy as the
/// read-only diagnostic and resource transition planner. This is a PURE scope
/// gate, NOT a mutation authorization or an installed network health proof.
///
/// STOP is deliberately not routed through this function: a broken Compose
/// policy must not prevent an emergency stop of proven owned containers.
pub fn validate_vm_native_start_dag(
    host: &FleetHost,
    installed_policy: &FleetVmDesiredGraph,
    plan: &crate::FleetVmResourceTransitionPlan,
) -> Result<(), &'static str> {
    use crate::{
        FleetHostPlannedStep as Step, FleetResourceKind as Kind, FleetResourceOwner as Owner,
    };
    validate_vm_resource_transition_plan(plan, host)?;
    let hierarchy = derive_vm_resource_hierarchy(host, installed_policy)?;
    let nodes = hierarchy
        .nodes
        .iter()
        .map(|node| (node.resource_id.as_str(), node))
        .collect::<std::collections::BTreeMap<_, _>>();
    let transitions = plan
        .resources
        .iter()
        .map(|entry| (entry.resource_id.as_str(), entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    if transitions.len() != installed_policy.resources.len() {
        return Err("VM_START_DAG_SCOPE_INCOMPLETE");
    }
    let mut mutating = 0;
    for (resource_id, transition) in &transitions {
        let node = nodes
            .get(resource_id)
            .ok_or("VM_START_DAG_RESOURCE_NOT_REGISTERED")?;
        if node.kind != Kind::DockerContainer as i32
            || node.owner != Owner::VmRootAgent as i32
            || node.parent_resource_id != vm_host_resource_id(host)
            || node.dependency_ids.is_empty()
        {
            return Err("VM_START_DAG_OWNER_OR_PARENT_UNPROVEN");
        }
        let step = Step::try_from(transition.step).map_err(|_| "VM_START_DAG_STEP_INVALID")?;
        match step {
            Step::Noop => {}
            Step::Start | Step::Install => {
                mutating += 1;
                for dependency_id in &node.dependency_ids {
                    let dependency = nodes
                        .get(dependency_id.as_str())
                        .ok_or("VM_START_DAG_DEPENDENCY_UNREGISTERED")?;
                    let dependency_kind = Kind::try_from(dependency.kind)
                        .map_err(|_| "VM_START_DAG_DEPENDENCY_KIND_UNRECOGNIZED")?;
                    // A Worker credential is a real graph prerequisite but
                    // its presence is NEVER a credential authorization.
                    // Physical ACTIVE must be proven by root ResourceReport/v2
                    // before the resource planner can return START/INSTALL.
                    if dependency_kind == Kind::CredentialRef {
                        if dependency.owner != Owner::WorkerSecrets as i32
                            || dependency.resource_id != vm_worker_credential_resource_id(host)
                            || dependency.parent_resource_id != vm_host_resource_id(host)
                        {
                            return Err("VM_START_DAG_CREDENTIAL_OWNER_UNPROVEN");
                        }
                        continue;
                    }
                    if dependency.owner != Owner::VmRootAgent as i32 {
                        return Err("VM_START_DAG_DEPENDENCY_OWNER_UNPROVEN");
                    }
                    match dependency_kind {
                        Kind::DockerNetwork => {
                            if dependency.parent_resource_id != vm_host_resource_id(host) {
                                return Err("VM_START_DAG_NETWORK_PARENT_UNPROVEN");
                            }
                        }
                        Kind::DockerContainer => {
                            let upstream = transitions
                                .get(dependency_id.as_str())
                                .ok_or("VM_START_DAG_CONTAINER_DEPENDENCY_NOT_IN_PLAN")?;
                            match Step::try_from(upstream.step)
                                .map_err(|_| "VM_START_DAG_DEPENDENCY_STEP_INVALID")?
                            {
                                Step::Noop | Step::Start => {}
                                _ => return Err("VM_START_DAG_UPSTREAM_NOT_READY"),
                            }
                        }
                        _ => return Err("VM_START_DAG_DEPENDENCY_KIND_UNSUPPORTED"),
                    }
                }
            }
            _ => return Err("VM_START_DAG_ACTION_NOT_START"),
        }
    }
    if mutating == 0 {
        return Err("VM_START_DAG_NO_MUTATION");
    }
    Ok(())
}

/// A runtime NOOP is not proof of config convergence. Use the *typed* reason
/// from the exact same plan consumed by the native owner, never free text.
pub fn vm_resource_requires_attention(transition: &crate::FleetVmResourceTransition) -> bool {
    transition.step != crate::FleetHostPlannedStep::Noop as i32
        || transition.reason
            == crate::FleetVmResourceReason::RunningRuntimeOnlyConfigUnproven as i32
}

#[cfg(test)]
mod vm_graph_reconcile_tests {
    use super::*;
    use crate::{
        FleetHostKind, FleetVmContainer, FleetVmDesiredGraph, FleetVmDesiredResource,
        FleetVmPolicyChange,
    };

    fn sample() -> (FleetHost, FleetVmDesiredGraph) {
        let selectors = ["line1-gateway", "line2-proxy", "warp-egress"]
            .iter()
            .map(|name| FleetVmContainer {
                container_name: format!("vultr-{name}"),
                compose_project: "vultr-edge".into(),
                compose_service: (*name).into(),
            })
            .collect::<Vec<_>>();
        let host = FleetHost {
            machine_id: "vm-a".into(),
            kind: FleetHostKind::Vm as i32,
            vm_containers: selectors.clone(),
            ..Default::default()
        };
        let image = format!("app/gateway@sha256:{}", "a".repeat(64));
        let warp_image = format!("app/warp@sha256:{}", "b".repeat(64));
        let resources = selectors
            .into_iter()
            .enumerate()
            .map(|(index, resource)| FleetVmDesiredResource {
                resource: Some(resource),
                image_ref: if index == 2 {
                    warp_image.clone()
                } else {
                    image.clone()
                },
                dependencies: if index == 2 {
                    vec![]
                } else {
                    vec!["warp-egress".into()]
                },
                config_template_sha256: if index == 2 { vec![] } else { vec![10; 32] },
            })
            .collect();
        let graph = FleetVmDesiredGraph {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources,
            networks: vec![crate::FleetVmDesiredNetwork {
                compose_project: "vultr-edge".into(),
                network_name: "edge_net".into(),
                driver: "bridge".into(),
                attached_services: vec![
                    "line1-gateway".into(),
                    "line2-proxy".into(),
                    "warp-egress".into(),
                ],
            }],
        };
        (host, graph)
    }

    #[test]
    fn immutable_vm_resource_hierarchy_is_closed_and_parented() {
        use crate::{FleetResourceKind as Kind, FleetResourceOwner as Owner};
        let (host, desired) = sample();
        let hierarchy = derive_vm_resource_hierarchy(&host, &desired).unwrap();
        assert!(!hierarchy.owner_attested && !hierarchy.mutation_authorized);
        assert_eq!(hierarchy.nodes.len(), 8);
        assert_eq!(hierarchy.nodes[0].resource_id, "host/vm-a");
        assert_eq!(
            hierarchy.nodes[1].resource_id,
            "credential/vm-a/application-v2"
        );
        assert_eq!(hierarchy.nodes[1].kind, Kind::CredentialRef as i32);
        assert_eq!(hierarchy.nodes[1].owner, Owner::WorkerSecrets as i32);
        assert_eq!(hierarchy.nodes[1].parent_resource_id, "host/vm-a");
        assert_eq!(
            hierarchy.nodes[2].resource_id,
            "network/vultr-edge/edge_net"
        );
        assert_eq!(hierarchy.nodes[2].kind, Kind::DockerNetwork as i32);
        assert_eq!(hierarchy.nodes[2].owner, Owner::VmRootAgent as i32);
        let line2 = hierarchy
            .nodes
            .iter()
            .find(|node| node.resource_id == "container/vultr-edge/line2-proxy")
            .unwrap();
        assert_eq!(line2.parent_resource_id, "host/vm-a");
        assert_eq!(line2.kind, Kind::DockerContainer as i32);
        assert_eq!(
            line2.dependency_ids,
            vec![
                "container/vultr-edge/warp-egress".to_owned(),
                "credential/vm-a/application-v2".to_owned(),
                "network/vultr-edge/edge_net".to_owned(),
            ]
        );
        let config = hierarchy
            .nodes
            .iter()
            .find(|node| node.resource_id == "config/vultr-edge/line2-proxy")
            .unwrap();
        assert_eq!(config.parent_resource_id, line2.resource_id);
        assert_eq!(config.kind, Kind::SingboxConfig as i32);
        assert_eq!(
            config.expected_policy_sha256,
            desired.resources[1].config_template_sha256
        );
        assert_eq!(
            validate_vm_resource_hierarchy(&hierarchy, &host, &desired),
            Ok(())
        );
        let mut forged = hierarchy.clone();
        forged.nodes[1].owner = Owner::WindowsSystemController as i32;
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes[1].parent_resource_id = "host/foreign".into();
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged
            .nodes
            .iter_mut()
            .find(|node| node.resource_id == "container/vultr-edge/line2-proxy")
            .unwrap()
            .dependency_ids
            .retain(|dependency| dependency != "credential/vm-a/application-v2");
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes[3].parent_resource_id = "host/foreign".into();
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes[3].dependency_ids.clear();
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.owner_attested = true;
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
        forged = hierarchy.clone();
        forged.nodes.push(forged.nodes[0].clone());
        assert!(validate_vm_resource_hierarchy(&forged, &host, &desired).is_err());
    }

    #[test]
    fn start_dag_rejects_missing_upstream_and_sibling_mutation() {
        use crate::{
            FleetHostPlannedStep as Step, FleetVmResourceReason as Reason,
            FleetVmResourceTransition, FleetVmResourceTransitionPlan,
        };
        let (host, graph) = sample();
        let mut plan = FleetVmResourceTransitionPlan {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources: host
                .vm_containers
                .iter()
                .map(|resource| FleetVmResourceTransition {
                    resource: Some(resource.clone()),
                    resource_id: vm_container_resource_id(&host, resource).unwrap(),
                    step: Step::Noop as i32,
                    reason: Reason::RunningRuntimeOnlyConfigUnproven as i32,
                    reason_code: "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN".into(),
                })
                .collect(),
            ..Default::default()
        };
        // A single missing Line2 is admissible only when the WARP dependency
        // is already running and its network exists in the immutable graph.
        plan.resources[1].step = Step::Install as i32;
        plan.resources[1].reason = Reason::ContainerAbsentInstallRequired as i32;
        plan.resources[1].reason_code = "CONTAINER_ABSENT_INSTALL_REQUIRED".into();
        assert_eq!(validate_vm_native_start_dag(&host, &graph, &plan), Ok(()));

        // No implicit start of a missing WARP parent: a dependency is NOT
        // silently considered ready because it exists in Git desired.
        plan.resources[2].step = Step::Install as i32;
        plan.resources[2].reason = Reason::ContainerAbsentInstallRequired as i32;
        plan.resources[2].reason_code = "CONTAINER_ABSENT_INSTALL_REQUIRED".into();
        assert_eq!(
            validate_vm_native_start_dag(&host, &graph, &plan),
            Err("VM_START_DAG_UPSTREAM_NOT_READY")
        );
        plan.resources[2].step = Step::Noop as i32;
        plan.resources[2].reason = Reason::RunningRuntimeOnlyConfigUnproven as i32;
        plan.resources[2].reason_code = "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN".into();

        let mut foreign = graph.clone();
        foreign.resources[1].dependencies = vec!["foreign-mesh".into()];
        assert!(validate_vm_native_start_dag(&host, &foreign, &plan).is_err());
        foreign = graph.clone();
        foreign.networks[0]
            .attached_services
            .retain(|s| s != "line2-proxy");
        assert!(validate_vm_native_start_dag(&host, &foreign, &plan).is_err());

        plan.resources[1].step = Step::Stop as i32;
        plan.resources[1].reason = Reason::ContainerRunningButTargetStopped as i32;
        plan.resources[1].reason_code = "CONTAINER_RUNNING_BUT_TARGET_STOPPED".into();
        assert_eq!(
            validate_vm_native_start_dag(&host, &graph, &plan),
            Err("VM_START_DAG_ACTION_NOT_START")
        );
    }

    #[test]
    fn docker_network_policy_change_never_sneaks_through_image_or_config_effector() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.networks[0].network_name = "new_edge_net".into();
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_NETWORK_POLICY_REQUIRES_NATIVE_HANDLER")
        );
        desired = installed.clone();
        desired.networks[0].attached_services.swap(0, 1);
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_NETWORK_POLICY_REQUIRES_NATIVE_HANDLER")
        );
    }

    #[test]
    fn line2_configuration_only_changes_one_registered_resource() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.resources[1].config_template_sha256 = vec![11; 32];
        let plan = propose_vm_graph_reconcile(&host, &installed, &desired).unwrap();
        assert_eq!(plan.resources.len(), 3);
        assert!(!plan.owner_attested && !plan.mutation_authorized);
        assert_eq!(
            plan.resources[0].change,
            FleetVmPolicyChange::NoChange as i32
        );
        assert_eq!(
            plan.resources[1].change,
            FleetVmPolicyChange::ConfigTemplateReplaced as i32
        );
        assert_eq!(
            plan.resources[2].change,
            FleetVmPolicyChange::NoChange as i32
        );
        assert_eq!(
            plan.resources[1].expected_image_ref,
            installed.resources[1].image_ref
        );
        assert_eq!(
            plan.resources[1].resource_id,
            "config/vultr-edge/line2-proxy"
        );
        assert_eq!(
            plan.resources[1].resource_kind,
            crate::FleetResourceKind::SingboxConfig as i32
        );
        assert_eq!(
            plan.resources[0].resource_id,
            "container/vultr-edge/line1-gateway"
        );
        assert_eq!(
            plan.resources[0].resource_kind,
            crate::FleetResourceKind::DockerContainer as i32
        );
    }

    #[test]
    fn shared_image_is_one_indivisible_owner_scope() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.resources[0].image_ref = format!("app/gateway@sha256:{}", "c".repeat(64));
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_SHARED_IMAGE_PARTIAL_REPLACE")
        );
        desired.resources[1].image_ref = desired.resources[0].image_ref.clone();
        let plan = propose_vm_graph_reconcile(&host, &installed, &desired).unwrap();
        assert_eq!(
            plan.resources
                .iter()
                .filter(|item| item.change == FleetVmPolicyChange::ImageReplaced as i32)
                .count(),
            2
        );
        assert_eq!(
            plan.resources[2].change,
            FleetVmPolicyChange::NoChange as i32
        );
        assert_eq!(
            plan.resources[0].resource_id,
            "container/vultr-edge/line1-gateway"
        );
        assert_eq!(
            plan.resources[1].resource_id,
            "container/vultr-edge/line2-proxy"
        );
        assert!(
            plan.resources[0].resource_kind == crate::FleetResourceKind::DockerContainer as i32
        );
    }

    #[test]
    fn dependencies_and_combined_image_config_are_not_silent_updates() {
        let (host, installed) = sample();
        let mut desired = installed.clone();
        desired.resources[0].dependencies.clear();
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_DEPENDENCY_OR_IDENTITY_CHANGED")
        );
        desired = installed.clone();
        desired.resources[0].image_ref = format!("app/gateway@sha256:{}", "d".repeat(64));
        desired.resources[0].config_template_sha256 = vec![12; 32];
        assert_eq!(
            propose_vm_graph_reconcile(&host, &installed, &desired),
            Err("VM_RECONCILE_COMBINED_IMAGE_AND_CONFIG_UNSUPPORTED")
        );
        desired = installed.clone();
        desired.resources[0].image_ref = "app/gateway:latest".into();
        assert!(propose_vm_graph_reconcile(&host, &installed, &desired).is_err());
    }
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
            schema_version: 2,
            bootstrap_phase: crate::FleetVmBootstrapPhase::Unspecified as i32,
            processes: None,
            managed_docker: Vec::new(),
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
                observed_reason: crate::FleetVmObservedReason::Healthy as i32,
                health: "HEALTHY".into(),
                ..Default::default()
            }],
            remote_attested: false,
            network: None,
            installed_policy_graph: None,
            installed_policy_status: 0,
            installed_policy_error_code: String::new(),
            credential: Some(crate::FleetVmCredentialReadback {
                state: crate::FleetVmCredentialState::ActiveLocalValid as i32,
                active_generation: 42,
                ..Default::default()
            }),
        };
        (host, report)
    }

    fn step(host: &FleetHost, report: &FleetVmResourceReport) -> FleetHostPlannedStep {
        let result = propose_vm_resource_transitions(host, report).unwrap();
        assert!(!result.owner_attested && !result.mutation_authorized);
        FleetHostPlannedStep::try_from(result.resources[0].step).unwrap()
    }

    #[test]
    fn credential_dependency_blocks_running_but_never_prevents_emergency_stop() {
        use crate::{
            FleetHostPlannedStep as Step, FleetHostRunState, FleetVmCredentialState,
            FleetVmResourceReason as Reason,
        };
        let (mut host, mut report) = fixture();
        let credential = report.credential.as_mut().unwrap();
        credential.state = FleetVmCredentialState::StoreAbsent as i32;
        credential.active_generation = 0;
        let blocked = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(blocked.resources[0].step, Step::Blocked as i32);
        assert_eq!(
            blocked.resources[0].reason,
            Reason::CredentialDependencyUnproven as i32
        );
        report.credential.as_mut().unwrap().state = FleetVmCredentialState::CandidateOnly as i32;
        report.credential.as_mut().unwrap().candidate_generation = 101;
        let candidate = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(candidate.resources[0].step, Step::Blocked as i32);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        let stopped = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(stopped.resources[0].step, Step::Stop as i32);
        assert_eq!(
            stopped.resources[0].reason,
            Reason::ContainerRunningButTargetStopped as i32
        );
    }

    #[test]
    fn first_use_resource_plan_matches_host_install_without_granting_authority() {
        use crate::{
            FleetVmBootstrapPhase as Phase, FleetVmCredentialState as Cred,
            FleetVmFirstUseCredential, FleetVmObservedReason as Observed,
            FleetVmResourceReason as Reason,
        };
        let (mut host, mut report) = fixture();
        host.native_receipt_public_key = vec![9; 32];
        host.vm_first_use_credential = Some(FleetVmFirstUseCredential {
            generation: 19,
            bundle_sha256: "b".repeat(64),
        });
        report.credential.as_mut().unwrap().state = Cred::StoreAbsent as i32;
        report.credential.as_mut().unwrap().active_generation = 0;
        report.bootstrap_phase = Phase::FirstUseWorkerSourceVerifiedLocal as i32;
        report.resources[0] = FleetVmResourceReadback {
            resource: Some(host.vm_containers[0].clone()),
            observed_reason: Observed::ContainerAbsent as i32,
            reason_code: "CONTAINER_ABSENT".into(),
            ..Default::default()
        };
        let proposal = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(
            proposal.resources[0].step,
            FleetHostPlannedStep::Install as i32
        );
        assert_eq!(
            proposal.resources[0].reason,
            Reason::FirstUseWorkerVerifiedInstallProposalOnly as i32
        );
        assert_eq!(
            proposal.resources[0].reason_code,
            "FIRST_USE_WORKER_VERIFIED_INSTALL_PROPOSAL_ONLY"
        );
        assert!(!proposal.owner_attested && !proposal.mutation_authorized);
        assert!(validate_vm_resource_transition_plan(&proposal, &host).is_ok());
        let mut forged = proposal.clone();
        forged.resources[0].step = FleetHostPlannedStep::Start as i32;
        assert_eq!(
            validate_vm_resource_transition_plan(&forged, &host),
            Err("VM_RESOURCE_PLAN_ACTION_REASON_CONFLICT")
        );

        // A stale/unavailable Worker, or an unverified bootstrap, does not
        // become a credential bypass merely because Docker is empty.
        for phase in [
            Phase::FirstUseWorkerSourceUnverified,
            Phase::FirstUseWorkerSourceMismatch,
            Phase::FirstUseWorkerSourceUnavailable,
        ] {
            report.bootstrap_phase = phase as i32;
            let blocked = propose_vm_resource_transitions(&host, &report).unwrap();
            assert_eq!(
                blocked.resources[0].step,
                FleetHostPlannedStep::Blocked as i32
            );
            assert_eq!(
                blocked.resources[0].reason,
                Reason::CredentialDependencyUnproven as i32
            );
        }

        // The STOPPED desired state never installs an absent application.
        report.bootstrap_phase = Phase::FirstUseWorkerSourceVerifiedLocal as i32;
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Running as i32;

        // A partially present application is a different state from the
        // fresh all-absent VM; it must not borrow the first-use exemption.
        let mut existing = fixture().1.resources.remove(0);
        let mut sibling = host.vm_containers[0].clone();
        sibling.container_name = "vultr-line1-gateway".into();
        sibling.compose_service = "line1-gateway".into();
        existing.resource = Some(sibling.clone());
        host.vm_containers.push(sibling);
        report.resources.push(existing);
        let partial = propose_vm_resource_transitions(&host, &report).unwrap();
        assert!(
            partial
                .resources
                .iter()
                .all(|item| item.step == FleetHostPlannedStep::Blocked as i32)
        );
        assert!(
            partial
                .resources
                .iter()
                .all(|item| { item.reason == Reason::CredentialDependencyUnproven as i32 })
        );
    }

    #[test]
    fn typed_resource_reason_and_action_are_one_non_authorizing_contract() {
        use crate::FleetVmResourceReason as Reason;
        let (host, report) = fixture();
        let plan = propose_vm_resource_transitions(&host, &report).unwrap();
        assert_eq!(
            plan.resources[0].reason,
            Reason::RunningRuntimeOnlyConfigUnproven as i32
        );
        assert_eq!(
            plan.resources[0].reason_code,
            "RUNNING_RUNTIME_ONLY_CONFIG_UNPROVEN"
        );
        assert!(validate_vm_resource_transition_plan(&plan, &host).is_ok());
        let mut invalid = plan.clone();
        invalid.resources[0].reason_code = "ARBITRARY_FIX_WITH_SHELL".into();
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_REASON_CODE_MISMATCH")
        );
        invalid = plan.clone();
        invalid.resources[0].step = FleetHostPlannedStep::Stop as i32;
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_ACTION_REASON_CONFLICT")
        );
        invalid = plan.clone();
        invalid.resources[0].reason = Reason::Unspecified as i32;
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_REASON_UNSPECIFIED")
        );
        invalid = plan.clone();
        invalid.resources[0].resource_id = "container/foreign/line2-proxy".into();
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_IDENTITY_INVALID")
        );
        invalid = plan.clone();
        invalid.owner_attested = true;
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_SCOPE_OR_AUTHORITY_INVALID")
        );
        invalid = plan.clone();
        invalid.resources[0]
            .resource
            .as_mut()
            .unwrap()
            .compose_service = "foreign".into();
        assert_eq!(
            validate_vm_resource_transition_plan(&invalid, &host),
            Err("VM_RESOURCE_PLAN_IDENTITY_INVALID")
        );
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
        report.resources[0].observed_reason =
            crate::FleetVmObservedReason::RunningNoHealthcheck as i32;
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
        report.resources[0].observed_reason = crate::FleetVmObservedReason::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Start);
        host.target.as_mut().unwrap().run_state = FleetHostRunState::Stopped as i32;
        assert_eq!(step(&host, &report), FleetHostPlannedStep::Noop);
        report.resources[0].running = true;
        report.resources[0].reason_code = "RUNNING_NO_HEALTHCHECK".into();
        report.resources[0].observed_reason =
            crate::FleetVmObservedReason::RunningNoHealthcheck as i32;
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
        report.resources[0].observed_reason = crate::FleetVmObservedReason::ForeignOwner as i32;
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
        report.resources[0].observed_reason = crate::FleetVmObservedReason::Stopped as i32;
        let plan = propose_vm_resource_transitions(&stopped, &report).unwrap();
        assert!(!vm_resource_requires_attention(&plan.resources[0]));
    }

    #[test]
    fn absence_and_untrusted_reports_are_not_recovery_authority() {
        let (mut host, mut report) = fixture();
        report.resources[0] = FleetVmResourceReadback {
            resource: host.vm_containers.first().cloned(),
            reason_code: "CONTAINER_ABSENT".into(),
            observed_reason: crate::FleetVmObservedReason::ContainerAbsent as i32,
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
