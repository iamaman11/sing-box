#[path = "docker_native_gateway.rs"]
mod native_gateway;
use native_gateway::*;
#[path = "docker_managed_file.rs"]
mod managed_file;
use managed_file::*;

#[path = "docker_runtime_readback.rs"]
mod runtime_readback;
pub(super) use runtime_readback::*;

use edge_shared_types::{ApplyBundleRequest, FleetHost, FleetHostPlannedStep, FleetVmContainer};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use bollard::{
    API_DEFAULT_VERSION, Docker,
    errors::Error as BollardError,
    models::{
        ContainerSummary, ContainerSummaryNetworkSettings, ContainerSummaryStateEnum, PortSummary,
        PortSummaryTypeEnum,
    },
    query_parameters::{ListContainersOptionsBuilder, LogsOptionsBuilder},
};
use futures_util::{StreamExt, TryStreamExt};
use prost::Message;
use std::net::IpAddr;

const DOCKER_SOCKET: &str = "unix:///var/run/docker.sock";
const DOCKER_API_TIMEOUT_SECONDS: u64 = 6;

#[derive(Debug, Clone)]
struct DockerContainerObservation {
    name: String,
    running: bool,
    image: Option<String>,
    networks: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DockerObservation {
    pub(crate) reachable: bool,
    pub(crate) running_containers: Vec<String>,
    pub(crate) listening_tcp_ports: Vec<u32>,
    pub(crate) listening_udp_ports: Vec<u32>,
    containers: Vec<DockerContainerObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerRuntimeEvidence {
    pub(crate) present: bool,
    pub(crate) running: bool,
    pub(crate) exit_code: Option<i64>,
    pub(crate) runtime_error: Option<String>,
    pub(crate) log_tail: Vec<String>,
    pub(crate) name: String,
    pub(crate) image: Option<String>,
    pub(crate) restart_count: Option<u64>,
    pub(crate) oom_killed: Option<bool>,
    pub(crate) health: Option<String>,
    pub(crate) networks: Vec<String>,
    pub(crate) published_ports: Vec<String>,
    pub(crate) mounts: Vec<String>,
}

impl ContainerRuntimeEvidence {
    pub(crate) fn summary(&self) -> String {
        let exit_code = self
            .exit_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let runtime_error = self.runtime_error.as_deref().unwrap_or("none");
        let logs = if self.log_tail.is_empty() {
            "none".to_owned()
        } else {
            self.log_tail.join(" | ")
        };
        format!(
            "present={} running={} exit_code={} restart_count={} oom_killed={} health={} image={} networks={:?} ports={:?} mounts={:?} runtime_error={} log_tail={}",
            self.present,
            self.running,
            exit_code,
            self.restart_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
            self.oom_killed
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
            self.health.as_deref().unwrap_or("unknown"),
            self.image.as_deref().unwrap_or("unknown"),
            self.networks,
            self.published_ports,
            self.mounts,
            runtime_error,
            logs
        )
    }
}

impl DockerObservation {
    pub(crate) fn unreachable() -> Self {
        Self {
            reachable: false,
            running_containers: Vec::new(),
            listening_tcp_ports: Vec::new(),
            listening_udp_ports: Vec::new(),
            containers: Vec::new(),
        }
    }

    pub(crate) fn container_present(&self, name: &str) -> bool {
        self.containers
            .iter()
            .any(|container| container.name == name)
    }

    pub(crate) fn container_running(&self, name: &str) -> bool {
        self.containers
            .iter()
            .any(|container| container.name == name && container.running)
    }

    pub(crate) fn container_exact_image_ready(&self, name: &str, expected: &str) -> bool {
        self.containers.iter().any(|container| {
            container.name == name
                && container.running
                && container.image.as_deref() == Some(expected)
        })
    }

    pub(crate) fn container_on_mesh_network(&self, name: &str) -> bool {
        self.containers.iter().any(|container| {
            container.name == name
                && container.running
                && container
                    .networks
                    .iter()
                    .any(|network| network == "mesh_net" || network.ends_with("_mesh_net"))
        })
    }
}

async fn docker_connection() -> Result<Docker, String> {
    Docker::connect_with_unix(
        DOCKER_SOCKET,
        DOCKER_API_TIMEOUT_SECONDS,
        API_DEFAULT_VERSION,
    )
    .map_err(|err| format!("failed to open Docker Engine Unix socket: {err}"))?
    .negotiate_version()
    .await
    .map_err(|err| format!("failed to negotiate Docker Engine API version: {err}"))
}

/// Prevent the native lifecycle from ever adopting a same-named container
/// belonging to another Compose project. Foreign Mesh/other containers are
/// outside our resource scope and must not be inspected or mutated here.
fn exact_application_compose_owner(
    name: &str,
    labels: &HashMap<String, String>,
    expected: &[FleetVmContainer],
) -> Result<(), &'static str> {
    let resource = expected
        .iter()
        .find(|item| item.container_name == name)
        .ok_or("HOST_NATIVE_CONTAINER_OUTSIDE_APPLICATION_SCOPE")?;
    if labels.get("com.docker.compose.project").map(String::as_str)
        != Some(resource.compose_project.as_str())
        || labels.get("com.docker.compose.service").map(String::as_str)
            != Some(resource.compose_service.as_str())
    {
        return Err("HOST_NATIVE_CONTAINER_OWNERSHIP_UNPROVEN");
    }
    Ok(())
}

/// An absent flag is not proof of a safe transition state. An existing
/// container must have a complete Docker state before any ID-based mutation.
fn require_known_native_container_state(
    state: &bollard::models::ContainerState,
) -> Result<bool, &'static str> {
    if state.paused != Some(false) || state.restarting != Some(false) || state.dead != Some(false) {
        return Err("HOST_NATIVE_CONTAINER_TRANSITION_UNPROVEN");
    }
    state
        .running
        .ok_or("HOST_NATIVE_CONTAINER_RUNNING_UNPROVEN")
}

#[derive(Debug, Clone)]
struct OwnedVmContainer {
    id: String,
    running: bool,
    service: String,
    dependencies: Vec<String>,
    image_ref: String,
}

/// Inspect every application-owned container before admitting a native change.
/// Names alone are not ownership: check the Compose project, service and
/// immutable Docker container ID. Mesh and unrelated Docker projects are
/// intentionally outside this scope. Missing containers are valid on fresh VMs.
async fn owned_application_container_ids(
    docker: &Docker,
    expected: &[FleetVmContainer],
) -> Result<Vec<OwnedVmContainer>, String> {
    if expected.is_empty() {
        return Err("HOST_NATIVE_VM_RESOURCE_SCOPE_MISSING".into());
    }
    let mut owned = Vec::new();
    for resource in expected {
        let name = resource.container_name.as_str();
        let inspect = match docker.inspect_container(name, None).await {
            Ok(value) => value,
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => continue,
            Err(_) => return Err("HOST_NATIVE_DOCKER_IDENTITY_UNAVAILABLE".into()),
        };
        if inspect.name.as_deref() != Some(format!("/{name}").as_str()) {
            return Err("HOST_NATIVE_CONTAINER_NAME_UNPROVEN".into());
        }
        let config = inspect
            .config
            .as_ref()
            .ok_or("HOST_NATIVE_CONTAINER_CONFIG_MISSING")?;
        let labels = config
            .labels
            .as_ref()
            .ok_or("HOST_NATIVE_CONTAINER_LABELS_MISSING")?;
        exact_application_compose_owner(name, labels, expected).map_err(str::to_owned)?;
        let id = inspect.id.ok_or("HOST_NATIVE_CONTAINER_ID_MISSING")?;
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("HOST_NATIVE_CONTAINER_ID_INVALID".into());
        }
        let state = inspect
            .state
            .ok_or("HOST_NATIVE_CONTAINER_STATE_UNAVAILABLE")?;
        let running = require_known_native_container_state(&state).map_err(str::to_owned)?;
        // Compose-generated dependency identity, not a runner-supplied
        // shell command or hard-coded per-machine startup order.
        let mut dependencies = Vec::new();
        if let Some(value) = labels.get("com.docker.compose.depends_on") {
            for entry in value.split(',').filter(|entry| !entry.is_empty()) {
                let service = entry.split(':').next().unwrap_or("");
                if service == resource.compose_service
                    || !expected.iter().any(|item| item.compose_service == service)
                    || dependencies.iter().any(|known| known == service)
                {
                    return Err("HOST_NATIVE_CONTAINER_DEPENDENCY_UNTRUSTED".into());
                }
                dependencies.push(service.to_owned());
            }
        }
        let image_ref = config
            .image
            .clone()
            .ok_or("HOST_NATIVE_CONTAINER_IMAGE_UNPROVEN")?;
        owned.push(OwnedVmContainer {
            id,
            running,
            service: resource.compose_service.clone(),
            dependencies,
            image_ref,
        });
    }
    Ok(owned)
}

/// Root-only read-only preadmission check, shared with the STOP effector.
pub(crate) async fn verify_owned_application_containers(
    expected: &[FleetVmContainer],
) -> Result<(), String> {
    let docker = docker_connection().await?;
    owned_application_container_ids(&docker, expected)
        .await
        .map(|_| ())
}

/// One ephemeral native pre-BEGIN snapshot. Not a new persistent journal,
/// authority, or credential. The signed host journal still owns the one-shot
/// transaction for the entire application.
#[derive(Debug)]
pub(crate) struct NativeVmRunPlan {
    step: FleetHostPlannedStep,
    identities: Vec<Option<(String, bool, String)>>,
    desired_graph: Option<edge_shared_types::FleetVmDesiredGraph>,
    // Exactly one missing gateway can be re-created without touching the
    // existing WARP, sibling gateway, shared network, or release marker.
    create_missing: Option<String>,
    prepared_create: Option<bollard::models::ContainerCreateBody>,
    // Raw immutable Compose bytes complement the projected DAG, which does
    // not itself cover published ports and host mount sources.
    compose_sha256: Option<Vec<u8>>,
    edge_network_id: Option<String>,
}

fn check_owned_vm_snapshot(
    host: &FleetHost,
    owned: &[OwnedVmContainer],
    identities: &[Option<(String, bool, String)>],
) -> Result<(), String> {
    if host.vm_containers.len() != identities.len() {
        return Err("HOST_NATIVE_VM_SNAPSHOT_SCOPE_CHANGED".into());
    }
    for (resource, original) in host.vm_containers.iter().zip(identities) {
        let observed = owned
            .iter()
            .find(|item| item.service == resource.compose_service);
        match (original, observed) {
            (None, None) => {}
            (Some((id, was_running, image)), Some(current))
                if id == &current.id
                    && *was_running == current.running
                    && image == &current.image_ref => {}
            _ => return Err("HOST_NATIVE_VM_IDENTITY_OR_STATE_CHANGED_NO_REPLAY".into()),
        }
    }
    Ok(())
}

/// Pure, closed-scope selection. INSTALL at resource level means a
/// missing container; it must never escalate to the whole-stack bootstrap.
fn select_scoped_vm_create(
    host: &FleetHost,
    plan: &edge_shared_types::FleetVmResourceTransitionPlan,
    step: FleetHostPlannedStep,
) -> Result<Option<String>, String> {
    if step != FleetHostPlannedStep::Start {
        return Ok(None);
    }
    let absent = plan
        .resources
        .iter()
        .filter(|entry| entry.step == FleetHostPlannedStep::Install as i32)
        .collect::<Vec<_>>();
    if absent.is_empty() {
        return Ok(None);
    }
    let [target] = absent.as_slice() else {
        return Err("HOST_VM_CREATE_MULTIPLE_MISSING_RESOURCES".into());
    };
    let resource = target
        .resource
        .as_ref()
        .ok_or("HOST_VM_CREATE_RESOURCE_IDENTITY_MISSING")?;
    if !matches!(
        resource.compose_service.as_str(),
        "line1-gateway" | "line2-proxy"
    ) || !host.vm_containers.contains(resource)
        || plan.resources.iter().any(|entry| {
            entry.resource.as_ref() != Some(resource)
                && entry.step != FleetHostPlannedStep::Noop as i32
        })
    {
        return Err("HOST_VM_CREATE_SCOPE_OR_NEIGHBOUR_NOT_READY".into());
    }
    Ok(Some(resource.compose_service.clone()))
}

/// The two gateways use only an existing, owned Compose edge_net bridge.
/// Never create/adopt Mesh or an unrelated network as a side effect of
/// recovering one missing container.
fn verify_scoped_gateway_network_policy(
    host: &FleetHost,
    graph: &edge_shared_types::FleetVmDesiredGraph,
    service: &str,
) -> Result<(), String> {
    // The existing native Compose effector implements exactly this network.
    // Other Git-owned networks remain typed proposals and need their own
    // actual native handler; never silently adopt Docker's implicit default.
    let [network] = graph.networks.as_slice() else {
        return Err("HOST_VM_CREATE_NETWORK_SCOPE_UNSUPPORTED".into());
    };
    if network.network_name != "edge_net"
        || network.driver != "bridge"
        || !network
            .attached_services
            .iter()
            .any(|member| member == service)
    {
        return Err("HOST_VM_CREATE_NETWORK_SCOPE_UNSUPPORTED".into());
    }
    use edge_shared_types::{FleetResourceKind as Kind, FleetResourceOwner as Owner};
    let hierarchy = edge_shared_types::host_resources::derive_vm_resource_hierarchy(host, graph)
        .map_err(str::to_owned)?;
    let selector = host
        .vm_containers
        .iter()
        .find(|item| item.compose_service == service)
        .ok_or("HOST_VM_CREATE_RESOURCE_NOT_REGISTERED")?;
    let resource_id = edge_shared_types::host_resources::vm_container_resource_id(host, selector)
        .map_err(str::to_owned)?;
    let node = hierarchy
        .nodes
        .iter()
        .find(|item| item.resource_id == resource_id)
        .ok_or("HOST_VM_CREATE_RESOURCE_NODE_MISSING")?;
    let network_id = format!(
        "network/{}/{}",
        network.compose_project, network.network_name
    );
    if !matches!(service, "line1-gateway" | "line2-proxy")
        || node.kind != Kind::DockerContainer as i32
        || node.owner != Owner::VmRootAgent as i32
        || node.parent_resource_id != format!("host/{}", host.machine_id)
        || !node.dependency_ids.contains(&network_id)
    {
        return Err("HOST_VM_CREATE_RESOURCE_GRAPH_SCOPE_INVALID".into());
    }
    Ok(())
}

/// This is an exact Docker endpoint identity, not a successful DNS lookup
/// or public access check. No foreign/Mesh network is allowed in this native
/// application's gateway recovery path.
fn exact_owned_network_attachment(
    observed: Option<&HashMap<String, bollard::models::EndpointSettings>>,
    compose_network_name: &str,
    expected_network_id: &str,
) -> bool {
    observed.is_some_and(|networks| {
        networks.len() == 1
            && networks
                .get(compose_network_name)
                .and_then(|endpoint| endpoint.network_id.as_deref())
                == Some(expected_network_id)
    })
}

async fn verify_vm_network_attachments(
    docker: &Docker,
    host: &FleetHost,
    owned: &[OwnedVmContainer],
    network_id: &str,
) -> Result<(), String> {
    let project = host
        .vm_containers
        .first()
        .ok_or("HOST_VM_NETWORK_OWNER_MISSING")?
        .compose_project
        .as_str();
    let name = format!("{project}_edge_net");
    for container in owned {
        let inspect = docker
            .inspect_container(&container.id, None)
            .await
            .map_err(|_| "HOST_VM_NETWORK_CONTAINER_INSPECT_FAILED")?;
        if inspect.id.as_deref() != Some(container.id.as_str())
            || !exact_owned_network_attachment(
                inspect
                    .network_settings
                    .as_ref()
                    .and_then(|settings| settings.networks.as_ref()),
                &name,
                network_id,
            )
        {
            return Err("HOST_VM_NETWORK_ATTACHMENT_UNPROVEN".into());
        }
    }
    Ok(())
}

/// Exact Docker network ID + Compose labels, from the engine itself. A
/// successful file read or a guessed name is not proof of network ownership.
async fn read_owned_edge_network_id(docker: &Docker, host: &FleetHost) -> Result<String, String> {
    let project = host
        .vm_containers
        .first()
        .ok_or("HOST_VM_CREATE_PROJECT_UNPROVEN")?
        .compose_project
        .as_str();
    if host
        .vm_containers
        .iter()
        .any(|item| item.compose_project != project)
    {
        return Err("HOST_VM_CREATE_PROJECT_IDENTITY_CHANGED".into());
    }
    let name = format!("{project}_edge_net");
    let network = docker
        .inspect_network(&name, None)
        .await
        .map_err(|_| "HOST_VM_CREATE_OWNED_NETWORK_MISSING")?;
    if network.name.as_deref() != Some(name.as_str())
        || network.driver.as_deref() != Some("bridge")
        || !network.labels.as_ref().is_some_and(|labels| {
            labels.get("com.docker.compose.project").map(String::as_str) == Some(project)
                && labels.get("com.docker.compose.network").map(String::as_str) == Some("edge_net")
        })
    {
        return Err("HOST_VM_CREATE_NETWORK_OWNER_UNPROVEN".into());
    }
    let id = network.id.ok_or("HOST_VM_CREATE_NETWORK_ID_UNPROVEN")?;
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("HOST_VM_CREATE_NETWORK_ID_INVALID".into());
    }
    Ok(id)
}

/// Compile exactly one owned gateway into native Docker Engine API fields.
/// Resolve the common typed resource planner against root-local Docker
/// evidence BEFORE the journal BEGIN. A single absent owned gateway may
/// use native Docker CREATE; other resources must be unchanged and ready.
pub(crate) async fn preflight_native_vm_run(
    stack_dir: &Path,
    host: &FleetHost,
    step: FleetHostPlannedStep,
) -> Result<NativeVmRunPlan, String> {
    if !matches!(
        step,
        FleetHostPlannedStep::Start | FleetHostPlannedStep::Stop
    ) {
        return Err("HOST_NATIVE_VM_RUN_STEP_INVALID".into());
    }
    let readback = observe_vm_resource_report(host, stack_dir).await?;
    let plan = edge_shared_types::host_resources::propose_vm_resource_transitions(host, &readback)
        .map_err(str::to_owned)?;
    let create_missing = select_scoped_vm_create(host, &plan, step)?;
    let mut changed = 0;
    for resource in &plan.resources {
        let candidate = FleetHostPlannedStep::try_from(resource.step)
            .map_err(|_| "HOST_NATIVE_VM_RESOURCE_STEP_INVALID")?;
        match candidate {
            FleetHostPlannedStep::Noop => {}
            value if value == step && create_missing.is_none() => changed += 1,
            FleetHostPlannedStep::Install
                if create_missing.as_deref()
                    == resource
                        .resource
                        .as_ref()
                        .map(|item| item.compose_service.as_str()) =>
            {
                changed += 1;
            }
            _ => return Err("HOST_NATIVE_VM_RESOURCE_PLAN_BLOCKED".into()),
        }
    }
    if changed == 0 {
        return Err("HOST_NATIVE_VM_RESOURCE_NO_MUTATION_REQUIRED".into());
    }
    let desired_graph = if step == FleetHostPlannedStep::Start {
        let graph = compile_native_vm_desired_graph(stack_dir, host)?;
        edge_shared_types::host_resources::validate_vm_native_start_dag(host, &graph, &plan)
            .map_err(str::to_owned)?;
        Some(graph)
    } else {
        // An emergency STOP must not require valid config templates.
        None
    };
    let compose_sha256 = if desired_graph.is_some() {
        Some(native_vm_compose_digest(stack_dir)?)
    } else {
        None
    };
    let identities = readback
        .resources
        .iter()
        .map(|item| {
            item.present
                .then(|| (item.container_id.clone(), item.running, item.image.clone()))
        })
        .collect::<Vec<_>>();
    let docker = docker_connection().await?;
    let mut owned = if step == FleetHostPlannedStep::Start && create_missing.is_none() {
        prepare_owned_vm_start(&docker, stack_dir, &host.vm_containers)
            .await?
            .0
    } else {
        owned_application_container_ids(&docker, &host.vm_containers).await?
    };
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut owned)?;
    check_owned_vm_snapshot(host, &owned, &identities)?;
    let mut edge_network_id = None;
    let mut prepared_create = None;
    if let Some(service) = create_missing.as_deref() {
        if owned.len() + 1 != host.vm_containers.len() || owned.iter().any(|item| !item.running) {
            return Err("HOST_VM_CREATE_NEIGHBOUR_INCOMPLETE".into());
        }
        verify_scoped_gateway_network_policy(
            host,
            desired_graph
                .as_ref()
                .ok_or("HOST_VM_CREATE_DESIRED_GRAPH_MISSING")?,
            service,
        )?;
        let expected = read_vm_expected_image_refs(stack_dir, &host.vm_containers)?;
        for item in &owned {
            if expected.get(&item.service) != Some(&item.image_ref) {
                return Err("HOST_VM_CREATE_NEIGHBOUR_IMAGE_DRIFT".into());
            }
        }
        let missing_image = expected
            .get(service)
            .ok_or("HOST_VM_CREATE_PINNED_IMAGE_MISSING")?;
        docker
            .inspect_image(missing_image)
            .await
            .map_err(|_| "HOST_VM_CREATE_LOCAL_IMAGE_UNAVAILABLE")?;
        let id = read_owned_edge_network_id(&docker, host).await?;
        verify_vm_network_attachments(&docker, host, &owned, &id).await?;
        prepared_create = Some(native_gateway_create_body(
            stack_dir,
            host,
            service,
            missing_image,
            &id,
        )?);
        if compose_sha256.as_deref() != Some(native_vm_compose_digest(stack_dir)?.as_slice()) {
            return Err("HOST_VM_CREATE_COMPOSE_CHANGED_DURING_PREFLIGHT".into());
        }
        edge_network_id = Some(id);
    }
    if step == FleetHostPlannedStep::Stop {
        owned_vm_stop_order(&owned)?;
    } else {
        owned_vm_start_order(&owned)?;
    }
    Ok(NativeVmRunPlan {
        step,
        identities,
        desired_graph,
        create_missing,
        prepared_create,
        compose_sha256,
        edge_network_id,
    })
}

/// After durable BEGIN, re-inspect all exact Compose-owned Docker IDs before
/// touching a single resource. Reject an ABA replacement or state race rather
/// than silently re-targeting a signed operation to a new container.
pub(crate) async fn apply_native_vm_run_once(
    stack_dir: &Path,
    host: &FleetHost,
    plan: NativeVmRunPlan,
) -> Result<(), String> {
    let docker = docker_connection().await?;
    let mut owned = owned_application_container_ids(&docker, &host.vm_containers).await?;
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut owned)?;
    check_owned_vm_snapshot(host, &owned, &plan.identities)?;
    if let Some(expected) = plan.compose_sha256.as_deref()
        && native_vm_compose_digest(stack_dir)?.as_slice() != expected
    {
        return Err("HOST_VM_COMPOSE_BYTES_CHANGED_BEFORE_MUTATION_NO_REPLAY".into());
    }
    if let Some(graph) = &plan.desired_graph
        && compile_native_vm_desired_graph(stack_dir, host)? != *graph
    {
        return Err("HOST_VM_GRAPH_CHANGED_BEFORE_MUTATION".into());
    }
    if plan.step == FleetHostPlannedStep::Start {
        let images = read_vm_expected_image_refs(stack_dir, &host.vm_containers)?;
        for container in &owned {
            if images.get(&container.service) != Some(&container.image_ref) {
                return Err("HOST_NATIVE_VM_START_IMAGE_MISMATCH_NO_REPLAY".into());
            }
        }
    }
    let order = if plan.step == FleetHostPlannedStep::Stop {
        owned_vm_stop_order(&owned)?
    } else {
        owned_vm_start_order(&owned)?
    };
    if let Some(service) = plan.create_missing.as_deref() {
        if plan.step != FleetHostPlannedStep::Start
            || owned.len() + 1 != host.vm_containers.len()
            || owned.iter().any(|item| !item.running)
            || plan.edge_network_id.as_deref()
                != Some(read_owned_edge_network_id(&docker, host).await?.as_str())
        {
            return Err("HOST_VM_CREATE_PREADMISSION_CHANGED_NO_REPLAY".into());
        }
        verify_scoped_gateway_network_policy(
            host,
            plan.desired_graph
                .as_ref()
                .ok_or("HOST_VM_CREATE_DESIRED_GRAPH_MISSING_NO_REPLAY")?,
            service,
        )?;
        verify_vm_network_attachments(
            &docker,
            host,
            &owned,
            plan.edge_network_id
                .as_deref()
                .ok_or("HOST_VM_CREATE_NETWORK_PRESTATE_UNPROVEN_NO_REPLAY")?,
        )
        .await?;
        // One native Docker Engine CREATE + START, compiled pre-BEGIN.
        // Uncertain Docker ACK leaves the signed journal pending, no replay.
        let config = plan
            .prepared_create
            .as_ref()
            .ok_or("HOST_VM_CREATE_PREPARED_BODY_MISSING_NO_REPLAY")?
            .clone();
        let selector = host
            .vm_containers
            .iter()
            .find(|item| item.compose_service == service)
            .ok_or("HOST_VM_CREATE_SELECTOR_MISSING_NO_REPLAY")?;
        let options = bollard::query_parameters::CreateContainerOptionsBuilder::default()
            .name(&selector.container_name)
            .build();
        let created = docker
            .create_container(Some(options), config)
            .await
            .map_err(|_| "HOST_VM_CREATE_ACK_UNCERTAIN_NO_REPLAY")?;
        if created.id.len() != 64 || !created.id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("HOST_VM_CREATE_ID_UNPROVEN_NO_REPLAY".into());
        }
        docker
            .start_container(
                &created.id,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await
            .map_err(|_| "HOST_VM_CREATE_START_UNCERTAIN_NO_REPLAY")?;
    }
    for index in order {
        let container = &owned[index];
        match plan.step {
            FleetHostPlannedStep::Start if !container.running => {
                docker
                    .start_container(
                        &container.id,
                        None::<bollard::query_parameters::StartContainerOptions>,
                    )
                    .await
                    .map_err(|_| "HOST_NATIVE_VM_START_UNCERTAIN_NO_REPLAY")?;
            }
            FleetHostPlannedStep::Stop if container.running => {
                docker
                    .stop_container(
                        &container.id,
                        Some(
                            bollard::query_parameters::StopContainerOptionsBuilder::default()
                                .t(20)
                                .build(),
                        ),
                    )
                    .await
                    .map_err(|_| "HOST_NATIVE_VM_STOP_UNCERTAIN_NO_REPLAY")?;
            }
            FleetHostPlannedStep::Start | FleetHostPlannedStep::Stop => {}
            _ => return Err("HOST_NATIVE_VM_RUN_STEP_INVALID".into()),
        }
    }
    // One exact Docker poststate for every registered resource before
    // the existing signed host journal releases the operation gate.
    let mut after = owned_application_container_ids(&docker, &host.vm_containers).await?;
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut after)?;
    verify_native_vm_run_poststate(host, &plan, &after)?;
    if let Some(expected) = plan.edge_network_id.as_deref() {
        if read_owned_edge_network_id(&docker, host).await?.as_str() != expected {
            return Err("HOST_VM_CREATE_NETWORK_CHANGED_NO_REPLAY".into());
        }
        verify_vm_network_attachments(&docker, host, &after, expected)
            .await
            .map_err(|_| "HOST_VM_CREATE_NETWORK_ATTACHMENT_NO_REPLAY")?;
    }
    if let Some(graph) = &plan.desired_graph
        && compile_native_vm_desired_graph(stack_dir, host)? != *graph
    {
        return Err("HOST_VM_GRAPH_POSTSTATE_CHANGED_NO_REPLAY".into());
    }
    Ok(())
}

/// Trust dependencies only from the same installed Compose manifest that
/// declares the immutable service images. Docker labels are corroborating
/// evidence, not an alternative desired-state authority.
fn resolve_compose_dependencies(
    compose: &serde_yaml::Value,
    expected: &[FleetVmContainer],
) -> Result<HashMap<String, Vec<String>>, String> {
    let services = compose
        .get("services")
        .ok_or("HOST_NATIVE_COMPOSE_SERVICES_UNPROVEN")?;
    if expected.is_empty()
        || expected
            .iter()
            .any(|item| item.compose_project != expected[0].compose_project)
        || compose.get("name").and_then(serde_yaml::Value::as_str)
            != Some(expected[0].compose_project.as_str())
    {
        return Err("HOST_NATIVE_COMPOSE_PROJECT_MISMATCH".into());
    }
    let mut result = HashMap::new();
    for resource in expected {
        let service = services
            .get(resource.compose_service.as_str())
            .ok_or("HOST_NATIVE_COMPOSE_SERVICE_MISSING")?;
        let mut deps = Vec::new();
        match service.get("depends_on") {
            None | Some(serde_yaml::Value::Null) => {}
            Some(serde_yaml::Value::Sequence(sequence)) => {
                for item in sequence {
                    deps.push(
                        item.as_str()
                            .ok_or("HOST_NATIVE_COMPOSE_DEPENDENCY_INVALID")?
                            .to_owned(),
                    );
                }
            }
            Some(serde_yaml::Value::Mapping(mapping)) => {
                for (key, _) in mapping {
                    deps.push(
                        key.as_str()
                            .ok_or("HOST_NATIVE_COMPOSE_DEPENDENCY_INVALID")?
                            .to_owned(),
                    );
                }
            }
            _ => return Err("HOST_NATIVE_COMPOSE_DEPENDENCY_INVALID".into()),
        }
        let mut seen = BTreeSet::new();
        for dependency in &deps {
            if dependency == &resource.compose_service
                || !expected
                    .iter()
                    .any(|item| item.compose_service == *dependency)
                || !seen.insert(dependency.as_str())
            {
                return Err("HOST_NATIVE_COMPOSE_DEPENDENCY_OUTSIDE_OWNER_SCOPE".into());
            }
        }
        result.insert(resource.compose_service.clone(), deps);
    }
    Ok(result)
}

fn bind_owned_vm_compose_dependencies(
    stack_dir: &Path,
    expected: &[FleetVmContainer],
    owned: &mut [OwnedVmContainer],
) -> Result<(), String> {
    let compose = read_native_vm_compose(stack_dir)?;
    let declared = resolve_compose_dependencies(&compose, expected)?;
    for container in owned {
        let expected = declared
            .get(&container.service)
            .ok_or("HOST_NATIVE_COMPOSE_SERVICE_MISSING")?;
        // Compose 2 sometimes omits this label. Never substitute its absent
        // value for the canonical dependency graph, and reject contradictions.
        if !container.dependencies.is_empty()
            && container.dependencies.iter().collect::<BTreeSet<_>>()
                != expected.iter().collect::<BTreeSet<_>>()
        {
            return Err("HOST_NATIVE_DOCKER_DEPENDENCY_LABEL_MISMATCH".into());
        }
        container.dependencies.clone_from(expected);
    }
    Ok(())
}

/// Compile exact Docker network ownership and service membership from the
/// same Compose YAML as the OCI image references. Unsupported network modes
/// are rejected before BEGIN, not hidden behind Docker Compose defaults.
fn compile_vm_networks_from_compose(
    host: &FleetHost,
    compose: &serde_yaml::Value,
) -> Result<Vec<edge_shared_types::FleetVmDesiredNetwork>, String> {
    let mut networks = BTreeMap::<String, Vec<String>>::new();
    let services = compose
        .get("services")
        .ok_or("HOST_VM_COMPOSE_SERVICES_MISSING")?;
    let declarations = compose
        .get("networks")
        .ok_or("HOST_VM_NETWORK_DECLARATIONS_MISSING")?;
    for selector in &host.vm_containers {
        let attachments = services
            .get(&selector.compose_service)
            .and_then(|service| service.get("networks"))
            .and_then(serde_yaml::Value::as_sequence)
            .ok_or("HOST_VM_NETWORK_IMPLICIT_OR_INVALID")?;
        if attachments.len() != 1 {
            return Err("HOST_VM_NETWORK_MULTI_ATTACHMENT_UNSUPPORTED".into());
        }
        let name = attachments[0]
            .as_str()
            .ok_or("HOST_VM_NETWORK_ATTACHMENT_NOT_TYPED")?;
        networks
            .entry(name.to_owned())
            .or_default()
            .push(selector.compose_service.clone());
    }
    let project = host
        .vm_containers
        .first()
        .ok_or("HOST_VM_NETWORK_OWNER_SCOPE_MISSING")?
        .compose_project
        .clone();
    let mut graph_networks = Vec::new();
    for (network_name, attached_services) in networks {
        let policy = declarations
            .get(&network_name)
            .and_then(serde_yaml::Value::as_mapping)
            .ok_or("HOST_VM_NETWORK_POLICY_MISSING")?;
        if policy.len() != 1
            || policy.get("driver").and_then(serde_yaml::Value::as_str) != Some("bridge")
        {
            return Err("HOST_VM_NETWORK_POLICY_UNSUPPORTED".into());
        }
        graph_networks.push(edge_shared_types::FleetVmDesiredNetwork {
            compose_project: project.clone(),
            network_name,
            driver: "bridge".into(),
            attached_services,
        });
    }
    Ok(graph_networks)
}

// A stage-stamped native error: provenance is assigned where a failure
// occurs, never guessed by searching the error text. The code is bounded,
// non-secret and never used as an admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeVmPolicyFailure {
    status: edge_shared_types::FleetVmInstalledPolicyStatus,
    code: String,
}

impl NativeVmPolicyFailure {
    fn at(status: edge_shared_types::FleetVmInstalledPolicyStatus, error: impl AsRef<str>) -> Self {
        let error = error.as_ref();
        let code = if error.starts_with("HOST_")
            && error.len() <= 128
            && error
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            error.to_owned()
        } else {
            "HOST_VM_POLICY_ERROR_UNCLASSIFIED".to_owned()
        };
        Self { status, code }
    }
}

/// One typed graph compiler for BOTH immutable Git bundle desired and
/// root-local actual policy. This never infers desired from installed files.
fn compile_vm_graph_from_parts(
    host: &FleetHost,
    compose: &serde_yaml::Value,
    env: &BTreeMap<String, String>,
    mut template_bytes: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<edge_shared_types::FleetVmDesiredGraph, NativeVmPolicyFailure> {
    use edge_shared_types::{
        FleetVmDesiredGraph, FleetVmDesiredResource, FleetVmInstalledPolicyStatus as Status,
    };
    let images = resolve_owned_vm_images(compose, env, &host.vm_containers)
        .map_err(|error| NativeVmPolicyFailure::at(Status::ImageInvalid, error))?;
    let deps = resolve_compose_dependencies(compose, &host.vm_containers)
        .map_err(|error| NativeVmPolicyFailure::at(Status::DependencyInvalid, error))?;
    let networks = compile_vm_networks_from_compose(host, compose)
        .map_err(|error| NativeVmPolicyFailure::at(Status::NetworkInvalid, error))?;
    let mut resources = Vec::with_capacity(host.vm_containers.len());
    for identity in &host.vm_containers {
        let template = match identity.compose_service.as_str() {
            "line1-gateway" => Some("line1-gateway/config.template.json"),
            "line2-proxy" => Some("line2-proxy/config.template.json"),
            _ => None,
        };
        let config_template_sha256 = if let Some(path) = template {
            ring::digest::digest(
                &ring::digest::SHA256,
                &template_bytes(path)
                    .map_err(|error| NativeVmPolicyFailure::at(Status::ConfigInvalid, error))?,
            )
            .as_ref()
            .to_vec()
        } else {
            Vec::new()
        };
        resources.push(FleetVmDesiredResource {
            resource: Some(identity.clone()),
            image_ref: images
                .get(&identity.compose_service)
                .ok_or_else(|| {
                    NativeVmPolicyFailure::at(Status::ImageInvalid, "HOST_VM_GRAPH_IMAGE_MISSING")
                })?
                .clone(),
            dependencies: deps
                .get(&identity.compose_service)
                .ok_or_else(|| {
                    NativeVmPolicyFailure::at(
                        Status::DependencyInvalid,
                        "HOST_VM_GRAPH_DEPENDENCY_MISSING",
                    )
                })?
                .clone(),
            config_template_sha256,
        });
    }
    let graph = FleetVmDesiredGraph {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        resources,
        networks,
    };
    edge_shared_types::host_resources::derive_vm_resource_hierarchy(host, &graph)
        .map_err(|error| NativeVmPolicyFailure::at(Status::OtherInvalid, error))?;
    Ok(graph)
}

/// ActualGraph: solely the installed policy; NEVER a target or authority.
/// The diagnostic caller receives a stage-stamped error; existing native
/// mutation callers get the same static error code via the single adapter.
fn compile_native_vm_policy_checked(
    stack_dir: &Path,
    host: &FleetHost,
) -> Result<edge_shared_types::FleetVmDesiredGraph, NativeVmPolicyFailure> {
    use edge_shared_types::FleetVmInstalledPolicyStatus as Status;
    let compose = read_native_vm_compose(stack_dir)
        .map_err(|error| NativeVmPolicyFailure::at(Status::ComposeInvalid, error))?;
    let env = super::read_exact_image_environment(stack_dir)
        .map_err(|error| NativeVmPolicyFailure::at(Status::ImageInvalid, error))?;
    compile_vm_graph_from_parts(host, &compose, &env, |path| {
        exact_vm_policy_file(stack_dir, path)
    })
}

fn compile_native_vm_desired_graph(
    stack_dir: &Path,
    host: &FleetHost,
) -> Result<edge_shared_types::FleetVmDesiredGraph, String> {
    compile_native_vm_policy_checked(stack_dir, host).map_err(|error| error.code)
}

/// Parse immutable bundle image pins in memory, without installing or
/// temporarily mounting caller-controlled files on the privileged host.
fn parse_vm_release_image_pins(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "HOST_VM_RELEASE_IMAGES_NOT_UTF8")?;
    let mut images = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("HOST_VM_RELEASE_IMAGE_LINE_INVALID")?;
        if key.is_empty()
            || key.trim() != key
            || value.is_empty()
            || images.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err("HOST_VM_RELEASE_IMAGE_LINE_INVALID".into());
        }
    }
    let keys = images.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if keys
        != BTreeSet::from([
            "EDGE_GATEWAY_IMAGE",
            "EDGE_WARP_EGRESS_IMAGE",
            "CLOUDFLARE_MESH_IMAGE",
        ])
    {
        return Err("HOST_VM_RELEASE_IMAGE_KEYS_INVALID".into());
    }
    for (key, repository) in [
        ("EDGE_GATEWAY_IMAGE", "ghcr.io/iamaman11/vultr-edge-gateway"),
        (
            "EDGE_WARP_EGRESS_IMAGE",
            "ghcr.io/iamaman11/vultr-warp-egress",
        ),
        ("CLOUDFLARE_MESH_IMAGE", "docker.io/cloudflare/mesh"),
    ] {
        super::validate_exact_image_ref(key, &images[key], repository)?;
    }
    Ok(images)
}

/// DesiredGraph: compile independently from the exact immutable signed
/// ReleaseSet application bundle. No installed Compose/template bytes, runner
/// variables, mutable on-host files, or second desired registry are consulted.
pub(crate) fn compile_vm_desired_graph_from_release(
    host: &FleetHost,
    request: &ApplyBundleRequest,
) -> Result<edge_shared_types::FleetVmDesiredGraph, String> {
    super::validate_digest_bound_bundle_request(request)
        .map_err(|_| "HOST_VM_RELEASE_BUNDLE_INVALID")?;
    let mut files = BTreeMap::new();
    for file in &request.stack_files {
        if files
            .insert(file.relative_path.as_str(), file.content.as_slice())
            .is_some()
        {
            return Err("HOST_VM_RELEASE_FILE_DUPLICATE".into());
        }
    }
    let compose = serde_yaml::from_slice::<serde_yaml::Value>(
        files
            .get("docker-compose.yml")
            .ok_or("HOST_VM_RELEASE_COMPOSE_MISSING")?,
    )
    .map_err(|_| "HOST_VM_RELEASE_COMPOSE_INVALID")?;
    let images = parse_vm_release_image_pins(
        files
            .get(".images.env")
            .ok_or("HOST_VM_RELEASE_IMAGES_MISSING")?,
    )?;
    let graph = compile_vm_graph_from_parts(host, &compose, &images, |path| {
        files
            .get(path)
            .filter(|content| !content.is_empty())
            .map(|content| content.to_vec())
            .ok_or_else(|| "HOST_VM_RELEASE_TEMPLATE_MISSING".to_owned())
    })
    .map_err(|error| error.code)?;
    validate_gateway_image_ownership(
        &graph,
        images
            .get("EDGE_GATEWAY_IMAGE")
            .ok_or("HOST_VM_RELEASE_GATEWAY_MISSING")?,
    )?;
    Ok(graph)
}

/// Compare a complete native after-image with the prepared per-resource
/// before-image. This is proof of a single Docker transition, NOT of external
/// TLS/auth or of the application reading new configuration bytes.
fn verify_native_vm_run_poststate(
    host: &FleetHost,
    plan: &NativeVmRunPlan,
    after: &[OwnedVmContainer],
) -> Result<(), String> {
    if plan.identities.len() != host.vm_containers.len() {
        return Err("HOST_NATIVE_VM_POSTSTATE_SCOPE_MISMATCH".into());
    }
    let desired_running = match plan.step {
        FleetHostPlannedStep::Start => true,
        FleetHostPlannedStep::Stop => false,
        _ => return Err("HOST_NATIVE_VM_POSTSTATE_STEP_UNSUPPORTED".into()),
    };
    let mut changes = 0;
    for (selector, expected) in host.vm_containers.iter().zip(&plan.identities) {
        let observed = after
            .iter()
            .find(|item| item.service == selector.compose_service);
        match (expected, observed) {
            (None, None) if !desired_running => {}
            (None, Some(current))
                if desired_running
                    && plan.create_missing.as_deref()
                        == Some(selector.compose_service.as_str())
                    && current.running
                    && plan.desired_graph.as_ref().is_some_and(|graph| {
                        graph.resources.iter().any(|resource| {
                            resource.resource.as_ref() == Some(selector)
                                && resource.image_ref == current.image_ref
                        })
                    }) =>
            {
                changes += 1;
            }
            (Some((id, was_running, image)), Some(current))
                if current.id == *id && current.image_ref == *image =>
            {
                if current.running != desired_running {
                    return Err("HOST_NATIVE_VM_POSTSTATE_NOT_CONVERGED_NO_REPLAY".into());
                }
                if *was_running != desired_running {
                    changes += 1;
                }
            }
            _ => return Err("HOST_NATIVE_VM_POSTSTATE_OWNER_CHANGED_NO_REPLAY".into()),
        }
    }
    if changes == 0 || after.len() > host.vm_containers.len() {
        return Err("HOST_NATIVE_VM_POSTSTATE_CHANGE_UNPROVEN_NO_REPLAY".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeVmCredentialPin {
    delivery_generation: u64,
    // In-memory only. Never returned through host status or the Worker.
    exact_bundle_sha256: [u8; 32],
}

/// Bind one worker-authored active generation to an immutable signed
/// HostIntent preflight. Any A/B cursor change before BEGIN-owned materialization
/// is an explicit fail-closed no-replay result, never a credential fallback.
fn pin_active_native_vm_credential(
    bundle: &edge_shared_types::CredentialDeliveryBundle,
) -> Result<NativeVmCredentialPin, String> {
    if bundle.schema_version != 1
        || bundle.generation == 0
        || bundle.projection != edge_shared_types::CredentialProjectionKind::Vm as i32
        || bundle.dummy_non_secret
    {
        return Err("HOST_VM_INSTALL_V2_ACTIVE_IDENTITY_INVALID".into());
    }
    super::ApplicationRuntimeSecrets::from_vm_bundle(bundle)
        .map_err(|_| "HOST_VM_INSTALL_V2_ACTIVE_PAYLOAD_INVALID")?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bundle.encode_to_vec());
    let mut exact_bundle_sha256 = [0u8; 32];
    exact_bundle_sha256.copy_from_slice(digest.as_ref());
    Ok(NativeVmCredentialPin {
        delivery_generation: bundle.generation,
        exact_bundle_sha256,
    })
}

#[cfg(test)]
mod native_vm_worker_pin_tests {
    use super::*;

    #[test]
    fn worker_active_origin_must_match_exact_pinned_generation_and_sha256() {
        let expected = NativeVmCredentialPin {
            delivery_generation: 17,
            exact_bundle_sha256: [0x7a; 32],
        };
        let mut origin = edge_secrets::CredentialOriginObservation {
            generation: 17,
            slot: "B",
            bundle_sha256: "7a".repeat(32),
        };
        assert!(verify_native_vm_install_worker_pin(&expected, &origin).is_ok());
        origin.generation = 18;
        assert_eq!(
            verify_native_vm_install_worker_pin(&expected, &origin),
            Err("HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_MISMATCH"),
        );
        origin.generation = 17;
        origin.bundle_sha256 = "7b".repeat(32);
        assert!(verify_native_vm_install_worker_pin(&expected, &origin).is_err());
        origin.bundle_sha256 = "7a".repeat(32);
        origin.slot = "C";
        assert!(verify_native_vm_install_worker_pin(&expected, &origin).is_err());
    }
}

// Never derive Debug for a plan that may temporarily hold a fresh secret.
pub(crate) struct NativeVmInstallPlan {
    request: ApplyBundleRequest,
    graph: edge_shared_types::FleetVmDesiredGraph,
    project: String,
    gateway_image: String,
    warp_image: String,
    credential_pin: NativeVmCredentialPin,
    first_use_bundle: Option<edge_shared_types::CredentialDeliveryBundle>,
}

/// The selected generation and the complete canonical Worker-v2 bundle
/// digest are part of signed Git desired. No credentials, URLs or payload
/// may be supplied by the runner or the signed command comment.
fn verify_native_vm_first_use_identity(
    host: &FleetHost,
    bundle: &edge_shared_types::CredentialDeliveryBundle,
) -> Result<NativeVmCredentialPin, &'static str> {
    let identity = host
        .vm_first_use_credential
        .as_ref()
        .ok_or("HOST_VM_INSTALL_GIT_FIRST_USE_IDENTITY_REQUIRED")?;
    if identity.generation == 0 || bundle.generation != identity.generation {
        return Err("HOST_VM_INSTALL_GIT_FIRST_USE_GENERATION_MISMATCH");
    }
    let digest = edge_shared_types::credential_delivery_bundle_sha256(bundle)
        .map_err(|_| "HOST_VM_INSTALL_WORKER_FIRST_USE_BUNDLE_INVALID")?;
    if digest != identity.bundle_sha256 {
        return Err("HOST_VM_INSTALL_GIT_FIRST_USE_DIGEST_MISMATCH");
    }
    pin_active_native_vm_credential(bundle)
        .map_err(|_| "HOST_VM_INSTALL_WORKER_FIRST_USE_PAYLOAD_INVALID")
}

/// A read-only, point-in-time Worker proof for deep status. Never outputs
/// credential values and never gives the runner mutation authority. The
/// signed native INSTALL always repeats this check after taking the root lock.
fn classify_native_vm_first_use_source(
    host: &FleetHost,
    remote: Result<edge_shared_types::CredentialDeliveryBundle, String>,
) -> edge_shared_types::FleetVmBootstrapPhase {
    use edge_shared_types::FleetVmBootstrapPhase as Phase;
    match remote {
        Ok(bundle) if verify_native_vm_first_use_identity(host, &bundle).is_ok() => {
            Phase::FirstUseWorkerSourceVerifiedLocal
        }
        Ok(_) => Phase::FirstUseWorkerSourceMismatch,
        Err(_) => Phase::FirstUseWorkerSourceUnavailable,
    }
}

async fn observe_native_vm_first_use_source(
    host: &FleetHost,
    stack_dir: &Path,
) -> edge_shared_types::FleetVmBootstrapPhase {
    let remote = async {
        let first = host
            .vm_first_use_credential
            .as_ref()
            .ok_or("HOST_VM_FIRST_USE_GIT_SOURCE_MISSING".to_owned())?;
        let access = super::vm_credential_access_identity_path(stack_dir)?;
        edge_secrets::fetch_canonical_credential_bundle(
            edge_shared_types::CredentialProjectionKind::Vm,
            first.generation,
            &access,
        )
        .await
    }
    .await;
    classify_native_vm_first_use_source(host, remote)
}

/// Called ONLY after the shared signed native journal persisted BEGIN.
/// A crash or failed local pointer write cannot authorize a replay.
fn activate_native_vm_first_use_cursor_once(
    stack_dir: &Path,
    host: &FleetHost,
    first: &edge_shared_types::CredentialDeliveryBundle,
) -> Result<(), String> {
    super::require_empty_vm_initial_credential_host(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_PRESTATE_CHANGED_NO_REPLAY")?;
    verify_native_vm_first_use_identity(host, first)
        .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_IDENTITY_DRIFT_NO_REPLAY")?;
    let root = super::vm_credential_store_root(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_STORE_UNPROVEN_NO_REPLAY")?;
    let store =
        edge_secrets::CredentialStore::new(root, edge_shared_types::CredentialProjectionKind::Vm)
            .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_STORE_UNPROVEN_NO_REPLAY")?;
    let staged = store
        .stage_delivery_candidate(first)
        .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_STAGE_UNCERTAIN_NO_REPLAY")?;
    if staged.active.is_some()
        || staged.previous.is_some()
        || staged
            .candidate
            .as_ref()
            .map(|candidate| candidate.generation)
            != Some(first.generation)
    {
        return Err("HOST_VM_INSTALL_FIRST_USE_CANDIDATE_UNPROVEN_NO_REPLAY".into());
    }
    let committed = store
        .promote_candidate()
        .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_ACTIVE_UNCERTAIN_NO_REPLAY")?;
    if committed.candidate.is_some()
        || committed.previous.is_some()
        || committed.active.as_ref().map(|active| active.generation) != Some(first.generation)
    {
        return Err("HOST_VM_INSTALL_FIRST_USE_ACTIVE_UNPROVEN_NO_REPLAY".into());
    }
    Ok(())
}

#[cfg(test)]
mod native_vm_first_use_tests {
    use super::*;

    fn valid_vm_bundle() -> edge_shared_types::CredentialDeliveryBundle {
        // Real X25519 private material is required by runtime projection.
        // Keep it test-local and never serialize/log the generated secret.
        let private = edge_secrets::ApplicationRuntimeSecrets::generate();
        use edge_shared_types::{
            CredentialDeliverySlot, CredentialProjectionKind, ProxyCredentialGeneration,
            RealityPrivateIdentity, RealityPrivateIdentityGeneration, TunnelAuthentication,
            TunnelAuthenticationGeneration, VmCredentialProjection, credential_delivery_bundle,
        };
        let tunnel = |uuid: &str, value: char| TunnelAuthentication {
            vless_uuid: uuid.to_owned(),
            hysteria2_password: value.to_string().repeat(64),
            reality_short_id: "b".repeat(16),
        };
        edge_shared_types::CredentialDeliveryBundle {
            schema_version: 1,
            generation: 31,
            projection: CredentialProjectionKind::Vm as i32,
            slot: CredentialDeliverySlot::A as i32,
            dummy_non_secret: false,
            payload: Some(credential_delivery_bundle::Payload::Vm(
                VmCredentialProjection {
                    tunnel_auth: Some(TunnelAuthenticationGeneration {
                        generation: 31,
                        direct: Some(tunnel("00000000-0000-4000-8000-000000000001", 'a')),
                        warp: Some(tunnel("00000000-0000-4000-8000-000000000002", 'c')),
                    }),
                    reality_identity: Some(RealityPrivateIdentityGeneration {
                        generation: 31,
                        direct: Some(RealityPrivateIdentity {
                            private_key: private.reality_private_key,
                        }),
                        warp: Some(RealityPrivateIdentity {
                            private_key: private.reality_warp_private_key,
                        }),
                    }),
                    line2_proxy: Some(ProxyCredentialGeneration {
                        generation: 31,
                        password: "e".repeat(64),
                    }),
                },
            )),
        }
    }

    #[test]
    fn first_use_deep_status_classifies_exact_worker_source_without_leaking_secrets() {
        use edge_shared_types::{FleetVmBootstrapPhase as Phase, FleetVmFirstUseCredential};
        let bundle = valid_vm_bundle();
        let digest = edge_shared_types::credential_delivery_bundle_sha256(&bundle).unwrap();
        let mut host = FleetHost {
            vm_first_use_credential: Some(FleetVmFirstUseCredential {
                generation: bundle.generation,
                bundle_sha256: digest,
            }),
            ..Default::default()
        };
        assert_eq!(
            classify_native_vm_first_use_source(&host, Ok(bundle.clone())),
            Phase::FirstUseWorkerSourceVerifiedLocal
        );
        host.vm_first_use_credential.as_mut().unwrap().generation += 1;
        assert_eq!(
            classify_native_vm_first_use_source(&host, Ok(bundle)),
            Phase::FirstUseWorkerSourceMismatch
        );
        assert_eq!(
            classify_native_vm_first_use_source(&host, Err("redacted".into())),
            Phase::FirstUseWorkerSourceUnavailable
        );
    }

    #[test]
    fn signed_first_use_cursor_converges_once_and_rejects_replay() {
        use edge_shared_types::{CredentialProjectionKind, FleetVmFirstUseCredential};
        let bundle = valid_vm_bundle();
        let digest = edge_shared_types::credential_delivery_bundle_sha256(&bundle).unwrap();
        let host = FleetHost {
            vm_first_use_credential: Some(FleetVmFirstUseCredential {
                generation: 31,
                bundle_sha256: digest,
            }),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join(format!(
            "native-first-use-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let stack_dir = dir.join("stack");
        activate_native_vm_first_use_cursor_once(&stack_dir, &host, &bundle).unwrap();
        let pin = verify_native_vm_first_use_identity(&host, &bundle).unwrap();
        assert!(verify_native_vm_install_credential_pin(&stack_dir, &pin).is_ok());
        assert!(activate_native_vm_first_use_cursor_once(&stack_dir, &host, &bundle).is_err());
        let store = edge_secrets::CredentialStore::open_existing(
            super::super::vm_credential_store_root(&stack_dir).unwrap(),
            CredentialProjectionKind::Vm,
        )
        .unwrap()
        .unwrap();
        let state = store.read_state().unwrap().unwrap();
        assert!(state.candidate.is_none() && state.previous.is_none());
        assert_eq!(state.active.unwrap().generation, 31);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn git_first_use_credential_identity_is_exact_and_non_authorizing() {
        let mut host = FleetHost::default();
        let mut bundle = edge_shared_types::CredentialDeliveryBundle::default();
        bundle.generation = 31;
        assert_eq!(
            verify_native_vm_first_use_identity(&host, &bundle),
            Err("HOST_VM_INSTALL_GIT_FIRST_USE_IDENTITY_REQUIRED")
        );
        host.vm_first_use_credential = Some(edge_shared_types::FleetVmFirstUseCredential {
            generation: 32,
            bundle_sha256: "1".repeat(64),
        });
        assert_eq!(
            verify_native_vm_first_use_identity(&host, &bundle),
            Err("HOST_VM_INSTALL_GIT_FIRST_USE_GENERATION_MISMATCH")
        );
        host.vm_first_use_credential.as_mut().unwrap().generation = 31;
        assert_eq!(
            verify_native_vm_first_use_identity(&host, &bundle),
            Err("HOST_VM_INSTALL_WORKER_FIRST_USE_BUNDLE_INVALID")
        );
    }
}

#[cfg(test)]
mod native_vm_warp_state_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn isolated_parent() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "native-warp-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }

    #[test]
    fn fresh_warp_state_is_created_once_in_exact_owned_parent() {
        let parent = isolated_parent();
        let uid = fs::symlink_metadata(&parent).unwrap().uid();
        assert_eq!(inspect_native_warp_state(&parent, uid), Ok(false));
        ensure_native_warp_state_once(&parent, uid).unwrap();
        assert_eq!(inspect_native_warp_state(&parent, uid), Ok(true));
        ensure_native_warp_state_once(&parent, uid).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn warp_state_rejects_symlinks_files_foreign_owners_and_writable_parent() {
        let parent = isolated_parent();
        let uid = fs::symlink_metadata(&parent).unwrap().uid();
        assert!(inspect_native_warp_state(&parent, uid.saturating_add(1)).is_err());
        let state = parent.join("warp-state");
        symlink("/tmp", &state).unwrap();
        assert_eq!(
            inspect_native_warp_state(&parent, uid),
            Err("HOST_VM_INSTALL_WARP_STATE_UNTRUSTED")
        );
        assert!(ensure_native_warp_state_once(&parent, uid).is_err());
        fs::remove_file(&state).unwrap();
        fs::write(&state, b"foreign").unwrap();
        assert!(inspect_native_warp_state(&parent, uid).is_err());
        fs::remove_file(&state).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            inspect_native_warp_state(&parent, uid),
            Err("HOST_VM_INSTALL_WARP_PARENT_UNTRUSTED")
        );
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}

/// Compare the Worker-v2 authenticated, exact-generation ACTIVE readback to
/// the same in-memory credential pin produced by native INSTALL preflight.
/// This is proof of source, NOT authorization to mutate or credential
/// publication. A/B promotions still belong exclusively to Worker-v2.
fn verify_native_vm_install_worker_pin(
    expected: &NativeVmCredentialPin,
    observed: &edge_secrets::CredentialOriginObservation,
) -> Result<(), &'static str> {
    let exact_sha256 = expected
        .exact_bundle_sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if observed.generation != expected.delivery_generation
        || observed.bundle_sha256 != exact_sha256
        || !matches!(observed.slot, "A" | "B")
    {
        return Err("HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_MISMATCH");
    }
    Ok(())
}

/// A read-only canonical Worker-v2 GET under the native owner lock, BEFORE
/// journal BEGIN. No credentials are copied into GitHub or stdout; the local
/// A/B cursor is checked for drift by credential_origin and later by INSTALL.
pub(crate) async fn attest_native_vm_install_worker_origin(
    stack_dir: &Path,
    plan: &NativeVmInstallPlan,
) -> Result<(), &'static str> {
    let root = super::vm_credential_store_root(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_WORKER_STORE_UNPROVEN")?;
    let access = super::vm_credential_access_identity_path(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_WORKER_ACCESS_UNPROVEN")?;
    if let Some(first) = plan.first_use_bundle.as_ref() {
        // Fresh enrollment has no local cursor yet. A second read-only GET
        // proves Worker has not replaced the exact Git-bound generation
        // before BEGIN; it NEVER promotes the candidate.
        let repeated = edge_secrets::fetch_canonical_credential_bundle(
            edge_shared_types::CredentialProjectionKind::Vm,
            first.generation,
            &access,
        )
        .await
        .map_err(|_| "HOST_VM_INSTALL_WORKER_ORIGIN_UNPROVEN")?;
        if repeated != *first {
            return Err("HOST_VM_INSTALL_WORKER_ACTIVE_ORIGIN_MISMATCH");
        }
        return Ok(());
    }
    let observation = edge_secrets::attest_worker_credential_origin(
        &root,
        &access,
        edge_shared_types::CredentialProjectionKind::Vm,
        edge_secrets::CredentialOriginSelection::Active,
    )
    .await
    .map_err(|_| "HOST_VM_INSTALL_WORKER_ORIGIN_UNPROVEN")?;
    verify_native_vm_install_worker_pin(&plan.credential_pin, &observation)
}

/// A signed install is allowed only on an empty exact Docker namespace.
/// No Compose/default Docker network and no adoption of a foreign resource.
/// Admission for the WARP child is pure and independent of the Docker
/// mutator. Reject any Compose capability, device, mount or network drift.
fn validate_native_warp_install_compose(
    host: &FleetHost,
    compose: &serde_yaml::Value,
) -> Result<(), String> {
    let warp = compose
        .get("services")
        .and_then(|v| v.get("warp-egress"))
        .ok_or("HOST_VM_INSTALL_WARP_UNPROVEN")?;
    let mapping = warp.as_mapping().ok_or("HOST_VM_INSTALL_WARP_INVALID")?;
    let keys = mapping
        .keys()
        .map(|key| key.as_str().ok_or("HOST_VM_INSTALL_WARP_KEY_INVALID"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if keys
        != BTreeSet::from([
            "image",
            "container_name",
            "restart",
            "cap_add",
            "devices",
            "volumes",
            "networks",
        ])
    {
        return Err("HOST_VM_INSTALL_WARP_FIELD_UNSUPPORTED".into());
    }
    let selector = host
        .vm_containers
        .iter()
        .find(|item| item.compose_service == "warp-egress")
        .ok_or("HOST_VM_INSTALL_WARP_SELECTOR_MISSING")?;
    let sequence = |field: &str| -> Result<Vec<String>, String> {
        warp.get(field)
            .and_then(serde_yaml::Value::as_sequence)
            .ok_or("HOST_VM_INSTALL_WARP_SEQUENCE_MISSING")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "HOST_VM_INSTALL_WARP_SEQUENCE_INVALID".to_owned())
            })
            .collect()
    };
    if warp.get("image").and_then(serde_yaml::Value::as_str)
        != Some("${EDGE_WARP_EGRESS_IMAGE:?EDGE_WARP_EGRESS_IMAGE is required}")
        || warp
            .get("container_name")
            .and_then(serde_yaml::Value::as_str)
            != Some(selector.container_name.as_str())
        || warp.get("restart").and_then(serde_yaml::Value::as_str) != Some("unless-stopped")
        || sequence("cap_add")? != ["NET_ADMIN"]
        || sequence("devices")? != ["/dev/net/tun:/dev/net/tun"]
        || sequence("volumes")? != ["../warp-state:/var/lib/cloudflare-warp"]
        || sequence("networks")? != ["edge_net"]
    {
        return Err("HOST_VM_INSTALL_WARP_POLICY_MISMATCH".into());
    }
    Ok(())
}

pub(crate) async fn preflight_native_vm_install(
    stack_dir: &Path,
    host: &FleetHost,
    request: &ApplyBundleRequest,
) -> Result<NativeVmInstallPlan, String> {
    super::validate_digest_bound_bundle_request(request)
        .map_err(|_| "HOST_VM_INSTALL_BUNDLE_INVALID")?;
    super::validate_initial_policy_bundle_request(request)
        .map_err(|_| "HOST_VM_INSTALL_POLICY_INVALID")?;
    let graph = compile_vm_desired_graph_from_release(host, request)?;
    let project = host
        .vm_containers
        .first()
        .ok_or("HOST_VM_INSTALL_OWNER_MISSING")?
        .compose_project
        .clone();
    let names = host
        .vm_containers
        .iter()
        .map(|item| item.compose_service.as_str())
        .collect::<BTreeSet<_>>();
    if host.vm_containers.len() != 3
        || names != BTreeSet::from(["line1-gateway", "line2-proxy", "warp-egress"])
        || project.is_empty()
        || host
            .vm_containers
            .iter()
            .any(|item| item.compose_project != project)
    {
        return Err("HOST_VM_INSTALL_RESOURCE_SCOPE_INVALID".into());
    }
    let [network] = graph.networks.as_slice() else {
        return Err("HOST_VM_INSTALL_NETWORK_SCOPE_INVALID".into());
    };
    if network.network_name != "edge_net"
        || network.driver != "bridge"
        || network.compose_project != project
        || network
            .attached_services
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != names
    {
        return Err("HOST_VM_INSTALL_NETWORK_SCOPE_INVALID".into());
    }
    for service in ["line1-gateway", "line2-proxy"] {
        if !graph.resources.iter().any(|item| {
            item.resource
                .as_ref()
                .is_some_and(|id| id.compose_service == service)
                && item.dependencies.iter().any(|dep| dep == "warp-egress")
        }) {
            return Err("HOST_VM_INSTALL_DEPENDENCY_INVALID".into());
        }
    }
    let compose_bytes = request
        .stack_files
        .iter()
        .find(|file| file.relative_path == "docker-compose.yml")
        .ok_or("HOST_VM_INSTALL_COMPOSE_MISSING")?;
    let compose: serde_yaml::Value = serde_yaml::from_slice(&compose_bytes.content)
        .map_err(|_| "HOST_VM_INSTALL_COMPOSE_INVALID")?;
    validate_native_warp_install_compose(host, &compose)?;
    inspect_native_warp_state(
        native_vm_warp_state_parent(stack_dir).map_err(str::to_owned)?,
        0,
    )
    .map_err(str::to_owned)?;
    let mut published = BTreeSet::new();
    for service in ["line1-gateway", "line2-proxy"] {
        let policy = compile_native_gateway_policy(host, &compose, service)?;
        for (host_port, _, protocol) in policy.ports {
            if !published.insert((host_port, protocol)) {
                return Err("HOST_VM_INSTALL_GATEWAY_PUBLISHED_PORT_COLLISION".into());
            }
        }
    }
    super::require_empty_vm_initial_bundle_host(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_EXISTING_STACK")?;
    let docker = docker_connection().await?;
    if !owned_application_container_ids(&docker, &host.vm_containers)
        .await?
        .is_empty()
    {
        return Err("HOST_VM_INSTALL_CONTAINER_ALREADY_PRESENT".into());
    }
    let network_name = format!("{project}_edge_net");
    match docker.inspect_network(&network_name, None).await {
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => {}
        Ok(_) => return Err("HOST_VM_INSTALL_EXISTING_NETWORK".into()),
        Err(_) => return Err("HOST_VM_INSTALL_NETWORK_UNOBSERVABLE".into()),
    }
    let active = super::active_vm_credential_bundle(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_CREDENTIAL_UNPROVEN")?;
    // A fresh signed INSTALL can use one explicitly Git-pinned Worker-v2
    // generation. Its payload stays in native root memory until journal
    // BEGIN; cursor creation and Docker materialization are one-shot.
    let (credential_pin, first_use_bundle) = match active {
        Some(bundle) => {
            let pinned = pin_active_native_vm_credential(&bundle)?;
            if host.vm_first_use_credential.is_some() {
                verify_native_vm_first_use_identity(host, &bundle)?;
            }
            (pinned, None)
        }
        None => {
            super::require_empty_vm_initial_credential_host(stack_dir)
                .map_err(|_| "HOST_VM_INSTALL_FIRST_USE_STORE_NOT_EMPTY")?;
            let generation = host
                .vm_first_use_credential
                .as_ref()
                .ok_or("HOST_VM_INSTALL_GIT_FIRST_USE_IDENTITY_REQUIRED")?
                .generation;
            if generation == 0 {
                return Err("HOST_VM_INSTALL_GIT_FIRST_USE_IDENTITY_REQUIRED".into());
            }
            let worker = edge_secrets::fetch_canonical_credential_bundle(
                edge_shared_types::CredentialProjectionKind::Vm,
                generation,
                &super::vm_credential_access_identity_path(stack_dir)
                    .map_err(|_| "HOST_VM_INSTALL_WORKER_ACCESS_UNPROVEN")?,
            )
            .await
            .map_err(|_| "HOST_VM_INSTALL_WORKER_ORIGIN_UNPROVEN")?;
            let pin = verify_native_vm_first_use_identity(host, &worker).map_err(str::to_owned)?;
            (pin, Some(worker))
        }
    };
    let pins = request
        .stack_files
        .iter()
        .find(|file| file.relative_path == ".images.env")
        .ok_or("HOST_VM_INSTALL_IMAGE_POLICY_MISSING")?;
    let images = parse_vm_release_image_pins(&pins.content)?;
    Ok(NativeVmInstallPlan {
        request: request.clone(),
        graph,
        project,
        gateway_image: images["EDGE_GATEWAY_IMAGE"].clone(),
        warp_image: images["EDGE_WARP_EGRESS_IMAGE"].clone(),
        credential_pin,
        first_use_bundle,
    })
}

/// Read the Worker-v2 ACTIVE snapshot under the existing root owner lock
/// and compare its exact generation+canonical bundle digest with preadmission.
/// Never read candidate/previous, create credentials, or fall back to v1.
/// The projection returned here is the ONLY one installed by signed INSTALL.
fn verify_native_vm_install_credential_pin(
    stack_dir: &Path,
    expected: &NativeVmCredentialPin,
) -> Result<super::ApplicationRuntimeSecrets, String> {
    let bundle = super::active_vm_credential_bundle(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_CREDENTIAL_CURSOR_UNPROVEN_NO_REPLAY")?
        .ok_or("HOST_VM_INSTALL_ACTIVE_CREDENTIAL_DISAPPEARED_NO_REPLAY")?;
    let actual = pin_active_native_vm_credential(&bundle)
        .map_err(|_| "HOST_VM_INSTALL_CREDENTIAL_CHANGED_NO_REPLAY")?;
    if &actual != expected {
        return Err("HOST_VM_INSTALL_CREDENTIAL_DRIFT_NO_REPLAY".into());
    }
    super::ApplicationRuntimeSecrets::from_vm_bundle(&bundle)
        .map_err(|_| "HOST_VM_INSTALL_CREDENTIAL_PROJECTION_INVALID_NO_REPLAY".into())
}

fn stage_native_first_vm_bundle(
    stack_dir: &Path,
    request: &ApplyBundleRequest,
    pinned_secrets: &super::ApplicationRuntimeSecrets,
) -> Result<(), String> {
    // BEGIN has been durably recorded. No cleanup or implicit rollback is
    // allowed for any scratch state following an uncertain operation.
    super::require_empty_vm_initial_bundle_host(stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_PRESTATE_CHANGED_NO_REPLAY")?;
    let parent = stack_dir.parent().ok_or("HOST_VM_INSTALL_PARENT_MISSING")?;
    let stage = parent.join(super::STAGING_STACK_DIR);
    fs::create_dir(&stage).map_err(|_| "HOST_VM_INSTALL_STAGE_UNCERTAIN_NO_REPLAY")?;
    let mut written = Vec::new();
    for file in &request.stack_files {
        super::write_bundle_file(&stage, file, &mut written)
            .map_err(|_| "HOST_VM_INSTALL_BUNDLE_WRITE_UNCERTAIN_NO_REPLAY")?;
    }
    // Project exactly the bundle verified against signed pre-BEGIN pin.
    // Reopening the A/B store here would permit a TOCTOU credential swap
    // after the last check and before the runtime is materialized.
    super::write_vm_runtime_environment(&stage, pinned_secrets)
        .map_err(|_| "HOST_VM_INSTALL_CREDENTIAL_PROJECTION_UNCERTAIN_NO_REPLAY")?;
    super::prepare_runtime_directories(&stage)
        .map_err(|_| "HOST_VM_INSTALL_RUNTIME_DIR_UNCERTAIN_NO_REPLAY")?;
    let runtime = super::read_typed_runtime_environment(&stage)
        .map_err(|_| "HOST_VM_INSTALL_RUNTIME_UNPROVEN_NO_REPLAY")?;
    super::require_line2_policy(&runtime)
        .map_err(|_| "HOST_VM_INSTALL_LINE2_POLICY_INVALID_NO_REPLAY")?;
    super::require_tunnel_policy(&runtime)
        .map_err(|_| "HOST_VM_INSTALL_LINE1_POLICY_INVALID_NO_REPLAY")?;
    super::render_line1_runtime(&stage, &runtime)
        .map_err(|_| "HOST_VM_INSTALL_LINE1_RENDER_UNCERTAIN_NO_REPLAY")?;
    super::render_line2_runtime(&stage, &runtime)
        .map_err(|_| "HOST_VM_INSTALL_LINE2_RENDER_UNCERTAIN_NO_REPLAY")?;
    let (bundle_id, bundle_digest) = super::validate_digest_bound_bundle_request(request)
        .map_err(|_| "HOST_VM_INSTALL_DIGEST_CHANGED_NO_REPLAY")?;
    super::write_application_release(
        &stage,
        &super::ApplicationBundleRelease {
            schema_version: 1,
            bundle_id,
            bundle_digest,
        },
    )
    .map_err(|_| "HOST_VM_INSTALL_MARKER_UNCERTAIN_NO_REPLAY")?;
    // An installer may precreate an empty target. Remove only that exact
    // empty directory; any foreign/nonempty path is UNKNOWN_NO_REPLAY.
    if stack_dir.exists() {
        fs::remove_dir(stack_dir).map_err(|_| "HOST_VM_INSTALL_TARGET_NOT_EMPTY_NO_REPLAY")?;
    }
    fs::rename(&stage, stack_dir)
        .map_err(|_| "HOST_VM_INSTALL_ACTIVATE_UNCERTAIN_NO_REPLAY".to_owned())
}

async fn pull_native_vm_image_once(docker: &Docker, image: &str) -> Result<(), String> {
    if docker.inspect_image(image).await.is_ok() {
        return Ok(());
    }
    let options = bollard::query_parameters::CreateImageOptionsBuilder::default()
        .from_image(image)
        .build();
    let pull = async {
        let mut stream = docker.create_image(Some(options), None, None);
        while let Some(result) = stream.next().await {
            result.map_err(|_| "HOST_VM_INSTALL_PULL_ACK_UNCERTAIN_NO_REPLAY")?;
        }
        Ok::<(), String>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(180), pull)
        .await
        .map_err(|_| "HOST_VM_INSTALL_PULL_TIMEOUT_NO_REPLAY")??;
    docker
        .inspect_image(image)
        .await
        .map_err(|_| "HOST_VM_INSTALL_IMAGE_DIGEST_UNPROVEN_NO_REPLAY")?;
    Ok(())
}

/// The WARP bind lives only in the registered application's root-owned
/// host-state parent, never in an arbitrary Docker or Mesh directory.
fn native_vm_warp_state_parent(stack_dir: &Path) -> Result<&Path, &'static str> {
    if stack_dir != Path::new(super::DEFAULT_STACK_DIR) {
        return Err("HOST_VM_INSTALL_WARP_STACK_SCOPE_INVALID");
    }
    stack_dir
        .parent()
        .ok_or("HOST_VM_INSTALL_WARP_PARENT_MISSING")
}

/// Read-only admission: no symlink resolution, no adoption of foreign state,
/// and no writable parent that another owner could swap before BEGIN.
fn inspect_native_warp_state(parent: &Path, expected_uid: u32) -> Result<bool, &'static str> {
    let parent_meta =
        fs::symlink_metadata(parent).map_err(|_| "HOST_VM_INSTALL_WARP_PARENT_UNPROVEN")?;
    if !parent.is_absolute()
        || !parent_meta.file_type().is_dir()
        || parent_meta.uid() != expected_uid
        || parent_meta.permissions().mode() & 0o022 != 0
    {
        return Err("HOST_VM_INSTALL_WARP_PARENT_UNTRUSTED");
    }
    match fs::symlink_metadata(parent.join("warp-state")) {
        Ok(meta)
            if meta.file_type().is_dir()
                && meta.uid() == expected_uid
                && meta.permissions().mode() & 0o022 == 0 =>
        {
            Ok(true)
        }
        Ok(_) => Err("HOST_VM_INSTALL_WARP_STATE_UNTRUSTED"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("HOST_VM_INSTALL_WARP_STATE_UNOBSERVABLE"),
    }
}

/// Called only inside the already signed root owner operation, after durable
/// BEGIN. One native mkdir in the exact application namespace, not a second
/// installer, daemon, shell, or mutation authority.
fn ensure_native_warp_state_once(parent: &Path, expected_uid: u32) -> Result<(), &'static str> {
    if inspect_native_warp_state(parent, expected_uid)? {
        return Ok(());
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(parent.join("warp-state"))
        .map_err(|_| "HOST_VM_INSTALL_WARP_STATE_CREATE_UNCERTAIN_NO_REPLAY")?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "HOST_VM_INSTALL_WARP_STATE_SYNC_UNCERTAIN_NO_REPLAY")?;
    if !inspect_native_warp_state(parent, expected_uid)? {
        return Err("HOST_VM_INSTALL_WARP_STATE_CHANGED_NO_REPLAY");
    }
    Ok(())
}

fn native_warp_create_body(
    stack_dir: &Path,
    host: &FleetHost,
    image: &str,
    network_id: &str,
) -> Result<bollard::models::ContainerCreateBody, String> {
    use bollard::models::{
        ContainerCreateBody, DeviceMapping, EndpointSettings, HostConfig, NetworkingConfig,
        RestartPolicy, RestartPolicyNameEnum,
    };
    let identity = host
        .vm_containers
        .iter()
        .find(|id| id.compose_service == "warp-egress")
        .ok_or("HOST_VM_INSTALL_WARP_SELECTOR_MISSING")?;
    let parent = native_vm_warp_state_parent(stack_dir).map_err(str::to_owned)?;
    if inspect_native_warp_state(parent, 0).map_err(str::to_owned)? != true {
        return Err("HOST_VM_INSTALL_WARP_STATE_MISSING".into());
    }
    // The root-owned path was inspected without following any symlink.
    let state = parent.join("warp-state");
    let mut labels = HashMap::new();
    labels.insert(
        "com.docker.compose.project".to_owned(),
        identity.compose_project.clone(),
    );
    labels.insert(
        "com.docker.compose.service".to_owned(),
        identity.compose_service.clone(),
    );
    let mut endpoints = HashMap::new();
    endpoints.insert(
        format!("{}_edge_net", identity.compose_project),
        EndpointSettings {
            network_id: Some(network_id.to_owned()),
            ..Default::default()
        },
    );
    Ok(ContainerCreateBody {
        image: Some(image.to_owned()),
        labels: Some(labels),
        host_config: Some(HostConfig {
            binds: Some(vec![format!(
                "{}:/var/lib/cloudflare-warp:rw",
                state.display()
            )]),
            cap_add: Some(vec!["NET_ADMIN".to_owned()]),
            devices: Some(vec![DeviceMapping {
                path_on_host: Some("/dev/net/tun".to_owned()),
                path_in_container: Some("/dev/net/tun".to_owned()),
                cgroup_permissions: Some("rwm".to_owned()),
            }]),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                ..Default::default()
            }),
            ..Default::default()
        }),
        networking_config: Some(NetworkingConfig {
            endpoints_config: Some(endpoints),
        }),
        ..Default::default()
    })
}

async fn native_create_vm_container_once(
    docker: &Docker,
    host: &FleetHost,
    service: &str,
    body: bollard::models::ContainerCreateBody,
) -> Result<(), String> {
    let identity = host
        .vm_containers
        .iter()
        .find(|id| id.compose_service == service)
        .ok_or("HOST_VM_INSTALL_SELECTOR_MISSING")?;
    let options = bollard::query_parameters::CreateContainerOptionsBuilder::default()
        .name(&identity.container_name)
        .build();
    let created = docker
        .create_container(Some(options), body)
        .await
        .map_err(|_| "HOST_VM_INSTALL_CREATE_ACK_UNCERTAIN_NO_REPLAY")?;
    if created.id.len() != 64 || !created.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("HOST_VM_INSTALL_CREATED_ID_UNPROVEN_NO_REPLAY".into());
    }
    docker
        .start_container(
            &created.id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .map_err(|_| "HOST_VM_INSTALL_START_ACK_UNCERTAIN_NO_REPLAY")?;
    Ok(())
}

/// One signed journal authority; no Docker Compose or shell is executable
/// in fresh install, including pulls, owned network and WARP creation.
pub(crate) async fn apply_native_vm_install_once(
    stack_dir: &Path,
    host: &FleetHost,
    plan: NativeVmInstallPlan,
) -> Result<(), String> {
    let docker = docker_connection().await?;
    if !owned_application_container_ids(&docker, &host.vm_containers)
        .await?
        .is_empty()
    {
        return Err("HOST_VM_INSTALL_PRESTATE_CHANGED_NO_REPLAY".into());
    }
    let network_name = format!("{}_edge_net", plan.project);
    match docker.inspect_network(&network_name, None).await {
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => {}
        _ => return Err("HOST_VM_INSTALL_NETWORK_CHANGED_NO_REPLAY".into()),
    }
    // Pre-BEGIN has already inspected the root-owned WARP namespace.
    // After BEGIN, create it once before any Docker or credential writes.
    // A partial mkdir/sync fails closed through the existing native journal.
    ensure_native_warp_state_once(
        native_vm_warp_state_parent(stack_dir).map_err(str::to_owned)?,
        0,
    )
    .map_err(str::to_owned)?;
    // BEGIN is durable before this one-time, root-owned credential mutation.
    // A crash or partial cursor write retains UNKNOWN_NO_REPLAY.
    if let Some(ref first) = plan.first_use_bundle {
        activate_native_vm_first_use_cursor_once(stack_dir, host, first)?;
    }
    // Bind the exact post-BEGIN projection once: all subsequent filesystem
    // rendering consumes this immutable, already verified in-memory value.
    let pinned_secrets = verify_native_vm_install_credential_pin(stack_dir, &plan.credential_pin)?;
    stage_native_first_vm_bundle(stack_dir, &plan.request, &pinned_secrets)?;
    if compile_native_vm_desired_graph(stack_dir, host)? != plan.graph {
        return Err("HOST_VM_INSTALL_GRAPH_CHANGED_NO_REPLAY".into());
    }
    pull_native_vm_image_once(&docker, &plan.warp_image).await?;
    pull_native_vm_image_once(&docker, &plan.gateway_image).await?;
    let mut labels = HashMap::new();
    labels.insert(
        "com.docker.compose.project".to_owned(),
        plan.project.clone(),
    );
    labels.insert(
        "com.docker.compose.network".to_owned(),
        "edge_net".to_owned(),
    );
    docker
        .create_network(bollard::models::NetworkCreateRequest {
            name: network_name,
            driver: Some("bridge".to_owned()),
            labels: Some(labels),
            ..Default::default()
        })
        .await
        .map_err(|_| "HOST_VM_INSTALL_NETWORK_CREATE_UNCERTAIN_NO_REPLAY")?;
    let id = read_owned_edge_network_id(&docker, host).await?;
    native_create_vm_container_once(
        &docker,
        host,
        "warp-egress",
        native_warp_create_body(stack_dir, host, &plan.warp_image, &id)?,
    )
    .await?;
    for service in ["line1-gateway", "line2-proxy"] {
        let body = native_gateway_create_body(stack_dir, host, service, &plan.gateway_image, &id)?;
        native_create_vm_container_once(&docker, host, service, body).await?;
    }
    let mut after = owned_application_container_ids(&docker, &host.vm_containers).await?;
    if after.len() != host.vm_containers.len() || after.iter().any(|item| !item.running) {
        return Err("HOST_VM_INSTALL_POSTSTATE_MISSING_NO_REPLAY".into());
    }
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut after)?;
    verify_vm_network_attachments(&docker, host, &after, &id).await?;
    if after.iter().any(|item| {
        item.image_ref.as_str()
            != if item.service == "warp-egress" {
                plan.warp_image.as_str()
            } else {
                plan.gateway_image.as_str()
            }
    }) {
        return Err("HOST_VM_INSTALL_IMAGE_POSTSTATE_CHANGED_NO_REPLAY".into());
    }
    for service in [ScopedVmService::Line1, ScopedVmService::Line2] {
        verify_running_container_config_binding(
            service.container_name(host)?,
            &stack_dir.join(service.rendered_relative()),
        )
        .await
        .map_err(|_| "HOST_VM_INSTALL_CONFIG_UNPROVEN_NO_REPLAY")?;
    }
    if compile_native_vm_desired_graph(stack_dir, host)? != plan.graph {
        return Err("HOST_VM_INSTALL_POSTSTATE_GRAPH_CHANGED_NO_REPLAY".into());
    }
    // The durable terminal VERIFIED receipt is forbidden if local A/B
    // changed while Docker containers were being created. No compensation,
    // cursor promotion or mutation replay is attempted.
    verify_native_vm_install_credential_pin(stack_dir, &plan.credential_pin)?;
    Ok(())
}

/// One application-owned service selector. No caller-supplied Docker name,
/// command, path, or second operation authority can enter this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopedVmService {
    Line1,
    Line2,
}

impl ScopedVmService {
    fn from_template(path: &str) -> Result<Self, String> {
        match path {
            "line1-gateway/config.template.json" => Ok(Self::Line1),
            "line2-proxy/config.template.json" => Ok(Self::Line2),
            _ => Err("HOST_NATIVE_VM_SCOPED_RESOURCE_UNSUPPORTED".into()),
        }
    }

    fn compose_service(self) -> &'static str {
        match self {
            Self::Line1 => "line1-gateway",
            Self::Line2 => "line2-proxy",
        }
    }

    fn container_name<'a>(self, host: &'a FleetHost) -> Result<&'a str, String> {
        host.vm_containers
            .iter()
            .find(|identity| identity.compose_service == self.compose_service())
            .map(|identity| identity.container_name.as_str())
            .ok_or_else(|| "HOST_NATIVE_VM_SCOPED_RESOURCE_NOT_REGISTERED".into())
    }

    fn template_relative(self) -> &'static str {
        match self {
            Self::Line1 => "line1-gateway/config.template.json",
            Self::Line2 => "line2-proxy/config.template.json",
        }
    }

    fn rendered_relative(self) -> &'static str {
        match self {
            Self::Line1 => "rendered/line1-gateway.json",
            Self::Line2 => "rendered/line2-proxy.json",
        }
    }

    fn render(self, stack_dir: &Path, runtime: &BTreeMap<String, String>) -> Result<(), String> {
        match self {
            Self::Line1 => super::render_line1_runtime(stack_dir, runtime),
            Self::Line2 => super::render_line2_runtime(stack_dir, runtime),
        }
    }
}

/// One paired, dependency-aware image resource update. The shared image
/// belongs to both Line1 and Line2. Changing one service independently would
/// leave a false "desired converged" claim. WARP and Mesh are never adopted.
#[derive(Debug)]
struct NativeVmGatewayImageReplacePlan {
    previous_images: Vec<u8>,
    new_images: Vec<u8>,
    new_gateway_image: String,
    new_warp_image: Option<String>,
    identities: Vec<Option<(String, bool, String)>>,
    installed_graph: edge_shared_types::FleetVmDesiredGraph,
    target_graph: edge_shared_types::FleetVmDesiredGraph,
    release: edge_shared_types::ApplicationBundleReleaseState,
    edge_network_id: String,
    prepared_gateways: Vec<(String, bollard::models::ContainerCreateBody)>,
    prepared_warp: Option<bollard::models::ContainerCreateBody>,
    compose_sha256: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum NativeVmReplacePlan {
    Config(NativeVmScopedReplacePlan),
    GatewayImage(NativeVmGatewayImageReplacePlan),
    ManagedFile(NativeVmManagedFilePlan),
}

impl NativeVmReplacePlan {
    /// Only a single sing-box config child; the paired-image effector is
    /// deliberately ineligible for a config-scoped signed operation.
    pub(crate) fn single_config_resource_id(
        &self,
        host: &FleetHost,
    ) -> Result<String, &'static str> {
        let Self::Config(plan) = self else {
            return Err("HOST_NATIVE_SCOPE_IS_NOT_SINGLE_CONFIG");
        };
        let selector = host
            .vm_containers
            .iter()
            .find(|item| item.compose_service == plan.target.compose_service())
            .ok_or("HOST_NATIVE_SCOPE_RESOURCE_NOT_REGISTERED")?;
        let id = format!(
            "config/{}/{}",
            selector.compose_project, selector.compose_service
        );
        edge_shared_types::host_lifecycle::validate_scoped_vm_resource_id(host, &id)?;
        let hierarchy = edge_shared_types::host_resources::derive_vm_resource_hierarchy(
            host,
            &plan.target_graph,
        )?;
        let node = hierarchy
            .nodes
            .iter()
            .find(|item| item.resource_id == id)
            .ok_or("HOST_NATIVE_SCOPE_NODE_NOT_IN_DESIRED")?;
        if node.kind != edge_shared_types::FleetResourceKind::SingboxConfig as i32
            || node.owner != edge_shared_types::FleetResourceOwner::VmRootAgent as i32
            || node.parent_resource_id
                != format!(
                    "container/{}/{}",
                    selector.compose_project, selector.compose_service
                )
        {
            return Err("HOST_NATIVE_SCOPE_PARENT_OR_OWNER_INVALID");
        }
        Ok(id)
    }
}

/// Only EDGE_GATEWAY_IMAGE may change. Its exact value is a trusted immutable
/// OCI digest. All other environment lines remain byte-for-byte identical.
fn gateway_image_policy_delta(
    installed: &[u8],
    desired: &[u8],
    current_image: &str,
) -> Result<String, String> {
    let old = std::str::from_utf8(installed).map_err(|_| "HOST_VM_IMAGE_ENV_NOT_UTF8")?;
    let target = std::str::from_utf8(desired).map_err(|_| "HOST_VM_IMAGE_TARGET_NOT_UTF8")?;
    let prefix = "EDGE_GATEWAY_IMAGE=";
    let old_lines = old.lines().collect::<Vec<_>>();
    let new_lines = target.lines().collect::<Vec<_>>();
    if old_lines.len() != new_lines.len() || old_lines.len() != 3 {
        return Err("HOST_VM_IMAGE_ENV_SHAPE_CHANGED".into());
    }
    let mut gateway = None;
    let mut gateway_count = 0;
    for (previous, next) in old_lines.iter().zip(new_lines.iter()) {
        if let Some(value) = previous.strip_prefix(prefix) {
            gateway_count += 1;
            if value != current_image {
                return Err("HOST_VM_IMAGE_PREVIOUS_DIGEST_MISMATCH".into());
            }
            let changed = next
                .strip_prefix(prefix)
                .ok_or("HOST_VM_IMAGE_GATEWAY_KEY_REMOVED")?;
            let sha = changed
                .strip_prefix("ghcr.io/iamaman11/vultr-edge-gateway@sha256:")
                .ok_or("HOST_VM_IMAGE_REPOSITORY_NOT_PINNED")?;
            if sha.len() != 64
                || !sha
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                || sha.bytes().all(|c| c == b'0')
                || changed == value
            {
                return Err("HOST_VM_IMAGE_DIGEST_NOT_CHANGED_OR_INVALID".into());
            }
            gateway = Some(changed.to_owned());
        } else if previous != next {
            return Err("HOST_VM_IMAGE_FOREIGN_IMAGE_OR_ENV_CHANGED".into());
        }
    }
    if gateway_count != 1 || old.ends_with('\n') != target.ends_with('\n') {
        return Err("HOST_VM_IMAGE_ENV_NONCANONICAL".into());
    }
    gateway.ok_or_else(|| "HOST_VM_IMAGE_GATEWAY_MISSING".into())
}

/// Pure release policy decision, independent of the running VM. Retain the
/// established gateway-only checker to verify all unchanged bytes, and allow
/// one additional digest-pinned WARP image inside the SAME transaction.
fn application_image_policy_delta(
    installed: &[u8],
    desired: &[u8],
) -> Result<(String, Option<String>), String> {
    let previous = parse_vm_release_image_pins(installed)?;
    let requested = parse_vm_release_image_pins(desired)?;
    if requested["CLOUDFLARE_MESH_IMAGE"] != previous["CLOUDFLARE_MESH_IMAGE"] {
        return Err("HOST_VM_IMAGE_FOREIGN_IMAGE_OR_ENV_CHANGED".into());
    }
    let target_warp = &requested["EDGE_WARP_EGRESS_IMAGE"];
    let old_warp = &previous["EDGE_WARP_EGRESS_IMAGE"];
    let desired_text =
        std::str::from_utf8(desired).map_err(|_| "HOST_VM_IMAGE_TARGET_NOT_UTF8")?;
    let normalized = desired_text.replace(
        &format!("EDGE_WARP_EGRESS_IMAGE={target_warp}"),
        &format!("EDGE_WARP_EGRESS_IMAGE={old_warp}"),
    );
    let next_gateway = gateway_image_policy_delta(
        installed,
        normalized.as_bytes(),
        &previous["EDGE_GATEWAY_IMAGE"],
    )?;
    let next_warp = (target_warp != old_warp).then(|| target_warp.clone());
    Ok((next_gateway, next_warp))
}

/// One exact Git-owned .images.env update: paired gateway change and an
/// optional WARP change. Foreign Mesh, templates and networking never change.
fn select_gateway_image_policy(
    stack_dir: &Path,
    request: &ApplyBundleRequest,
) -> Result<(Vec<u8>, Vec<u8>, String, Option<String>), String> {
    if request.stack_files.is_empty() || request.stack_files.len() > 128 {
        return Err("HOST_VM_IMAGE_BUNDLE_INVALID".into());
    }
    let mut exact = request.clone();
    let mut items = exact
        .stack_files
        .iter_mut()
        .filter(|file| file.relative_path == ".images.env")
        .collect::<Vec<_>>();
    let [candidate] = items.as_mut_slice() else {
        return Err("HOST_VM_IMAGE_ENV_SCOPE_INVALID".into());
    };
    if candidate.executable || candidate.sensitive {
        return Err("HOST_VM_IMAGE_ENV_FLAGS_INVALID".into());
    }
    let desired = candidate.content.clone();
    let installed = exact_vm_policy_file(stack_dir, ".images.env")?;
    let (next_gateway, next_warp) = application_image_policy_delta(&installed, &desired)?;
    candidate.content = installed.clone();
    verify_exact_installed_vm_bundle_static(stack_dir, &exact)?;
    Ok((installed, desired, next_gateway, next_warp))
}

/// Shared image ownership must be demonstrated by the actual Compose-derived
/// graph. Merely seeing one changed .images.env key does not establish that
/// both gateway services use it (or that WARP does not).
fn validate_gateway_image_ownership(
    graph: &edge_shared_types::FleetVmDesiredGraph,
    current_gateway: &str,
) -> Result<(), String> {
    let mut owners = BTreeSet::new();
    for resource in &graph.resources {
        let identity = resource
            .resource
            .as_ref()
            .ok_or("HOST_VM_IMAGE_OWNER_IDENTITY_MISSING")?;
        if matches!(
            identity.compose_service.as_str(),
            "line1-gateway" | "line2-proxy"
        ) {
            if resource.image_ref != current_gateway {
                return Err("HOST_VM_IMAGE_GATEWAY_COMPOSE_NOT_SHARED".into());
            }
            owners.insert(identity.compose_service.as_str());
        } else if resource.image_ref == current_gateway {
            return Err("HOST_VM_IMAGE_FOREIGN_SERVICE_SHARES_GATEWAY".into());
        }
    }
    if owners != BTreeSet::from(["line1-gateway", "line2-proxy"]) {
        return Err("HOST_VM_IMAGE_GATEWAY_OWNERS_INCOMPLETE".into());
    }
    Ok(())
}

async fn preflight_gateway_image_replace(
    stack_dir: &Path,
    host: &FleetHost,
    request: &ApplyBundleRequest,
) -> Result<NativeVmGatewayImageReplacePlan, String> {
    let (bundle_id, digest) = super::validate_digest_bound_bundle_request(request)?;
    if super::read_application_release(stack_dir)
        .ok_or("HOST_VM_IMAGE_PREVIOUS_RELEASE_UNPROVEN")?
        .bundle_digest
        == digest
    {
        return Err("HOST_VM_IMAGE_RELEASE_ALREADY_INSTALLED".into());
    }
    let (previous_images, new_images, new_gateway_image, new_warp_image) =
        select_gateway_image_policy(stack_dir, request)?;
    for service in [ScopedVmService::Line1, ScopedVmService::Line2] {
        service.container_name(host)?;
    }
    let installed_graph = compile_native_vm_desired_graph(stack_dir, host)?;
    let current_gateway = super::read_exact_image_environment(stack_dir)?
        .get("EDGE_GATEWAY_IMAGE")
        .cloned()
        .ok_or("HOST_VM_IMAGE_CURRENT_GATEWAY_MISSING")?;
    validate_gateway_image_ownership(&installed_graph, &current_gateway)?;
    let mut target_graph = installed_graph.clone();
    let mut changed = 0;
    for row in &mut target_graph.resources {
        if row.resource.as_ref().is_some_and(|item| {
            matches!(
                item.compose_service.as_str(),
                "line1-gateway" | "line2-proxy"
            )
        }) {
            row.image_ref.clone_from(&new_gateway_image);
            changed += 1;
        }
    }
    if let Some(ref image) = new_warp_image {
        let warp = target_graph
            .resources
            .iter_mut()
            .find(|row| row.resource.as_ref().is_some_and(|r| r.compose_service == "warp-egress"))
            .ok_or("HOST_VM_IMAGE_WARP_OWNER_MISSING")?;
        warp.image_ref.clone_from(image);
        changed += 1;
    }
    if changed != 2 + usize::from(new_warp_image.is_some()) {
        return Err("HOST_VM_IMAGE_REGISTERED_SERVICES_INCOMPLETE".into());
    }
    edge_shared_types::host_resources::validate_vm_desired_graph(&target_graph, host)
        .map_err(str::to_owned)?;
    let docker = docker_connection().await?;
    let mut owned = owned_application_container_ids(&docker, &host.vm_containers).await?;
    if owned.len() != host.vm_containers.len() || owned.iter().any(|item| !item.running) {
        return Err("HOST_VM_IMAGE_ALL_REGISTERED_MUST_RUN".into());
    }
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut owned)?;
    owned_vm_start_order(&owned)?;
    let expected_images = read_vm_expected_image_refs(stack_dir, &host.vm_containers)?;
    if owned
        .iter()
        .any(|item| expected_images.get(&item.service) != Some(&item.image_ref))
    {
        return Err("HOST_VM_IMAGE_PREVIOUS_IDENTITY_DRIFT".into());
    }
    for service in [ScopedVmService::Line1, ScopedVmService::Line2] {
        verify_running_container_config_binding(
            service.container_name(host)?,
            &stack_dir.join(service.rendered_relative()),
        )
        .await?;
    }
    let edge_network_id = read_owned_edge_network_id(&docker, host).await?;
    verify_vm_network_attachments(&docker, host, &owned, &edge_network_id).await?;
    // Require both replacement image and exact network policy to be
    // available before committing the one-shot journal transaction.
    docker
        .inspect_image(&new_gateway_image)
        .await
        .map_err(|_| "HOST_VM_IMAGE_PINNED_IMAGE_NOT_LOCAL")?;
    let prepared_warp = if let Some(ref image) = new_warp_image {
        docker
            .inspect_image(image)
            .await
            .map_err(|_| "HOST_VM_IMAGE_WARP_PINNED_IMAGE_NOT_LOCAL")?;
        Some(native_warp_create_body(stack_dir, host, image, &edge_network_id)?)
    } else {
        None
    };
    let mut prepared_gateways = Vec::new();
    for service in ["line2-proxy", "line1-gateway"] {
        prepared_gateways.push((
            service.to_owned(),
            native_gateway_create_body(
                stack_dir,
                host,
                service,
                &new_gateway_image,
                &edge_network_id,
            )?,
        ));
    }
    let compose_sha256 = native_vm_compose_digest(stack_dir)?;
    let identities = host
        .vm_containers
        .iter()
        .map(|selector| {
            owned
                .iter()
                .find(|item| item.service == selector.compose_service)
                .map(|item| (item.id.clone(), item.running, item.image_ref.clone()))
        })
        .collect::<Vec<_>>();
    Ok(NativeVmGatewayImageReplacePlan {
        previous_images,
        new_images,
        new_gateway_image,
        new_warp_image,
        identities,
        installed_graph,
        target_graph,
        edge_network_id,
        prepared_gateways,
        prepared_warp,
        compose_sha256,
        release: edge_shared_types::ApplicationBundleReleaseState {
            schema_version: 1,
            bundle_id,
            bundle_digest: digest,
        },
    })
}

async fn apply_gateway_image_replace_once(
    stack_dir: &Path,
    host: &FleetHost,
    plan: NativeVmGatewayImageReplacePlan,
) -> Result<(), String> {
    let docker = docker_connection().await?;
    let mut owned = owned_application_container_ids(&docker, &host.vm_containers).await?;
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut owned)?;
    check_owned_vm_snapshot(host, &owned, &plan.identities)?;
    if compile_native_vm_desired_graph(stack_dir, host)? != plan.installed_graph
        || exact_vm_policy_file(stack_dir, ".images.env")? != plan.previous_images
        || native_vm_compose_digest(stack_dir)? != plan.compose_sha256
        || read_owned_edge_network_id(&docker, host).await? != plan.edge_network_id
    {
        return Err("HOST_VM_IMAGE_PRESTATE_CHANGED_NO_REPLAY".into());
    }
    verify_vm_network_attachments(&docker, host, &owned, &plan.edge_network_id).await?;

    let staging = stack_dir.join(".images.env.next");
    if fs::symlink_metadata(&staging).is_ok() {
        return Err("HOST_VM_IMAGE_STAGING_EXISTS_NO_REPLAY".into());
    }
    // The shared signed native journal has already persisted BEGIN. No
    // automatic rollback/retry can be safe if either Compose ACK is lost.
    fs::write(&staging, &plan.new_images).map_err(|_| "HOST_VM_IMAGE_STAGE_UNCERTAIN_NO_REPLAY")?;
    super::set_bundle_file_permissions(&staging, false, false)
        .map_err(|_| "HOST_VM_IMAGE_STAGE_PERMISSIONS_UNCERTAIN_NO_REPLAY")?;
    fs::rename(&staging, stack_dir.join(".images.env"))
        .map_err(|_| "HOST_VM_IMAGE_ACTIVATE_UNCERTAIN_NO_REPLAY")?;
    fs::File::open(stack_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "HOST_VM_IMAGE_SYNC_UNCERTAIN_NO_REPLAY")?;
    let image_vars = super::read_exact_image_environment(stack_dir)?;
    if image_vars.get("EDGE_GATEWAY_IMAGE") != Some(&plan.new_gateway_image)
        || (plan.new_warp_image.is_some()
            && image_vars.get("EDGE_WARP_EGRESS_IMAGE") != plan.new_warp_image.as_ref())
    {
        return Err("HOST_VM_IMAGE_ENV_NOT_CONVERGED_NO_REPLAY".into());
    }
    // WARP is a dependency of BOTH gateways: recreate it first, then the
    // two gateways, inside one durable native BEGIN. No Compose or shell.
    if let Some(body) = plan.prepared_warp {
        let previous = owned
            .iter()
            .find(|item| item.service == "warp-egress")
            .ok_or("HOST_VM_IMAGE_WARP_ID_MISSING_NO_REPLAY")?;
        recreate_native_vm_container_once(
            &docker,
            host,
            "warp-egress",
            &previous.id,
            &plan.edge_network_id,
            body,
        )
        .await?;
    }
    for (service, body) in plan.prepared_gateways {
        let previous = owned
            .iter()
            .find(|item| item.service == service)
            .ok_or("HOST_VM_IMAGE_TARGET_ID_MISSING_NO_REPLAY")?;
        recreate_native_gateway_once(
            &docker,
            host,
            &service,
            &previous.id,
            &plan.edge_network_id,
            body,
        )
        .await?;
    }
    let after = owned_application_container_ids(&docker, &host.vm_containers).await?;
    if after.len() != host.vm_containers.len() {
        return Err("HOST_VM_IMAGE_POSTSTATE_MISSING_NO_REPLAY".into());
    }
    for (selector, before) in host.vm_containers.iter().zip(&plan.identities) {
        let (old_id, old_running, old_image) = before
            .as_ref()
            .ok_or("HOST_VM_IMAGE_PRESTATE_IDENTITY_MISSING")?;
        let current = after
            .iter()
            .find(|item| item.service == selector.compose_service)
            .ok_or("HOST_VM_IMAGE_POSTSTATE_IDENTITY_MISSING_NO_REPLAY")?;
        if !*old_running || !current.running {
            return Err("HOST_VM_IMAGE_POSTSTATE_NOT_RUNNING_NO_REPLAY".into());
        }
        let gateway = matches!(
            selector.compose_service.as_str(),
            "line1-gateway" | "line2-proxy"
        );
        if gateway {
            if current.id == *old_id || current.image_ref != plan.new_gateway_image {
                return Err("HOST_VM_IMAGE_GATEWAY_NOT_RECREATED_NO_REPLAY".into());
            }
        } else if selector.compose_service == "warp-egress"
            && plan.new_warp_image.is_some()
        {
            if current.id == *old_id
                || Some(&current.image_ref) != plan.new_warp_image.as_ref()
            {
                return Err("HOST_VM_IMAGE_WARP_NOT_RECREATED_NO_REPLAY".into());
            }
        } else if current.id != *old_id || current.image_ref != *old_image {
            return Err("HOST_VM_IMAGE_NEIGHBOUR_CHANGED_NO_REPLAY".into());
        }
    }
    for service in [ScopedVmService::Line1, ScopedVmService::Line2] {
        verify_running_container_config_binding(
            service.container_name(host)?,
            &stack_dir.join(service.rendered_relative()),
        )
        .await
        .map_err(|_| "HOST_VM_IMAGE_CONFIG_POSTSTATE_UNPROVEN_NO_REPLAY")?;
    }
    if compile_native_vm_desired_graph(stack_dir, host)? != plan.target_graph {
        return Err("HOST_VM_IMAGE_GRAPH_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    super::write_application_release(stack_dir, &plan.release)
        .map_err(|_| "HOST_VM_IMAGE_RELEASE_UNCERTAIN_NO_REPLAY")?;
    Ok(())
}

/// The same signed HostIntent, owner lock and durable journal handle both
/// exact template changes and a paired immutable gateway-image update.
pub(crate) async fn preflight_native_vm_replace(
    stack_dir: &Path,
    host: &FleetHost,
    request: &ApplyBundleRequest,
) -> Result<NativeVmReplacePlan, String> {
    let target_graph = compile_vm_desired_graph_from_release(host, request)?;
    let installed_graph = compile_native_vm_desired_graph(stack_dir, host)?;
    let changes = edge_shared_types::host_resources::propose_vm_graph_reconcile(
        host,
        &installed_graph,
        &target_graph,
    )
    .map_err(str::to_owned)?;
    use edge_shared_types::{FleetResourceKind as Kind, FleetVmPolicyChange};
    // Only the canonical hierarchy may determine an effector's target.
    // Reject a mismatch before reading/writing any native container policy.
    let hierarchy =
        edge_shared_types::host_resources::derive_vm_resource_hierarchy(host, &target_graph)
            .map_err(str::to_owned)?;
    for resource in &changes.resources {
        let node = hierarchy
            .nodes
            .iter()
            .find(|node| node.resource_id == resource.resource_id)
            .ok_or("HOST_VM_RECONCILE_TARGET_NODE_UNREGISTERED")?;
        if node.kind != resource.resource_kind
            || node.owner != edge_shared_types::FleetResourceOwner::VmRootAgent as i32
        {
            return Err("HOST_VM_RECONCILE_TARGET_NODE_OWNER_INVALID".into());
        }
    }
    let changed = changes
        .resources
        .iter()
        .filter(|resource| resource.change != FleetVmPolicyChange::NoChange as i32)
        .collect::<Vec<_>>();
    // The existing native effectors support exactly two closed, independently
    // tested scopes. Unsupported network/dependency/combined changes never
    // fall through to the old whole-stack BootstrapFull mutator.
    let config_only = changed.len() == 1
        && changed[0].change == FleetVmPolicyChange::ConfigTemplateReplaced as i32
        && changed[0].resource_kind == Kind::SingboxConfig as i32
        && changed[0].resource.as_ref().is_some_and(|resource| {
            matches!(
                resource.compose_service.as_str(),
                "line1-gateway" | "line2-proxy"
            )
        });
    let gateway_pair = (changed.len() == 2 || changed.len() == 3)
        && changed.iter().all(|resource| {
            resource.change == FleetVmPolicyChange::ImageReplaced as i32
                && resource.resource_kind == Kind::DockerContainer as i32
        })
        && {
            let owners = changed
                .iter()
                .filter_map(|resource| resource.resource.as_ref())
                .map(|resource| resource.compose_service.as_str())
                .collect::<BTreeSet<_>>();
            owners == BTreeSet::from(["line1-gateway", "line2-proxy"])
                || owners == BTreeSet::from(["line1-gateway", "line2-proxy", "warp-egress"])
        };
    // A signed ReleaseSet may also mutate exactly one non-secret file
    // inside root-owned stack/managed. Changes to network/container/Compose
    // are never reinterpreted as file actions.
    if !config_only && !gateway_pair && !changed.is_empty() {
        return Err("HOST_VM_RECONCILE_EFFECTOR_NOT_IMPLEMENTED".into());
    }
    if config_only || gateway_pair {
        let images = request
            .stack_files
            .iter()
            .find(|file| file.relative_path == ".images.env")
            .ok_or("HOST_VM_REPLACE_IMAGE_ENV_MISSING")?;
        let current = exact_vm_policy_file(stack_dir, ".images.env")?;
        if (images.content != current) != gateway_pair {
            return Err("HOST_VM_RECONCILE_IMAGE_SCOPE_CONFLICT".into());
        }
    }
    let plan = if gateway_pair {
        preflight_gateway_image_replace(stack_dir, host, request)
            .await
            .map(NativeVmReplacePlan::GatewayImage)?
    } else if config_only {
        preflight_native_vm_scoped_replace(stack_dir, host, request)
            .await
            .map(NativeVmReplacePlan::Config)?
    } else {
        preflight_native_vm_managed_file(stack_dir, host, request, &installed_graph, &target_graph)
            .await
            .map(NativeVmReplacePlan::ManagedFile)?
    };
    let prepared_graph = match &plan {
        NativeVmReplacePlan::Config(value) => &value.target_graph,
        NativeVmReplacePlan::GatewayImage(value) => &value.target_graph,
        NativeVmReplacePlan::ManagedFile(value) => &value.target_graph,
    };
    if prepared_graph != &target_graph {
        return Err("HOST_VM_RELEASE_TARGET_GRAPH_MISMATCH".into());
    }
    Ok(plan)
}

pub(crate) async fn apply_native_vm_replace_once(
    stack_dir: &Path,
    host: &FleetHost,
    plan: NativeVmReplacePlan,
) -> Result<(), String> {
    match plan {
        NativeVmReplacePlan::Config(plan) => {
            apply_native_vm_scoped_replace_once(stack_dir, host, plan).await
        }
        NativeVmReplacePlan::GatewayImage(plan) => {
            apply_gateway_image_replace_once(stack_dir, host, plan).await
        }
        NativeVmReplacePlan::ManagedFile(plan) => {
            apply_native_vm_managed_file_once(stack_dir, host, plan).await
        }
    }
}

/// One signed config-only replacement. Exactly ONE application template may
/// change, never Compose, images, network, credentials, or shared policy.
#[derive(Debug)]
pub(crate) struct NativeVmScopedReplacePlan {
    target: ScopedVmService,
    identities: Vec<Option<(String, bool, String)>>,
    previous_template: Vec<u8>,
    new_template: Vec<u8>,
    // Unchanged files are checked again after BEGIN, before any mutation.
    unchanged_policy: Vec<(String, Vec<u8>)>,
    installed_graph: edge_shared_types::FleetVmDesiredGraph,
    target_graph: edge_shared_types::FleetVmDesiredGraph,
    release: edge_shared_types::ApplicationBundleReleaseState,
    expected_rendered_sha256: Vec<u8>,
    edge_network_id: String,
    prepared_gateway: bollard::models::ContainerCreateBody,
    compose_sha256: Vec<u8>,
}

fn exact_vm_policy_file(stack_dir: &Path, relative: &str) -> Result<Vec<u8>, String> {
    super::validate_bundle_relative_path(relative)?;
    let path = stack_dir.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|_| "HOST_NATIVE_VM_POLICY_FILE_MISSING")?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 4 * 1024 * 1024 {
        return Err("HOST_NATIVE_VM_POLICY_FILE_UNTRUSTED".into());
    }
    fs::read(&path).map_err(|_| "HOST_NATIVE_VM_POLICY_FILE_UNREADABLE".into())
}

/// The active immutable bundle manifest must not silently lose a file
/// merely because the target request omits it. Ignore only runtime-generated
/// files owned separately by this same root Agent.
fn installed_scoped_static_files(stack_dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut files = BTreeSet::new();
    let mut dirs = vec![stack_dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for item in fs::read_dir(&dir).map_err(|_| "HOST_NATIVE_VM_SCOPED_LIST_UNAVAILABLE")? {
            let item = item.map_err(|_| "HOST_NATIVE_VM_SCOPED_LIST_UNAVAILABLE")?;
            let path = item.path();
            let relative = path
                .strip_prefix(stack_dir)
                .map_err(|_| "HOST_NATIVE_VM_SCOPED_LIST_OUTSIDE_STACK")?
                .to_str()
                .ok_or("HOST_NATIVE_VM_SCOPED_FILE_NAME_INVALID")?
                .replace('\\', "/");
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| "HOST_NATIVE_VM_SCOPED_METADATA_UNAVAILABLE")?;
            if relative == "rendered" || relative == "certs" {
                if !metadata.file_type().is_dir() {
                    return Err("HOST_NATIVE_VM_SCOPED_RUNTIME_PATH_UNTRUSTED".into());
                }
                continue;
            }
            if metadata.file_type().is_dir() {
                dirs.push(path);
            } else if metadata.file_type().is_file() {
                if !matches!(
                    relative.as_str(),
                    ".env.runtime" | ".application-release.pb"
                ) && !files.insert(relative)
                {
                    return Err("HOST_NATIVE_VM_SCOPED_DUPLICATE_STATIC_FILE".into());
                }
            } else {
                return Err("HOST_NATIVE_VM_SCOPED_FOREIGN_FILE_TYPE".into());
            }
            if files.len() > 128 || dirs.len() > 128 {
                return Err("HOST_NATIVE_VM_SCOPED_FILE_COUNT_INVALID".into());
            }
        }
    }
    Ok(files)
}

/// Strict admission for the complete installed static bundle, rather than
/// trusting a container whose Compose/image files happen to match while its
/// sing-box config template or another Git-owned file has been modified.
/// Generated runtime, certs and release marker remain separately owned.
pub(crate) fn verify_exact_installed_vm_bundle_static(
    stack_dir: &Path,
    request: &ApplyBundleRequest,
) -> Result<(), String> {
    if request.stack_files.is_empty() || request.stack_files.len() > 128 {
        return Err("HOST_VM_STATIC_BUNDLE_SCOPE_INVALID".into());
    }
    let mut files = BTreeSet::new();
    for expected in &request.stack_files {
        super::validate_bundle_relative_path(&expected.relative_path)
            .map_err(|_| "HOST_VM_STATIC_BUNDLE_PATH_INVALID")?;
        if !files.insert(expected.relative_path.clone())
            || expected.content.is_empty()
            || expected.content.len() > 4 * 1024 * 1024
        {
            return Err("HOST_VM_STATIC_BUNDLE_FILE_INVALID".into());
        }
        if exact_vm_policy_file(stack_dir, &expected.relative_path)? != expected.content {
            return Err("HOST_VM_STATIC_BUNDLE_DRIFT".into());
        }
    }
    if files != installed_scoped_static_files(stack_dir)? {
        return Err("HOST_VM_STATIC_BUNDLE_MANIFEST_DRIFT".into());
    }
    Ok(())
}

fn select_scoped_template_policy(
    stack_dir: &Path,
    request: &ApplyBundleRequest,
) -> Result<(ScopedVmService, Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>), String> {
    if request.stack_files.is_empty() || request.stack_files.len() > 128 {
        return Err("HOST_NATIVE_VM_SCOPED_BUNDLE_INVALID".into());
    }
    let mut seen = BTreeSet::new();
    let mut changed = None;
    let mut unchanged = Vec::new();
    for file in &request.stack_files {
        if !seen.insert(file.relative_path.clone()) {
            return Err("HOST_NATIVE_VM_SCOPED_DUPLICATE_FILE".into());
        }
        let original = exact_vm_policy_file(stack_dir, &file.relative_path)?;
        if original == file.content {
            unchanged.push((file.relative_path.clone(), file.content.clone()));
            continue;
        }
        if changed.is_some() || file.sensitive || file.executable {
            return Err("HOST_NATIVE_VM_SCOPED_SHARED_POLICY_DRIFT".into());
        }
        let target = ScopedVmService::from_template(&file.relative_path)?;
        if file.content.is_empty() || file.content.len() > 65536 {
            return Err("HOST_NATIVE_VM_SCOPED_TEMPLATE_INVALID".into());
        }
        changed = Some((target, original, file.content.clone()));
    }
    let static_files = installed_scoped_static_files(stack_dir)?;
    if !seen.contains("docker-compose.yml")
        || !seen.contains(".images.env")
        || !seen.contains(".env.runtime.policy")
        || seen != static_files
    {
        return Err("HOST_NATIVE_VM_SCOPED_BUNDLE_INCOMPLETE".into());
    }
    let (target, before, after) =
        changed.ok_or_else(|| "HOST_NATIVE_VM_SCOPED_NO_SINGLE_TEMPLATE_CHANGE".to_owned())?;
    Ok((target, before, after, unchanged))
}

fn scoped_render_preview(
    target: ScopedVmService,
    template: &[u8],
    runtime: &BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    let mut values = runtime.clone();
    let required_keys: &[&str] = match target {
        ScopedVmService::Line1 => &super::LINE1_RUNTIME_TEMPLATE_KEYS,
        ScopedVmService::Line2 => {
            let (cert, key) = super::line2_certificate_container_paths(runtime)?;
            values.insert("PROXY_CERT_PATH".to_owned(), cert);
            values.insert("PROXY_KEY_PATH".to_owned(), key);
            &super::LINE2_RUNTIME_TEMPLATE_KEYS
        }
    };
    let mut text = std::str::from_utf8(template)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_TEMPLATE_NOT_UTF8")?
        .to_owned();
    for key in required_keys {
        let placeholder = format!("${{{key}}}");
        if !text.contains(&placeholder) {
            return Err("HOST_NATIVE_VM_SCOPED_TEMPLATE_PLACEHOLDER_MISSING".into());
        }
        let value = values
            .get(*key)
            .ok_or("HOST_NATIVE_VM_SCOPED_TEMPLATE_RUNTIME_MISSING")?;
        text = text.replace(&placeholder, value);
    }
    if text.contains("${") || serde_json::from_str::<serde_json::Value>(&text).is_err() {
        return Err("HOST_NATIVE_VM_SCOPED_RENDER_INVALID".into());
    }
    Ok(text.into_bytes())
}

/// Root-local admission prior to BEGIN. A partial Docker stack, changed
/// image, missing worker-projected runtime or edited unrelated policy is
/// not a request to recreate the whole application.
pub(crate) async fn preflight_native_vm_scoped_replace(
    stack_dir: &Path,
    host: &FleetHost,
    request: &ApplyBundleRequest,
) -> Result<NativeVmScopedReplacePlan, String> {
    let (bundle_id, digest) = super::validate_digest_bound_bundle_request(request)?;
    let previous_release = super::read_application_release(stack_dir)
        .ok_or("HOST_NATIVE_VM_SCOPED_PREVIOUS_RELEASE_UNPROVEN")?;
    if previous_release.bundle_digest == digest {
        return Err("HOST_NATIVE_VM_SCOPED_RELEASE_ALREADY_INSTALLED".into());
    }
    let (target, previous_template, new_template, unchanged_policy) =
        select_scoped_template_policy(stack_dir, request)?;
    // The Git-owned fleet registry, not a VM-specific hardcoded name,
    // provides the exact Docker identity for this semantic service.
    target.container_name(host)?;
    let installed_graph = compile_native_vm_desired_graph(stack_dir, host)?;
    let mut target_graph = installed_graph.clone();
    let resource = target_graph
        .resources
        .iter_mut()
        .find(|item| {
            item.resource
                .as_ref()
                .is_some_and(|selector| selector.compose_service == target.compose_service())
        })
        .ok_or("HOST_VM_SCOPED_GRAPH_RESOURCE_MISSING")?;
    resource.config_template_sha256 = ring::digest::digest(&ring::digest::SHA256, &new_template)
        .as_ref()
        .to_vec();
    edge_shared_types::host_resources::validate_vm_desired_graph(&target_graph, host)
        .map_err(str::to_owned)?;
    let runtime = super::read_typed_runtime_environment(stack_dir)?;
    let rendered = scoped_render_preview(target, &new_template, &runtime)?;
    let docker = docker_connection().await?;
    let mut owned = owned_application_container_ids(&docker, &host.vm_containers).await?;
    if owned.len() != host.vm_containers.len() || owned.iter().any(|item| !item.running) {
        return Err("HOST_NATIVE_VM_SCOPED_ALL_OWNED_CONTAINERS_MUST_RUN".into());
    }
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut owned)?;
    owned_vm_start_order(&owned)?;
    let image_refs = read_vm_expected_image_refs(stack_dir, &host.vm_containers)?;
    if owned
        .iter()
        .any(|item| image_refs.get(&item.service) != Some(&item.image_ref))
    {
        return Err("HOST_NATIVE_VM_SCOPED_IMAGE_DRIFT".into());
    }
    verify_running_container_config_binding(
        target.container_name(host)?,
        &stack_dir.join(target.rendered_relative()),
    )
    .await?;
    let edge_network_id = read_owned_edge_network_id(&docker, host).await?;
    verify_vm_network_attachments(&docker, host, &owned, &edge_network_id).await?;
    let image_ref = image_refs
        .get(target.compose_service())
        .ok_or("HOST_VM_SCOPED_IMAGE_MISSING")?;
    let prepared_gateway = native_gateway_create_body(
        stack_dir,
        host,
        target.compose_service(),
        image_ref,
        &edge_network_id,
    )?;
    let compose_sha256 = native_vm_compose_digest(stack_dir)?;
    let identities = host
        .vm_containers
        .iter()
        .map(|selector| {
            owned
                .iter()
                .find(|item| item.service == selector.compose_service)
                .map(|item| (item.id.clone(), item.running, item.image_ref.clone()))
        })
        .collect();
    Ok(NativeVmScopedReplacePlan {
        target,
        identities,
        previous_template,
        new_template,
        unchanged_policy,
        installed_graph,
        target_graph,
        release: edge_shared_types::ApplicationBundleReleaseState {
            schema_version: 1,
            bundle_id,
            bundle_digest: digest,
        },
        expected_rendered_sha256: ring::digest::digest(&ring::digest::SHA256, &rendered)
            .as_ref()
            .to_vec(),
        edge_network_id,
        prepared_gateway,
        compose_sha256,
    })
}

/// One mutation authority and one existing journal. The prepared exact
/// Docker Engine API body replaces the scoped gateway without Compose.
/// All other resource identities and image references must remain unchanged.
pub(crate) async fn apply_native_vm_scoped_replace_once(
    stack_dir: &Path,
    host: &FleetHost,
    plan: NativeVmScopedReplacePlan,
) -> Result<(), String> {
    let docker = docker_connection().await?;
    let mut before = owned_application_container_ids(&docker, &host.vm_containers).await?;
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut before)?;
    check_owned_vm_snapshot(host, &before, &plan.identities)?;
    if compile_native_vm_desired_graph(stack_dir, host)? != plan.installed_graph
        || native_vm_compose_digest(stack_dir)? != plan.compose_sha256
        || read_owned_edge_network_id(&docker, host).await? != plan.edge_network_id
    {
        return Err("HOST_VM_SCOPED_GRAPH_CHANGED_NO_REPLAY".into());
    }
    verify_vm_network_attachments(&docker, host, &before, &plan.edge_network_id).await?;
    if exact_vm_policy_file(stack_dir, plan.target.template_relative())? != plan.previous_template {
        return Err("HOST_NATIVE_VM_SCOPED_PRESTATE_CHANGED_NO_REPLAY".into());
    }
    // Do not silently adopt a changed neighbour, shared Compose/image policy,
    // or an alternate static bundle between admission and execution.
    for (path, expected) in &plan.unchanged_policy {
        if exact_vm_policy_file(stack_dir, path)? != *expected {
            return Err("HOST_NATIVE_VM_SCOPED_UNRELATED_DRIFT_NO_REPLAY".into());
        }
    }
    let runtime = super::read_typed_runtime_environment(stack_dir)?;
    let rendered = scoped_render_preview(plan.target, &plan.new_template, &runtime)?;
    if ring::digest::digest(&ring::digest::SHA256, &rendered).as_ref()
        != plan.expected_rendered_sha256.as_slice()
    {
        return Err("HOST_NATIVE_VM_SCOPED_RENDER_CHANGED_NO_REPLAY".into());
    }
    let template_path = stack_dir.join(plan.target.template_relative());
    let candidate_path = template_path.with_extension("next");
    if candidate_path.exists() {
        return Err("HOST_NATIVE_VM_SCOPED_STAGING_EXISTS_NO_REPLAY".into());
    }
    // BEGIN already persisted by the shared native journal. Any failed write,
    // Docker ACK or poststate is UNKNOWN; never restore/retry implicitly.
    fs::write(&candidate_path, &plan.new_template)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_WRITE_UNCERTAIN_NO_REPLAY")?;
    super::set_bundle_file_permissions(&candidate_path, false, false)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_PERMISSIONS_UNCERTAIN_NO_REPLAY")?;
    fs::rename(&candidate_path, &template_path)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_ACTIVATE_UNCERTAIN_NO_REPLAY")?;
    fs::File::open(
        template_path
            .parent()
            .ok_or("HOST_NATIVE_VM_SCOPED_TEMPLATE_PARENT_INVALID")?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| "HOST_NATIVE_VM_SCOPED_SYNC_UNCERTAIN_NO_REPLAY")?;
    plan.target
        .render(stack_dir, &runtime)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_RENDER_UNCERTAIN_NO_REPLAY")?;
    let previous_id = before
        .iter()
        .find(|item| item.service == plan.target.compose_service())
        .ok_or("HOST_NATIVE_VM_SCOPED_OLD_ID_MISSING_NO_REPLAY")?
        .id
        .clone();
    recreate_native_gateway_once(
        &docker,
        host,
        plan.target.compose_service(),
        &previous_id,
        &plan.edge_network_id,
        plan.prepared_gateway,
    )
    .await?;
    let after = owned_application_container_ids(&docker, &host.vm_containers).await?;
    if after.len() != host.vm_containers.len() {
        return Err("HOST_NATIVE_VM_SCOPED_POSTSTATE_MISSING_NO_REPLAY".into());
    }
    for (selector, earlier) in host.vm_containers.iter().zip(&plan.identities) {
        let (prior_id, prior_running, prior_image) = earlier
            .as_ref()
            .ok_or("HOST_NATIVE_VM_SCOPED_PRESTATE_IDENTITY_MISSING")?;
        let current = after
            .iter()
            .find(|item| item.service == selector.compose_service)
            .ok_or("HOST_NATIVE_VM_SCOPED_POSTSTATE_OWNER_MISSING_NO_REPLAY")?;
        if !current.running || !*prior_running || current.image_ref != *prior_image {
            return Err("HOST_NATIVE_VM_SCOPED_POSTSTATE_INCORRECT_NO_REPLAY".into());
        }
        if selector.compose_service == plan.target.compose_service() {
            if current.id == *prior_id {
                return Err("HOST_NATIVE_VM_SCOPED_TARGET_NOT_RECREATED_NO_REPLAY".into());
            }
        } else if current.id != *prior_id {
            return Err("HOST_NATIVE_VM_SCOPED_NEIGHBOUR_CHANGED_NO_REPLAY".into());
        }
    }
    verify_running_container_config_binding(
        plan.target.container_name(host)?,
        &stack_dir.join(plan.target.rendered_relative()),
    )
    .await
    .map_err(|_| "HOST_NATIVE_VM_SCOPED_CONFIG_POSTSTATE_UNPROVEN_NO_REPLAY")?;
    let bytes = fs::read(stack_dir.join(plan.target.rendered_relative()))
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_CONFIG_POSTSTATE_UNREADABLE")?;
    if ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()
        != plan.expected_rendered_sha256.as_slice()
    {
        return Err("HOST_NATIVE_VM_SCOPED_CONFIG_HASH_MISMATCH_NO_REPLAY".into());
    }
    if compile_native_vm_desired_graph(stack_dir, host)? != plan.target_graph {
        return Err("HOST_VM_SCOPED_GRAPH_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    super::write_application_release(stack_dir, &plan.release)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_RELEASE_UNCERTAIN_NO_REPLAY")?;
    Ok(())
}

/// Topological order comes from inspected Compose ownership labels. Failure
/// on absent/foreign dependencies is conservative: never start another
/// container in an unknown order, or mutate independently owned Mesh.
fn owned_vm_start_order(owned: &[OwnedVmContainer]) -> Result<Vec<usize>, String> {
    let mut order = Vec::with_capacity(owned.len());
    let mut completed = BTreeSet::new();
    while order.len() < owned.len() {
        let mut progressed = false;
        for (index, resource) in owned.iter().enumerate() {
            if !completed.contains(resource.service.as_str())
                && resource
                    .dependencies
                    .iter()
                    .all(|dependency| completed.contains(dependency.as_str()))
            {
                completed.insert(resource.service.as_str());
                order.push(index);
                progressed = true;
            }
        }
        if !progressed {
            return Err("HOST_NATIVE_VM_DEPENDENCIES_MISSING_OR_CYCLIC".into());
        }
    }
    Ok(order)
}

/// STOP is safe even if an upstream dependency has already disappeared.
/// Reverse the order of the remaining owned containers without adopting
/// missing/foreign dependencies. START retains its strict dependency gate.
fn owned_vm_stop_order(owned: &[OwnedVmContainer]) -> Result<Vec<usize>, String> {
    let services = owned
        .iter()
        .map(|resource| resource.service.as_str())
        .collect::<BTreeSet<_>>();
    let mut present = owned.to_vec();
    for resource in &mut present {
        resource
            .dependencies
            .retain(|dependency| services.contains(dependency.as_str()));
    }
    let mut order = owned_vm_start_order(&present)?;
    order.reverse();
    Ok(order)
}

fn native_vm_compose_digest(stack_dir: &Path) -> Result<Vec<u8>, String> {
    let path = stack_dir.join("docker-compose.yml");
    let meta = fs::symlink_metadata(&path).map_err(|_| "HOST_VM_COMPOSE_BYTES_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 65536 {
        return Err("HOST_VM_COMPOSE_BYTES_UNTRUSTED".into());
    }
    let raw = fs::read(&path).map_err(|_| "HOST_VM_COMPOSE_BYTES_UNREADABLE")?;
    if raw.len() as u64 != meta.len() {
        return Err("HOST_VM_COMPOSE_BYTES_UNSTABLE".into());
    }
    Ok(ring::digest::digest(&ring::digest::SHA256, &raw)
        .as_ref()
        .to_vec())
}

fn read_native_vm_compose(stack_dir: &Path) -> Result<serde_yaml::Value, String> {
    let compose_path = stack_dir.join("docker-compose.yml");
    let meta =
        fs::symlink_metadata(&compose_path).map_err(|_| "HOST_NATIVE_COMPOSE_UNAVAILABLE")?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 65536 {
        return Err("HOST_NATIVE_COMPOSE_UNPROVEN".into());
    }
    let bytes = fs::read(&compose_path).map_err(|_| "HOST_NATIVE_COMPOSE_UNREADABLE")?;
    serde_yaml::from_slice(&bytes).map_err(|_| "HOST_NATIVE_COMPOSE_PARSE_INVALID".into())
}

/// The trusted installed Compose file is the ONLY service->image mapping.
/// Image digests come from the existing ReleaseSet-owned image environment;
/// neither runners nor a second resource registry can override them.
fn resolve_owned_vm_images(
    compose: &serde_yaml::Value,
    images: &BTreeMap<String, String>,
    expected: &[FleetVmContainer],
) -> Result<HashMap<String, String>, String> {
    let services = compose
        .get("services")
        .ok_or("HOST_NATIVE_COMPOSE_SERVICES_UNPROVEN")?;
    let mut result = HashMap::new();
    for resource in expected {
        let raw = services
            .get(resource.compose_service.as_str())
            .and_then(|entry| entry.get("image"))
            .and_then(serde_yaml::Value::as_str)
            .ok_or("HOST_NATIVE_COMPOSE_IMAGE_UNPROVEN")?;
        let inner = raw
            .strip_prefix("${")
            .and_then(|value| value.strip_suffix('}'))
            .ok_or("HOST_NATIVE_COMPOSE_IMAGE_NOT_PINNED")?;
        let (key, required) = inner
            .split_once(":?")
            .ok_or("HOST_NATIVE_COMPOSE_IMAGE_NOT_PINNED")?;
        if key.is_empty() || required.is_empty() {
            return Err("HOST_NATIVE_COMPOSE_IMAGE_NOT_PINNED".into());
        }
        let pinned = images
            .get(key)
            .ok_or("HOST_NATIVE_COMPOSE_IMAGE_KEY_MISSING")?;
        if !pinned.contains("@sha256:") {
            return Err("HOST_NATIVE_COMPOSE_IMAGE_DIGEST_REQUIRED".into());
        }
        result.insert(resource.compose_service.clone(), pinned.clone());
    }
    Ok(result)
}

fn read_vm_expected_image_refs(
    stack_dir: &Path,
    expected: &[FleetVmContainer],
) -> Result<HashMap<String, String>, String> {
    let compose = read_native_vm_compose(stack_dir)?;
    let images = super::read_exact_image_environment(stack_dir)?;
    resolve_owned_vm_images(&compose, &images, expected)
}

async fn prepare_owned_vm_start(
    docker: &Docker,
    stack_dir: &Path,
    expected: &[FleetVmContainer],
) -> Result<(Vec<OwnedVmContainer>, Vec<usize>), String> {
    let expected_images = read_vm_expected_image_refs(stack_dir, expected)?;
    let mut owned = owned_application_container_ids(docker, expected).await?;
    if owned.len() != expected.len() {
        return Err("HOST_NATIVE_VM_START_REQUIRES_EXISTING_CONTAINERS".into());
    }
    bind_owned_vm_compose_dependencies(stack_dir, expected, &mut owned)?;
    // A root journal cannot make Docker state safe if an apparently owned
    // container is still running an image other than the ReleaseSet image.
    for container in &owned {
        if expected_images.get(&container.service) != Some(&container.image_ref) {
            return Err("HOST_NATIVE_VM_START_IMAGE_MISMATCH".into());
        }
    }
    let order = owned_vm_start_order(&owned)?;
    if !owned.iter().any(|container| !container.running) {
        return Err("HOST_NATIVE_VM_START_NO_STOPPED_CONTAINER".into());
    }
    Ok((owned, order))
}

#[cfg(test)]
mod release_desired_graph_tests {
    use super::*;

    #[test]
    fn native_gateway_create_rejects_unregistered_and_mesh_resources() {
        let host = edge_shared_types::FleetHost::default();
        assert_eq!(
            native_gateway_create_body(
                Path::new("/unavailable"),
                &host,
                "cloudflare-mesh",
                "image@sha256:deadbeef",
                &"a".repeat(64)
            )
            .unwrap_err(),
            "HOST_VM_CREATE_NATIVE_SCOPE_INVALID"
        );
        assert_eq!(
            native_gateway_create_body(
                Path::new("/unavailable"),
                &host,
                "line2-proxy",
                "image@sha256:deadbeef",
                &"a".repeat(64)
            )
            .unwrap_err(),
            "HOST_VM_CREATE_NATIVE_SELECTOR_UNREGISTERED"
        );
    }

    #[test]
    fn installed_policy_stage_not_inferred_from_error_words() {
        use edge_shared_types::FleetVmInstalledPolicyStatus as Status;
        let mislabeled =
            NativeVmPolicyFailure::at(Status::ImageInvalid, "HOST_VM_NETWORK_POLICY_UNSUPPORTED");
        assert_eq!(mislabeled.status, Status::ImageInvalid);
        assert_eq!(mislabeled.code, "HOST_VM_NETWORK_POLICY_UNSUPPORTED");
        let concealed =
            NativeVmPolicyFailure::at(Status::ComposeInvalid, "credentials=/etc/shadow");
        assert_eq!(concealed.status, Status::ComposeInvalid);
        assert_eq!(concealed.code, "HOST_VM_POLICY_ERROR_UNCLASSIFIED");
    }

    #[test]
    fn immutable_target_graph_is_independent_of_installed_template_bytes() {
        let project = "vultr-edge";
        let identities = ["line1-gateway", "line2-proxy", "warp-egress"]
            .iter()
            .map(|service| FleetVmContainer {
                container_name: format!("vultr-{service}"),
                compose_project: project.into(),
                compose_service: (*service).into(),
            })
            .collect::<Vec<_>>();
        let host = FleetHost {
            machine_id: "vm-test".into(),
            kind: edge_shared_types::FleetHostKind::Vm as i32,
            vm_containers: identities,
            ..Default::default()
        };
        let compose = serde_yaml::from_str::<serde_yaml::Value>(
            "name: vultr-edge\nservices:\n  line1-gateway:\n    image: ${EDGE_GATEWAY_IMAGE:?required}\n    depends_on: [warp-egress]\n    networks: [edge_net]\n  line2-proxy:\n    image: ${EDGE_GATEWAY_IMAGE:?required}\n    depends_on: [warp-egress]\n    networks: [edge_net]\n  warp-egress:\n    image: ${EDGE_WARP_EGRESS_IMAGE:?required}\n    networks: [edge_net]\nnetworks:\n  edge_net:\n    driver: bridge\n",
        ).unwrap();
        let gateway = format!(
            "ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}",
            "a".repeat(64)
        );
        let warp = format!(
            "ghcr.io/iamaman11/vultr-warp-egress@sha256:{}",
            "b".repeat(64)
        );
        let mut images = BTreeMap::new();
        images.insert("EDGE_GATEWAY_IMAGE".into(), gateway.clone());
        images.insert("EDGE_WARP_EGRESS_IMAGE".into(), warp);
        let make_graph = |line2: &[u8]| {
            compile_vm_graph_from_parts(&host, &compose, &images, |path| {
                if path.starts_with("line2-proxy/") {
                    Ok(line2.to_vec())
                } else {
                    Ok(b"line1".to_vec())
                }
            })
            .unwrap()
        };
        let before = make_graph(b"old-template");
        let desired = make_graph(b"new-template");
        verify_scoped_gateway_network_policy(&host, &desired, "line2-proxy").unwrap();
        assert!(verify_scoped_gateway_network_policy(&host, &desired, "warp-egress").is_err());
        validate_gateway_image_ownership(&desired, &gateway).unwrap();
        assert_ne!(before, desired);
        assert_eq!(before.resources[0], desired.resources[0]);
        assert_ne!(before.resources[1], desired.resources[1]);
        assert_eq!(before.resources[2], desired.resources[2]);

        let mut foreign = compose.clone();
        foreign["services"]["line2-proxy"]["depends_on"] =
            serde_yaml::from_str("[foreign-mesh]").unwrap();
        let failure =
            compile_vm_graph_from_parts(&host, &foreign, &images, |_| Ok(b"template".to_vec()))
                .unwrap_err();
        assert_eq!(
            failure.status,
            edge_shared_types::FleetVmInstalledPolicyStatus::DependencyInvalid
        );
        // Even if the code mentions IMAGE, the failure's stage is dependency.
        let mut no_network = compose.clone();
        no_network["services"]["line2-proxy"]["networks"] =
            serde_yaml::from_str("[foreign]").unwrap();
        let failure =
            compile_vm_graph_from_parts(&host, &no_network, &images, |_| Ok(b"template".to_vec()))
                .unwrap_err();
        assert_eq!(
            failure.status,
            edge_shared_types::FleetVmInstalledPolicyStatus::NetworkInvalid
        );
    }

    #[test]
    fn immutable_image_environment_requires_all_three_exact_digest_pins() {
        let gateway = format!(
            "ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}",
            "a".repeat(64)
        );
        let warp = format!(
            "ghcr.io/iamaman11/vultr-warp-egress@sha256:{}",
            "b".repeat(64)
        );
        let mesh = format!("docker.io/cloudflare/mesh@sha256:{}", "c".repeat(64));
        let pins = format!(
            "EDGE_GATEWAY_IMAGE={gateway}\nEDGE_WARP_EGRESS_IMAGE={warp}\nCLOUDFLARE_MESH_IMAGE={mesh}\n"
        );
        assert!(parse_vm_release_image_pins(pins.as_bytes()).is_ok());
        assert!(
            parse_vm_release_image_pins(pins.replace("@sha256:", ":latest").as_bytes()).is_err()
        );
        assert!(
            parse_vm_release_image_pins(format!("{pins}EDGE_GATEWAY_IMAGE={gateway}\n").as_bytes())
                .is_err()
        );
        assert!(
            parse_vm_release_image_pins(
                pins.replace("CLOUDFLARE_MESH_IMAGE", "FOREIGN_IMAGE")
                    .as_bytes()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod vm_native_start_order_tests {
    use super::*;

    fn item(service: &str, dependencies: &[&str]) -> OwnedVmContainer {
        OwnedVmContainer {
            id: "b".repeat(64),
            running: false,
            service: service.to_owned(),
            dependencies: dependencies
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            image_ref: "ghcr.io/example/app@sha256:".to_owned() + &"a".repeat(64),
        }
    }

    #[test]
    fn compose_network_policy_is_typed_not_an_implicit_or_foreign_fallback() {
        let compose: serde_yaml::Value = serde_yaml::from_str(
            "name: vultr-edge\nservices:\n  line1-gateway:\n    networks: [edge_net]\n  warp-egress:\n    networks: [edge_net]\n  cloudflare-mesh:\n    networks: [mesh_net]\nnetworks:\n  edge_net:\n    driver: bridge\n  mesh_net:\n    driver: bridge\n",
        )
        .unwrap();
        let host = FleetHost {
            vm_containers: ["line1-gateway", "warp-egress"]
                .iter()
                .map(|name| FleetVmContainer {
                    container_name: format!("vultr-{name}"),
                    compose_project: "vultr-edge".into(),
                    compose_service: (*name).into(),
                })
                .collect(),
            ..Default::default()
        };
        let networks = compile_vm_networks_from_compose(&host, &compose).unwrap();
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].network_name, "edge_net");
        assert_eq!(
            networks[0].attached_services,
            vec!["line1-gateway", "warp-egress"]
        );
        let mut changed = compose.clone();
        changed["services"]["warp-egress"]["networks"] =
            serde_yaml::from_str("[mesh_net]").unwrap();
        assert!(compile_vm_networks_from_compose(&host, &changed).is_ok());
        // A changed network is independently represented in DesiredGraph;
        // unsupported topology must not be admitted by native effectors.
        changed["networks"]["mesh_net"]["driver"] = serde_yaml::from_str("host").unwrap();
        assert!(compile_vm_networks_from_compose(&host, &changed).is_err());
        changed = compose;
        changed["networks"]["edge_net"]["internal"] = serde_yaml::from_str("true").unwrap();
        assert!(compile_vm_networks_from_compose(&host, &changed).is_err());
    }

    #[test]
    fn image_identity_is_derived_only_from_trusted_compose_and_pinned_release() {
        let compose: serde_yaml::Value = serde_yaml::from_str(
            "services:\n  line2-proxy:\n    image: ${EDGE_GATEWAY_IMAGE:?required}\n",
        )
        .unwrap();
        let resources = vec![FleetVmContainer {
            container_name: "test-line2".into(),
            compose_project: "test".into(),
            compose_service: "line2-proxy".into(),
        }];
        let mut images = BTreeMap::new();
        let digest = "ghcr.io/example/app@sha256:".to_owned() + &"a".repeat(64);
        images.insert("EDGE_GATEWAY_IMAGE".into(), digest.clone());
        let selected = resolve_owned_vm_images(&compose, &images, &resources).unwrap();
        assert_eq!(selected["line2-proxy"], digest);
        images.insert(
            "EDGE_GATEWAY_IMAGE".into(),
            "ghcr.io/example/app:latest".into(),
        );
        assert!(resolve_owned_vm_images(&compose, &images, &resources).is_err());
        images.clear();
        assert!(resolve_owned_vm_images(&compose, &images, &resources).is_err());
    }

    #[test]
    fn compose_is_sole_start_order_for_line1_line2_and_warp() {
        let compose: serde_yaml::Value = serde_yaml::from_str(
            "name: vultr-edge\nservices:\n  line1-gateway:\n    depends_on: [warp-egress]\n  line2-proxy:\n    depends_on:\n      warp-egress:\n        condition: service_started\n  warp-egress:\n    image: test\n  cloudflare-mesh:\n    image: foreign\n",
        )
        .unwrap();
        let selectors = ["line1-gateway", "line2-proxy", "warp-egress"]
            .iter()
            .map(|service| FleetVmContainer {
                container_name: format!("vultr-{service}"),
                compose_project: "vultr-edge".into(),
                compose_service: (*service).into(),
            })
            .collect::<Vec<_>>();
        let declared = resolve_compose_dependencies(&compose, &selectors).unwrap();
        assert_eq!(declared["line1-gateway"], vec!["warp-egress"]);
        assert_eq!(declared["line2-proxy"], vec!["warp-egress"]);
        assert!(declared["warp-egress"].is_empty());
        let mut observed = vec![
            item("line1-gateway", &[]),
            item("line2-proxy", &[]),
            item("warp-egress", &[]),
        ];
        for item in &mut observed {
            item.dependencies = declared[&item.service].clone();
        }
        assert_eq!(owned_vm_start_order(&observed).unwrap(), vec![2, 0, 1]);
        let mut foreign = compose.clone();
        foreign["services"]["line1-gateway"]["depends_on"] =
            serde_yaml::from_str("[cloudflare-mesh]").unwrap();
        assert!(resolve_compose_dependencies(&foreign, &selectors).is_err());
    }

    #[test]
    fn exact_compose_network_attachment_rejects_missing_foreign_or_multiple_networks() {
        let network_id = "a".repeat(64);
        let mut endpoint = bollard::models::EndpointSettings::default();
        endpoint.network_id = Some(network_id.clone());
        let mut endpoints = HashMap::from([("vultr-edge_edge_net".to_owned(), endpoint)]);
        assert!(exact_owned_network_attachment(
            Some(&endpoints),
            "vultr-edge_edge_net",
            &network_id
        ));
        assert!(!exact_owned_network_attachment(
            None,
            "vultr-edge_edge_net",
            &network_id
        ));
        assert!(!exact_owned_network_attachment(
            Some(&endpoints),
            "foreign_edge_net",
            &network_id
        ));
        assert!(!exact_owned_network_attachment(
            Some(&endpoints),
            "vultr-edge_edge_net",
            &"b".repeat(64)
        ));
        endpoints.insert(
            "foreign_mesh_net".into(),
            bollard::models::EndpointSettings::default(),
        );
        assert!(!exact_owned_network_attachment(
            Some(&endpoints),
            "vultr-edge_edge_net",
            &network_id
        ));
    }

    #[test]
    fn scoped_create_is_only_one_gateway_with_unchanged_neighbours() {
        use edge_shared_types::{FleetVmResourceTransition, FleetVmResourceTransitionPlan};
        let selectors = ["line1-gateway", "line2-proxy", "warp-egress"]
            .into_iter()
            .map(|service| FleetVmContainer {
                container_name: format!("vultr-{service}"),
                compose_project: "vultr-edge".into(),
                compose_service: service.to_owned(),
            })
            .collect::<Vec<_>>();
        let host = FleetHost {
            vm_containers: selectors.clone(),
            ..Default::default()
        };
        let mut plan = FleetVmResourceTransitionPlan {
            schema_version: 1,
            resources: selectors
                .iter()
                .map(|resource| FleetVmResourceTransition {
                    resource: Some(resource.clone()),
                    step: FleetHostPlannedStep::Noop as i32,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        plan.resources[1].step = FleetHostPlannedStep::Install as i32;
        assert_eq!(
            select_scoped_vm_create(&host, &plan, FleetHostPlannedStep::Start).unwrap(),
            Some("line2-proxy".into())
        );
        plan.resources[0].step = FleetHostPlannedStep::Install as i32;
        assert!(select_scoped_vm_create(&host, &plan, FleetHostPlannedStep::Start).is_err());
        plan.resources[0].step = FleetHostPlannedStep::Noop as i32;
        plan.resources[1].step = FleetHostPlannedStep::Noop as i32;
        plan.resources[2].step = FleetHostPlannedStep::Install as i32;
        assert!(select_scoped_vm_create(&host, &plan, FleetHostPlannedStep::Start).is_err());
        plan.resources[2].step = FleetHostPlannedStep::Noop as i32;
        plan.resources[1].step = FleetHostPlannedStep::Install as i32;
        plan.resources[0].step = FleetHostPlannedStep::Start as i32;
        assert!(select_scoped_vm_create(&host, &plan, FleetHostPlannedStep::Start).is_err());
        assert_eq!(
            select_scoped_vm_create(&host, &plan, FleetHostPlannedStep::Stop).unwrap(),
            None
        );
    }

    #[test]
    fn scoped_create_poststate_preserves_siblings_and_exact_image() {
        let selectors = ["line1-gateway", "line2-proxy", "warp-egress"]
            .into_iter()
            .map(|service| FleetVmContainer {
                container_name: format!("vultr-{service}"),
                compose_project: "vultr-edge".into(),
                compose_service: service.to_owned(),
            })
            .collect::<Vec<_>>();
        let host = FleetHost {
            machine_id: "vm-a".into(),
            vm_containers: selectors.clone(),
            ..Default::default()
        };
        let image = format!("example/gateway@sha256:{}", "a".repeat(64));
        let warp = format!("example/warp@sha256:{}", "b".repeat(64));
        let graph = edge_shared_types::FleetVmDesiredGraph {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resources: selectors
                .iter()
                .enumerate()
                .map(|(i, resource)| edge_shared_types::FleetVmDesiredResource {
                    resource: Some(resource.clone()),
                    image_ref: if i == 2 { warp.clone() } else { image.clone() },
                    config_template_sha256: if i == 2 { vec![] } else { vec![8; 32] },
                    ..Default::default()
                })
                .collect(),
            networks: vec![edge_shared_types::FleetVmDesiredNetwork {
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
        let plan = NativeVmRunPlan {
            step: FleetHostPlannedStep::Start,
            identities: vec![
                Some(("1".repeat(64), true, image.clone())),
                None,
                Some(("3".repeat(64), true, warp.clone())),
            ],
            desired_graph: Some(graph),
            create_missing: Some("line2-proxy".into()),
            prepared_create: None,
            compose_sha256: None,
            edge_network_id: None,
        };
        let after = vec![
            OwnedVmContainer {
                id: "1".repeat(64),
                running: true,
                service: "line1-gateway".into(),
                dependencies: vec![],
                image_ref: image.clone(),
            },
            OwnedVmContainer {
                id: "2".repeat(64),
                running: true,
                service: "line2-proxy".into(),
                dependencies: vec![],
                image_ref: image.clone(),
            },
            OwnedVmContainer {
                id: "3".repeat(64),
                running: true,
                service: "warp-egress".into(),
                dependencies: vec![],
                image_ref: warp,
            },
        ];
        assert!(verify_native_vm_run_poststate(&host, &plan, &after).is_ok());
        let mut foreign_image = after.clone();
        foreign_image[1].image_ref = "foreign:latest".into();
        assert!(verify_native_vm_run_poststate(&host, &plan, &foreign_image).is_err());
        let mut touched_sibling = after.clone();
        touched_sibling[0].id = "4".repeat(64);
        assert!(verify_native_vm_run_poststate(&host, &plan, &touched_sibling).is_err());
        let mut absent = after;
        absent.remove(1);
        assert!(verify_native_vm_run_poststate(&host, &plan, &absent).is_err());
    }

    #[test]
    fn native_run_snapshot_rejects_id_replacement_or_state_change() {
        let host = FleetHost {
            vm_containers: vec![FleetVmContainer {
                container_name: "line2".into(),
                compose_project: "app".into(),
                compose_service: "line2-proxy".into(),
            }],
            ..Default::default()
        };
        let before = vec![Some((
            "a".repeat(64),
            false,
            "ghcr.io/example/app@sha256:".to_owned() + &"a".repeat(64),
        ))];
        let observed = vec![item("line2-proxy", &[])];
        assert!(check_owned_vm_snapshot(&host, &observed, &before).is_err());
        let mut matching = observed;
        matching[0].id = "a".repeat(64);
        assert!(check_owned_vm_snapshot(&host, &matching, &before).is_ok());
        matching[0].running = true;
        assert!(check_owned_vm_snapshot(&host, &matching, &before).is_err());
    }

    #[test]
    fn start_and_stop_require_exact_scoped_poststate() {
        let host = FleetHost {
            vm_containers: vec![
                FleetVmContainer {
                    container_name: "vultr-line1-gateway".into(),
                    compose_project: "vultr-edge".into(),
                    compose_service: "line1-gateway".into(),
                },
                FleetVmContainer {
                    container_name: "vultr-line2-proxy".into(),
                    compose_project: "vultr-edge".into(),
                    compose_service: "line2-proxy".into(),
                },
            ],
            ..Default::default()
        };
        let mut before = vec![item("line1-gateway", &[]), item("line2-proxy", &[])];
        before[0].id = "1".repeat(64);
        before[1].id = "2".repeat(64);
        before[0].running = true;
        let snapshot = before
            .iter()
            .map(|item| Some((item.id.clone(), item.running, item.image_ref.clone())))
            .collect::<Vec<_>>();
        let start = NativeVmRunPlan {
            step: FleetHostPlannedStep::Start,
            identities: snapshot,
            desired_graph: None,
            create_missing: None,
            prepared_create: None,
            compose_sha256: None,
            edge_network_id: None,
        };
        assert!(verify_native_vm_run_poststate(&host, &start, &before).is_err());
        let mut after = before.clone();
        after[1].running = true;
        assert!(verify_native_vm_run_poststate(&host, &start, &after).is_ok());
        after[0].id = "3".repeat(64);
        assert!(verify_native_vm_run_poststate(&host, &start, &after).is_err());
        after[0].id = "1".repeat(64);
        after[0].image_ref = "foreign:latest".into();
        assert!(verify_native_vm_run_poststate(&host, &start, &after).is_err());
        let stop = NativeVmRunPlan {
            step: FleetHostPlannedStep::Stop,
            identities: vec![
                Some((before[0].id.clone(), true, before[0].image_ref.clone())),
                Some((before[1].id.clone(), true, before[1].image_ref.clone())),
            ],
            desired_graph: None,
            create_missing: None,
            prepared_create: None,
            compose_sha256: None,
            edge_network_id: None,
        };
        let mut stopped = before;
        stopped[0].running = false;
        assert!(verify_native_vm_run_poststate(&host, &stop, &stopped).is_ok());
    }

    #[test]
    fn scoped_template_update_rejects_shared_file_change_and_missing_manifest() {
        use edge_shared_types::BundleFile;
        let root = std::env::temp_dir().join(format!(
            "sing-box-scoped-manifest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("line2-proxy")).unwrap();
        fs::write(root.join("docker-compose.yml"), b"services: {}\n").unwrap();
        fs::write(root.join(".images.env"), b"pinned-image\n").unwrap();
        fs::write(root.join(".env.runtime.policy"), b"policy\n").unwrap();
        fs::write(
            root.join("line2-proxy/config.template.json"),
            b"old-template\n",
        )
        .unwrap();
        let files = [
            ("docker-compose.yml", b"services: {}\n".as_slice()),
            (".images.env", b"pinned-image\n".as_slice()),
            (".env.runtime.policy", b"policy\n".as_slice()),
            (
                "line2-proxy/config.template.json",
                b"new-template\n".as_slice(),
            ),
        ];
        let mut request = ApplyBundleRequest {
            stack_files: files
                .iter()
                .map(|(path, content)| BundleFile {
                    relative_path: (*path).into(),
                    content: content.to_vec(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        assert!(select_scoped_template_policy(&root, &request).is_ok());
        assert!(verify_exact_installed_vm_bundle_static(&root, &request).is_err());
        let mut exact = request.clone();
        exact.stack_files[3].content = b"old-template\n".to_vec();
        assert!(verify_exact_installed_vm_bundle_static(&root, &exact).is_ok());
        fs::write(root.join("line2-proxy/config.template.json"), b"edited\n").unwrap();
        assert!(verify_exact_installed_vm_bundle_static(&root, &exact).is_err());
        fs::write(
            root.join("line2-proxy/config.template.json"),
            b"old-template\n",
        )
        .unwrap();
        fs::write(root.join("extra-owned-file"), b"unexpected\n").unwrap();
        assert!(verify_exact_installed_vm_bundle_static(&root, &exact).is_err());
        fs::remove_file(root.join("extra-owned-file")).unwrap();
        request.stack_files.pop();
        assert!(select_scoped_template_policy(&root, &request).is_err());
        request.stack_files.push(BundleFile {
            relative_path: "line2-proxy/config.template.json".into(),
            content: b"new-template\n".to_vec(),
            ..Default::default()
        });
        request.stack_files[1].content = b"changed-image\n".to_vec();
        assert!(select_scoped_template_policy(&root, &request).is_err());
        request.stack_files[1].content = b"pinned-image\n".to_vec();
        request.stack_files[3].relative_path = "line1-gateway/config.template.json".into();
        assert!(select_scoped_template_policy(&root, &request).is_err());

        // Same native planner and journal for Line1, without any second
        // handler or permission to update a shared/WARP policy.
        request.stack_files[3].relative_path = "line2-proxy/config.template.json".into();
        request.stack_files[3].content = b"old-template\n".to_vec();
        fs::create_dir_all(root.join("line1-gateway")).unwrap();
        fs::write(
            root.join("line1-gateway/config.template.json"),
            b"old-line1\n",
        )
        .unwrap();
        request.stack_files.push(BundleFile {
            relative_path: "line1-gateway/config.template.json".into(),
            content: b"new-line1\n".to_vec(),
            ..Default::default()
        });
        let (target, old, new, unchanged) = select_scoped_template_policy(&root, &request).unwrap();
        assert_eq!(target, ScopedVmService::Line1);
        assert_eq!(old, b"old-line1\n");
        assert_eq!(new, b"new-line1\n");
        assert_eq!(unchanged.len(), 4);

        request.stack_files[3].content = b"new-template\n".to_vec();
        assert!(select_scoped_template_policy(&root, &request).is_err());
        request.stack_files[3].content = b"old-template\n".to_vec();
        request.stack_files[4].relative_path = "warp-egress/config.template.json".into();
        assert!(select_scoped_template_policy(&root, &request).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_dns_parser_is_bounded_and_never_assumes_resolution() {
        assert_eq!(
            parse_native_dns_configuration(
                b"# managed by systemd\nnameserver 127.0.0.53\nsearch example.org\nnameserver 1.1.1.1\n"
            )
            .unwrap(),
            vec!["127.0.0.53", "1.1.1.1"]
        );
        assert!(parse_native_dns_configuration(b"search example.org\n").is_err());
        assert!(parse_native_dns_configuration(b"nameserver example.org\n").is_err());
        assert!(
            parse_native_dns_configuration(b"nameserver 1.1.1.1\nnameserver 1.1.1.1\n").is_err()
        );
    }

    #[test]
    fn scoped_names_come_only_from_the_git_owned_fleet_registry() {
        let mut host = FleetHost {
            vm_containers: vec![FleetVmContainer {
                container_name: "other-vm-line1".into(),
                compose_project: "separate-project".into(),
                compose_service: "line1-gateway".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            ScopedVmService::Line1.container_name(&host).unwrap(),
            "other-vm-line1"
        );
        assert!(ScopedVmService::Line2.container_name(&host).is_err());
        host.vm_containers.clear();
        assert!(ScopedVmService::Line1.container_name(&host).is_err());
    }

    #[test]
    fn gateway_image_coupling_rejects_missing_owners_and_foreign_consumers() {
        use edge_shared_types::{FleetVmDesiredGraph, FleetVmDesiredResource};
        let pinned = format!(
            "ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}",
            "a".repeat(64)
        );
        let resource = |service: &str, image: &str| FleetVmDesiredResource {
            resource: Some(FleetVmContainer {
                container_name: format!("test-{service}"),
                compose_project: "test".into(),
                compose_service: service.into(),
            }),
            image_ref: image.into(),
            ..Default::default()
        };
        let mut graph = FleetVmDesiredGraph {
            resources: vec![
                resource("line1-gateway", &pinned),
                resource("line2-proxy", &pinned),
                resource("warp-egress", "warp-image"),
            ],
            ..Default::default()
        };
        assert!(validate_gateway_image_ownership(&graph, &pinned).is_ok());
        graph.resources[1].image_ref = "independent-image".into();
        assert!(validate_gateway_image_ownership(&graph, &pinned).is_err());
        graph.resources[1].image_ref.clone_from(&pinned);
        graph.resources[2].image_ref.clone_from(&pinned);
        assert!(validate_gateway_image_ownership(&graph, &pinned).is_err());
        graph.resources.pop();
        graph.resources.pop();
        assert!(validate_gateway_image_ownership(&graph, &pinned).is_err());
    }

    #[test]
    fn gateway_image_replacement_is_paired_and_rejects_other_image_changes() {
        let old = b"EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nEDGE_WARP_EGRESS_IMAGE=warp-old\nCLOUDFLARE_MESH_IMAGE=mesh-old\n";
        let existing = format!(
            "ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}",
            "a".repeat(64)
        );
        let new = format!(
            "ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}",
            "b".repeat(64)
        );
        let next = std::str::from_utf8(old).unwrap().replace(&existing, &new);
        assert_eq!(
            gateway_image_policy_delta(old, next.as_bytes(), &existing).unwrap(),
            new
        );
        assert!(gateway_image_policy_delta(old, old, &existing).is_err());
        let warp = next.replace("warp-old", "warp-new");
        assert!(gateway_image_policy_delta(old, warp.as_bytes(), &existing).is_err());
        let unpinned = next.replace(&new, "ghcr.io/iamaman11/vultr-edge-gateway:latest");
        assert!(gateway_image_policy_delta(old, unpinned.as_bytes(), &existing).is_err());
        let wrong = next.replace(
            &new,
            &format!("ghcr.io/other/repo@sha256:{}", "b".repeat(64)),
        );
        assert!(gateway_image_policy_delta(old, wrong.as_bytes(), &existing).is_err());
        let duplicated = next.replace("EDGE_WARP_EGRESS_IMAGE=", "EDGE_GATEWAY_IMAGE=");
        assert!(gateway_image_policy_delta(old, duplicated.as_bytes(), &existing).is_err());
    }

    #[test]
    fn paired_gateway_and_warp_images_use_one_exact_release_policy() {
        let old = format!(
            "EDGE_GATEWAY_IMAGE=ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}\nEDGE_WARP_EGRESS_IMAGE=ghcr.io/iamaman11/vultr-warp-egress@sha256:{}\nCLOUDFLARE_MESH_IMAGE=docker.io/cloudflare/mesh@sha256:{}\n",
            "a".repeat(64), "b".repeat(64), "c".repeat(64)
        );
        let next_gateway = format!("ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}", "d".repeat(64));
        let next_warp = format!("ghcr.io/iamaman11/vultr-warp-egress@sha256:{}", "e".repeat(64));
        let gateway_only = old.replace(&format!("ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}", "a".repeat(64)), &next_gateway);
        assert_eq!(
            application_image_policy_delta(old.as_bytes(), gateway_only.as_bytes()).unwrap(),
            (next_gateway.clone(), None)
        );
        let both = gateway_only.replace(
            &format!("ghcr.io/iamaman11/vultr-warp-egress@sha256:{}", "b".repeat(64)),
            &next_warp
        );
        assert_eq!(
            application_image_policy_delta(old.as_bytes(), both.as_bytes()).unwrap(),
            (next_gateway, Some(next_warp))
        );
        assert!(application_image_policy_delta(old.as_bytes(), old.as_bytes()).is_err());
        let changed_mesh = both.replace(&"c".repeat(64), &"f".repeat(64));
        assert!(application_image_policy_delta(old.as_bytes(), changed_mesh.as_bytes()).is_err());
        let unpinned_warp = both.replace("@sha256:eeee", ":latest-eeee");
        assert!(application_image_policy_delta(old.as_bytes(), unpinned_warp.as_bytes()).is_err());
    }

    #[test]
    fn scoped_resource_selector_is_closed_to_only_native_line_services() {
        assert_eq!(
            ScopedVmService::from_template("line1-gateway/config.template.json").unwrap(),
            ScopedVmService::Line1
        );
        assert_eq!(
            ScopedVmService::from_template("line2-proxy/config.template.json").unwrap(),
            ScopedVmService::Line2
        );
        for path in [
            "warp-egress/config.template.json",
            "cloudflare-mesh/config.template.json",
            "line2-proxy/../warp-egress/config.template.json",
            "docker-compose.yml",
        ] {
            assert!(ScopedVmService::from_template(path).is_err());
        }
    }

    #[test]
    fn stop_can_complete_after_owned_upstream_disappears() {
        let only_proxy = vec![item("line2-proxy", &["warp-egress"])];
        assert!(owned_vm_start_order(&only_proxy).is_err());
        assert_eq!(owned_vm_stop_order(&only_proxy).unwrap(), vec![0]);
        let all = vec![
            item("line1-gateway", &["warp-egress"]),
            item("line2-proxy", &["warp-egress"]),
            item("warp-egress", &[]),
        ];
        assert_eq!(owned_vm_stop_order(&all).unwrap(), vec![1, 0, 2]);
    }

    #[test]
    fn startup_order_respects_docker_dependencies_without_touching_mesh() {
        let resources = vec![
            item("line1-gateway", &["warp-egress"]),
            item("line2-proxy", &["warp-egress"]),
            item("warp-egress", &[]),
        ];
        assert_eq!(owned_vm_start_order(&resources).unwrap(), vec![2, 0, 1]);
        let missing = vec![item("line2-proxy", &["foreign-mesh"])];
        assert!(owned_vm_start_order(&missing).is_err());
        let cycle = vec![
            item("line1-gateway", &["line2-proxy"]),
            item("line2-proxy", &["line1-gateway"]),
        ];
        assert!(owned_vm_start_order(&cycle).is_err());
    }
}

#[cfg(test)]
#[path = "docker_observation_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "docker_observation_native_vm_install_policy_tests.rs"]
mod native_vm_install_policy_tests;

#[cfg(test)]
#[path = "docker_observation_native_vm_gateway_policy_tests.rs"]
mod native_vm_gateway_policy_tests;
