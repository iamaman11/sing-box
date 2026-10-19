use edge_shared_types::{ApplyBundleRequest, FleetHost, FleetHostPlannedStep, FleetVmContainer};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
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
use futures_util::TryStreamExt;
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

/// Resolve the common typed resource planner against root-local Docker
/// evidence BEFORE the journal BEGIN. Only START/STOP may cross this boundary,
/// and only when every registered resource is a safe NOOP or that exact step.
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
    let mut changed = 0;
    for resource in &plan.resources {
        let candidate = FleetHostPlannedStep::try_from(resource.step)
            .map_err(|_| "HOST_NATIVE_VM_RESOURCE_STEP_INVALID")?;
        match candidate {
            FleetHostPlannedStep::Noop => {}
            value if value == step => changed += 1,
            _ => return Err("HOST_NATIVE_VM_RESOURCE_PLAN_BLOCKED".into()),
        }
    }
    if changed == 0 {
        return Err("HOST_NATIVE_VM_RESOURCE_NO_MUTATION_REQUIRED".into());
    }
    let identities = readback
        .resources
        .iter()
        .map(|item| {
            item.present
                .then(|| (item.container_id.clone(), item.running, item.image.clone()))
        })
        .collect::<Vec<_>>();
    let docker = docker_connection().await?;
    let mut owned = if step == FleetHostPlannedStep::Start {
        prepare_owned_vm_start(&docker, stack_dir, &host.vm_containers)
            .await?
            .0
    } else {
        owned_application_container_ids(&docker, &host.vm_containers).await?
    };
    bind_owned_vm_compose_dependencies(stack_dir, &host.vm_containers, &mut owned)?;
    check_owned_vm_snapshot(host, &owned, &identities)?;
    if step == FleetHostPlannedStep::Stop {
        owned_vm_stop_order(&owned)?;
    } else {
        owned_vm_start_order(&owned)?;
    }
    Ok(NativeVmRunPlan { step, identities })
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

    fn container_name(self) -> &'static str {
        match self {
            Self::Line1 => "vultr-line1-gateway",
            Self::Line2 => "vultr-line2-proxy",
        }
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

    fn recreate(self, stack_dir: &Path, images: &BTreeMap<String, String>) -> Result<(), String> {
        match self {
            Self::Line1 => super::start_line1_gateway(stack_dir, images),
            Self::Line2 => super::start_line2_proxy(stack_dir, images),
        }
    }

    fn render(self, stack_dir: &Path, runtime: &BTreeMap<String, String>) -> Result<(), String> {
        match self {
            Self::Line1 => super::render_line1_runtime(stack_dir, runtime),
            Self::Line2 => super::render_line2_runtime(stack_dir, runtime),
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
    release: edge_shared_types::ApplicationBundleReleaseState,
    expected_rendered_sha256: Vec<u8>,
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
    if !host.vm_containers.iter().any(|item| {
        item.compose_service == target.compose_service()
            && item.container_name == target.container_name()
    }) {
        return Err("HOST_NATIVE_VM_SCOPED_RESOURCE_NOT_REGISTERED".into());
    }
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
        target.container_name(),
        &stack_dir.join(target.rendered_relative()),
    )
    .await?;
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
        release: edge_shared_types::ApplicationBundleReleaseState {
            schema_version: 1,
            bundle_id,
            bundle_digest: digest,
        },
        expected_rendered_sha256: ring::digest::digest(&ring::digest::SHA256, &rendered)
            .as_ref()
            .to_vec(),
    })
}

/// One mutation authority and one existing journal. Compose is the native
/// declarative Docker driver for scoped --no-deps Line1/Line2 replacement.
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
    // Compose ACK or poststate is UNKNOWN; never restore/retry implicitly.
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
    let images = super::read_exact_image_environment(stack_dir)?;
    plan.target
        .recreate(stack_dir, &images)
        .map_err(|_| "HOST_NATIVE_VM_SCOPED_DOCKER_UNCERTAIN_NO_REPLAY")?;
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
        plan.target.container_name(),
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

/// Running is not equivalent to readiness. A missing healthcheck is not
/// an implicit PASS. This only describes local Docker health, not egress.
fn native_running_health_reason(
    running: bool,
    health_debug: Option<&str>,
) -> (&'static str, &'static str) {
    if !running {
        return ("STOPPED", "");
    }
    match health_debug.map(str::to_ascii_lowercase) {
        Some(ref state) if state == "healthy" => ("HEALTHY", "HEALTHY"),
        Some(ref state) if state == "unhealthy" => ("HEALTH_UNHEALTHY", "UNHEALTHY"),
        Some(ref state) if state == "starting" => ("HEALTH_STARTING", "STARTING"),
        None => ("RUNNING_NO_HEALTHCHECK", ""),
        _ => ("HEALTH_UNPROVEN", ""),
    }
}

/// Bounded direct DNS configuration observation. /etc/resolv.conf may be a
/// systemd-resolved symlink: it is a source of configuration, never proof that
/// an upstream nameserver responds.
fn observe_native_dns_configuration() -> Result<Vec<String>, String> {
    let path = Path::new("/etc/resolv.conf");
    let metadata = fs::metadata(path).map_err(|_| "HOST_VM_DNS_CONFIG_UNAVAILABLE")?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("HOST_VM_DNS_CONFIG_UNTRUSTED".into());
    }
    let bytes = fs::read(path).map_err(|_| "HOST_VM_DNS_CONFIG_UNREADABLE")?;
    if bytes.len() > 4096 {
        return Err("HOST_VM_DNS_CONFIG_TOO_LARGE".into());
    }
    parse_native_dns_configuration(&bytes)
}

fn parse_native_dns_configuration(bytes: &[u8]) -> Result<Vec<String>, String> {
    let raw = std::str::from_utf8(bytes).map_err(|_| "HOST_VM_DNS_CONFIG_NOT_UTF8")?;
    let mut nameservers = Vec::new();
    let mut seen = BTreeSet::new();
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let addr = fields.next().ok_or("HOST_VM_DNS_NAMESERVER_INVALID")?;
        let parsed = addr
            .parse::<IpAddr>()
            .map_err(|_| "HOST_VM_DNS_NAMESERVER_INVALID")?;
        let canonical = parsed.to_string();
        if !seen.insert(canonical.clone()) || fields.next().is_some() {
            return Err("HOST_VM_DNS_NAMESERVER_DUPLICATE_OR_INVALID".into());
        }
        nameservers.push(canonical);
        if nameservers.len() > 8 {
            return Err("HOST_VM_DNS_TOO_MANY_NAMESERVERS".into());
        }
    }
    if nameservers.is_empty() {
        return Err("HOST_VM_DNS_NO_NAMESERVERS".into());
    }
    Ok(nameservers)
}

/// Native netfilter ruleset inspection via the installed nft CLI, with no
/// shell, dynamic arguments, mutation or polling. The digest is a fingerprint
/// of observed bytes, NOT evidence that firewall desired rules are correct.
async fn observe_native_nft_ruleset() -> Option<(Vec<u8>, u32)> {
    // The installed Linux coreutils timeout bounds the fixed nft command
    // without a Tokio process feature, background agent or polling loop.
    // The root owner provides every argument; no runner-supplied path or shell.
    let output = tokio::task::spawn_blocking(|| {
        std::process::Command::new("/usr/bin/timeout")
            .args(["-s", "KILL", "6s", "/usr/sbin/nft", "-j", "list", "ruleset"])
            .env_clear()
            .output()
    })
    .await
    .ok()?
    .ok()?;
    if !output.status.success() || output.stdout.len() > 262144 {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let rows = parsed.get("nftables")?.as_array()?;
    let count = rows
        .iter()
        .filter(|entry| entry.get("rule").is_some())
        .count();
    let count = u32::try_from(count).ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &output.stdout)
        .as_ref()
        .to_vec();
    Some((digest, count))
}

/// Same installed root Agent, same typed readback: netlink, DNS configuration,
/// and nft ruleset are separate observations. Unknown stays UNKNOWN.
async fn observe_native_vm_network_readback() -> edge_shared_types::FleetVmNetworkReadback {
    let ipv4 = super::network_observation::observe_ipv4_network()
        .await
        .ok()
        .filter(|value| value.encode_to_vec().len() <= 24_576);
    let dns = observe_native_dns_configuration().ok();
    let nft = observe_native_nft_ruleset().await;
    edge_shared_types::FleetVmNetworkReadback {
        ipv4,
        dns_nameservers: dns.clone().unwrap_or_default(),
        dns_configuration_observed: dns.is_some(),
        nft_ruleset_sha256: nft
            .as_ref()
            .map(|(hash, _)| hash.clone())
            .unwrap_or_default(),
        nft_rule_count: nft.as_ref().map(|(_, count)| *count).unwrap_or_default(),
        nft_ruleset_observed: nft.is_some(),
    }
}

/// Read-only, per-resource Docker evidence. Each entry is inspected once:
/// labels, immutable ID and state come from the SAME inspect response.
/// Never read or emit environment, credentials, mount contents or Docker logs.
pub(crate) async fn observe_vm_resource_report(
    host: &edge_shared_types::FleetHost,
    stack_dir: &Path,
) -> Result<edge_shared_types::FleetVmResourceReport, String> {
    use edge_shared_types::{FleetVmConfigProof, FleetVmResourceReadback, FleetVmResourceReport};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "HOST_VM_RESOURCES_CLOCK_UNAVAILABLE")?
        .as_secs();
    let docker = docker_connection().await.ok();
    let mut resources = Vec::with_capacity(host.vm_containers.len());
    for resource in &host.vm_containers {
        let mut row = FleetVmResourceReadback {
            resource: Some(resource.clone()),
            reason_code: "DOCKER_UNAVAILABLE".to_owned(),
            config_proof: if resource.compose_service == "warp-egress" {
                FleetVmConfigProof::NotApplicable as i32
            } else {
                FleetVmConfigProof::NotRunning as i32
            },
            ..Default::default()
        };
        if let Some(docker) = &docker {
            match docker
                .inspect_container(&resource.container_name, None)
                .await
            {
                Err(BollardError::DockerResponseServerError {
                    status_code: 404, ..
                }) => {
                    row.reason_code = "CONTAINER_ABSENT".to_owned();
                }
                Err(_) => row.reason_code = "INSPECT_UNAVAILABLE".to_owned(),
                Ok(inspect) => {
                    row.present = true;
                    row.reason_code = "FOREIGN_OWNER".to_owned();
                    let valid_labels = inspect
                        .config
                        .as_ref()
                        .and_then(|cfg| cfg.labels.as_ref())
                        .is_some_and(|labels| {
                            exact_application_compose_owner(
                                &resource.container_name,
                                labels,
                                &host.vm_containers,
                            )
                            .is_ok()
                        });
                    let id = inspect.id.as_deref().unwrap_or("");
                    let valid_id = id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit());
                    if inspect.name.as_deref()
                        == Some(format!("/{}", resource.container_name).as_str())
                        && valid_labels
                        && valid_id
                    {
                        row.ownership_proven = true;
                        row.container_id = id.to_owned();
                        if let Some(config) = &inspect.config {
                            row.image = config
                                .image
                                .as_deref()
                                .filter(|image| image.len() <= 256)
                                .unwrap_or("")
                                .to_owned();
                        }
                        if let Some(restarts) =
                            inspect.restart_count.and_then(|v| u64::try_from(v).ok())
                        {
                            row.restart_count = restarts;
                            row.restart_count_proven = true;
                        }
                        row.reason_code = "STATE_UNPROVEN".to_owned();
                        if let Some(state) = &inspect.state {
                            if let Ok(running) = require_known_native_container_state(state) {
                                row.running_proven = true;
                                row.running = running;
                                let raw_health = state
                                    .health
                                    .as_ref()
                                    .and_then(|health| health.status.as_ref())
                                    .map(|status| format!("{status:?}"));
                                let (reason, health) =
                                    native_running_health_reason(running, raw_health.as_deref());
                                row.reason_code = reason.to_owned();
                                row.health = health.to_owned();
                            }
                        }
                    }
                }
            }
        }
        if row.ownership_proven
            && row.running_proven
            && row.running
            && matches!(
                resource.compose_service.as_str(),
                "line1-gateway" | "line2-proxy"
            )
        {
            let name = resource.compose_service.as_str();
            let config = stack_dir.join(format!("rendered/{name}.json"));
            row.config_proof = FleetVmConfigProof::Unproven as i32;
            // Bounded, root-local file read. Any race or missing bind remains
            // UNPROVEN; no secret-bearing config bytes leave the owner.
            if let Ok(metadata) = fs::symlink_metadata(&config)
                && metadata.file_type().is_file()
                && metadata.len() > 0
                && metadata.len() <= 4 * 1024 * 1024
                && let Ok(before) = fs::read(&config)
                && verify_running_container_config_binding(&resource.container_name, &config)
                    .await
                    .is_ok()
                && fs::read(&config).is_ok_and(|after| after == before)
            {
                row.config_proof = FleetVmConfigProof::BoundRunningProcess as i32;
                row.config_sha256 = ring::digest::digest(&ring::digest::SHA256, &before)
                    .as_ref()
                    .to_vec();
            }
        }
        resources.push(row);
    }
    let report = FleetVmResourceReport {
        schema_version: 1,
        machine_id: host.machine_id.clone(),
        observed_at_unix: now,
        resources,
        remote_attested: false,
        network: Some(observe_native_vm_network_readback().await),
    };
    edge_shared_types::host_resources::validate_vm_resource_report(&report, host)
        .map_err(str::to_owned)?;
    Ok(report)
}

pub(crate) async fn observe_docker() -> Result<DockerObservation, String> {
    let docker = docker_connection().await?;

    let options = ListContainersOptionsBuilder::default().all(true).build();
    let containers = docker
        .list_containers(Some(options))
        .await
        .map_err(|err| format!("failed to list Docker containers: {err}"))?;

    Ok(normalize_containers(containers))
}

pub(crate) async fn observe_container_runtime(
    container_name: &str,
) -> Result<ContainerRuntimeEvidence, String> {
    let docker = docker_connection().await?;
    let inspect = match docker.inspect_container(container_name, None).await {
        Ok(inspect) => inspect,
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            return Ok(ContainerRuntimeEvidence {
                present: false,
                running: false,
                exit_code: None,
                runtime_error: None,
                log_tail: Vec::new(),
                name: container_name.to_owned(),
                image: None,
                restart_count: None,
                oom_killed: None,
                health: None,
                networks: Vec::new(),
                published_ports: Vec::new(),
                mounts: Vec::new(),
            });
        }
        Err(err) => {
            return Err(format!(
                "failed to inspect Docker container {container_name}: {err}"
            ));
        }
    };

    let state = inspect.state.unwrap_or_default();
    let image = inspect
        .config
        .and_then(|config| config.image)
        .or(inspect.image);
    let restart_count = inspect
        .restart_count
        .and_then(|value| u64::try_from(value).ok());
    let oom_killed = state.oom_killed;
    let health = state
        .health
        .as_ref()
        .and_then(|health| health.status.as_ref())
        .map(|status| format!("{status:?}"));

    let network_settings = inspect.network_settings.unwrap_or_default();
    let mut networks = network_settings
        .networks
        .unwrap_or_default()
        .into_keys()
        .collect::<Vec<_>>();
    networks.sort();
    networks.dedup();

    let mut published_ports = network_settings
        .ports
        .unwrap_or_default()
        .into_iter()
        .flat_map(|(container_port, bindings)| {
            bindings
                .unwrap_or_default()
                .into_iter()
                .map(move |binding| match binding.host_port {
                    Some(host_port) => format!("{container_port}->{host_port}"),
                    None => container_port.clone(),
                })
        })
        .collect::<Vec<_>>();
    published_ports.sort();
    published_ports.dedup();

    let mut mounts = inspect
        .mounts
        .unwrap_or_default()
        .into_iter()
        .map(|mount| {
            let kind = mount.typ.unwrap_or_else(|| "UNKNOWN".to_owned());
            let destination = mount.destination.unwrap_or_else(|| "<unknown>".to_owned());
            let rw = mount
                .rw
                .map(|value| value.to_string())
                .unwrap_or_else(|| "UNKNOWN".to_owned());
            format!("{kind}:{destination}:rw={rw}")
        })
        .collect::<Vec<_>>();
    mounts.sort();
    mounts.dedup();

    let options = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .timestamps(false)
        .tail("40")
        .build();
    let log_tail = match docker
        .logs(container_name, Some(options))
        .try_collect::<Vec<_>>()
        .await
    {
        Ok(outputs) => {
            bounded_redacted_log_tail(outputs.into_iter().map(|output| output.to_string()))
        }
        Err(err) => vec![format!("[docker log observation unavailable: {err}]")],
    };

    Ok(ContainerRuntimeEvidence {
        present: true,
        running: state.running.unwrap_or(false),
        exit_code: state.exit_code,
        runtime_error: state.error.filter(|value| !value.is_empty()),
        log_tail,
        name: container_name.to_owned(),
        image,
        restart_count,
        oom_killed,
        health,
        networks,
        published_ports,
        mounts,
    })
}

// Bollard 0.21.1 models Docker inspect MountPoint.Type as Option<String>,
// not MountPointTypeEnum. Debug-formatting it adds quotes (\x22bind\x22) and
// therefore falsely rejects a genuine read-only bind. Check the exact wire
// representation directly, and keep missing/writable evidence fail-closed.
fn require_exact_readonly_config_bind(
    container: &str,
    kind: Option<&str>,
    writable: Option<bool>,
) -> Result<(), String> {
    match kind {
        Some("bind") => {}
        Some(_) => {
            return Err(format!(
                "runtime config proof {container} config mount type=NON_BIND"
            ));
        }
        None => {
            return Err(format!(
                "runtime config proof {container} config mount type=UNAVAILABLE"
            ));
        }
    }
    match writable {
        Some(false) => Ok(()),
        Some(true) => Err(format!(
            "runtime config proof {container} config mount writable=TRUE"
        )),
        None => Err(format!(
            "runtime config proof {container} config mount writable=UNAVAILABLE"
        )),
    }
}

/// Read-only proof of the *file visible to the running process*. This does
/// not claim that sing-box reloaded that file into its in-memory configuration.
/// Authentication is an independent network-level proof.
pub(crate) async fn verify_running_container_config_binding(
    name: &str,
    expected_host_file: &Path,
) -> Result<(), String> {
    const CONTAINER_CONFIG: &str = "/etc/sing-box/config.json";
    const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
    if !matches!(name, "vultr-line1-gateway" | "vultr-line2-proxy") {
        return Err("runtime credential proof refuses an unknown container".to_owned());
    }
    let docker = docker_connection().await?;
    let before = docker
        .inspect_container(name, None)
        .await
        .map_err(|_| "runtime config proof cannot inspect the named container".to_owned())?;
    let state = before
        .state
        .as_ref()
        .ok_or("runtime config proof requires observed container state")?;
    if state.running != Some(true) {
        return Err("runtime config proof refuses a non-running container".to_owned());
    }
    let pid = state
        .pid
        .filter(|pid| *pid > 1)
        .ok_or("runtime config proof requires exact running Linux process PID")?;
    let started_at = state
        .started_at
        .clone()
        .ok_or("runtime config proof requires Docker process start identity")?;

    let config_mounts = before
        .mounts
        .as_ref()
        .ok_or("runtime config proof requires Docker bind mount evidence")?
        .iter()
        .filter(|mount| mount.destination.as_deref() == Some(CONTAINER_CONFIG))
        .collect::<Vec<_>>();
    if config_mounts.len() != 1 {
        return Err("runtime config proof requires exactly one config bind mount".to_owned());
    }
    let mount = config_mounts[0];
    require_exact_readonly_config_bind(name, mount.typ.as_deref(), mount.rw)?;
    let expected = fs::canonicalize(expected_host_file)
        .map_err(|_| "runtime config proof cannot resolve expected host file".to_owned())?;
    let bound = mount
        .source
        .as_deref()
        .ok_or("runtime config proof has no Docker source path")?;
    if fs::canonicalize(bound).ok().as_deref() != Some(expected.as_path()) {
        return Err("runtime config proof refuses a different bind source".to_owned());
    }
    let metadata = fs::metadata(&expected)
        .map_err(|_| "runtime config proof cannot stat expected file".to_owned())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err("runtime config proof refuses a missing or oversized config".to_owned());
    }
    let visible = PathBuf::from(format!("/proc/{pid}/root{CONTAINER_CONFIG}"));
    let in_container = fs::read(&visible)
        .map_err(|_| "runtime config proof cannot read running process mount view".to_owned())?;
    if in_container.len() as u64 != metadata.len()
        || in_container
            != fs::read(&expected)
                .map_err(|_| "runtime config proof cannot re-read expected host file".to_owned())?
    {
        return Err(
            "running process sees different config bytes than the exact host bind".to_owned(),
        );
    }
    let after = docker
        .inspect_container(name, None)
        .await
        .map_err(|_| "runtime config proof cannot re-inspect the named container".to_owned())?;
    let stable = after.state.as_ref().is_some_and(|state| {
        state.running == Some(true)
            && state.pid == Some(pid)
            && state.started_at.as_ref() == Some(&started_at)
    });
    if !stable {
        return Err("running container restarted during config-source attestation".to_owned());
    }
    Ok(())
}

fn bounded_redacted_log_tail<I>(lines: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut normalized = lines
        .into_iter()
        .flat_map(|chunk| {
            chunk
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(redact_runtime_log_line)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if normalized.len() > 40 {
        normalized.drain(..normalized.len() - 40);
    }
    normalized
}

fn redact_runtime_log_line(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    if [
        "password",
        "private_key",
        "private key",
        "authorization",
        "credential",
        "mesh_node_token",
        "bearer ",
        "token=",
        "uuid=",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return "[redacted sensitive runtime log line]".to_owned();
    }
    line.chars().take(320).collect()
}

fn normalize_containers(summaries: Vec<ContainerSummary>) -> DockerObservation {
    let mut containers = Vec::new();
    let mut running_containers = BTreeSet::new();
    let mut listening_tcp_ports = BTreeSet::new();
    let mut listening_udp_ports = BTreeSet::new();

    for summary in summaries {
        let running = matches!(summary.state, Some(ContainerSummaryStateEnum::RUNNING));
        let mut names = summary
            .names
            .unwrap_or_default()
            .into_iter()
            .map(|name| name.trim_start_matches('/').to_owned())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();

        if running {
            running_containers.extend(names.iter().cloned());
            for port in summary.ports.unwrap_or_default() {
                let Some(public_port) = port.public_port else {
                    continue;
                };
                match port.typ {
                    Some(PortSummaryTypeEnum::TCP) => {
                        listening_tcp_ports.insert(u32::from(public_port));
                    }
                    Some(PortSummaryTypeEnum::UDP) => {
                        listening_udp_ports.insert(u32::from(public_port));
                    }
                    _ => {}
                }
            }
        }

        let image = summary.image;
        let mut networks = summary
            .network_settings
            .and_then(|settings| settings.networks)
            .map(|networks| networks.into_keys().collect::<Vec<_>>())
            .unwrap_or_default();
        networks.sort();
        networks.dedup();

        for name in names {
            containers.push(DockerContainerObservation {
                name,
                running,
                image: image.clone(),
                networks: networks.clone(),
            });
        }
    }

    containers.sort_by(|left, right| left.name.cmp(&right.name));
    DockerObservation {
        reachable: true,
        running_containers: running_containers.into_iter().collect(),
        listening_tcp_ports: listening_tcp_ports.into_iter().collect(),
        listening_udp_ports: listening_udp_ports.into_iter().collect(),
        containers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm_scope_test() -> Vec<FleetVmContainer> {
        [
            ("vultr-line1-gateway", "line1-gateway"),
            ("vultr-line2-proxy", "line2-proxy"),
            ("vultr-warp-egress", "warp-egress"),
        ]
        .into_iter()
        .map(|(container_name, compose_service)| FleetVmContainer {
            container_name: container_name.to_owned(),
            compose_project: "vultr-edge".to_owned(),
            compose_service: compose_service.to_owned(),
        })
        .collect()
    }

    #[test]
    fn missing_or_starting_health_is_never_reported_healthy() {
        assert_eq!(
            native_running_health_reason(true, Some("Healthy")),
            ("HEALTHY", "HEALTHY")
        );
        assert_eq!(
            native_running_health_reason(true, Some("Starting")),
            ("HEALTH_STARTING", "STARTING")
        );
        assert_eq!(
            native_running_health_reason(true, Some("Unhealthy")),
            ("HEALTH_UNHEALTHY", "UNHEALTHY")
        );
        assert_eq!(
            native_running_health_reason(true, None),
            ("RUNNING_NO_HEALTHCHECK", "")
        );
        assert_eq!(
            native_running_health_reason(true, Some("Unknown")),
            ("HEALTH_UNPROVEN", "")
        );
        assert_eq!(native_running_health_reason(false, None), ("STOPPED", ""));
    }

    #[test]
    fn native_stop_requires_complete_state_and_never_adopts_mesh() {
        use bollard::models::ContainerState;
        let safe_running = ContainerState {
            running: Some(true),
            paused: Some(false),
            restarting: Some(false),
            dead: Some(false),
            ..Default::default()
        };
        assert_eq!(
            require_known_native_container_state(&safe_running),
            Ok(true)
        );
        let safe_stopped = ContainerState {
            running: Some(false),
            ..safe_running.clone()
        };
        assert_eq!(
            require_known_native_container_state(&safe_stopped),
            Ok(false)
        );
        let paused = ContainerState {
            paused: Some(true),
            ..safe_running.clone()
        };
        assert_eq!(
            require_known_native_container_state(&paused),
            Err("HOST_NATIVE_CONTAINER_TRANSITION_UNPROVEN")
        );
        let restarting = ContainerState {
            restarting: Some(true),
            ..safe_running.clone()
        };
        assert!(require_known_native_container_state(&restarting).is_err());
        let missing = ContainerState {
            running: None,
            ..safe_running
        };
        assert_eq!(
            require_known_native_container_state(&missing),
            Err("HOST_NATIVE_CONTAINER_RUNNING_UNPROVEN")
        );
        assert_eq!(
            exact_application_compose_owner("vultr-line2-proxy", &HashMap::new(), &[],),
            Err("HOST_NATIVE_CONTAINER_OUTSIDE_APPLICATION_SCOPE")
        );
        let valid_project = HashMap::from([
            (
                "com.docker.compose.project".to_owned(),
                "vultr-edge".to_owned(),
            ),
            (
                "com.docker.compose.service".to_owned(),
                "line2-proxy".to_owned(),
            ),
        ]);
        assert!(
            exact_application_compose_owner("vultr-line2-proxy", &valid_project, &vm_scope_test())
                .is_ok()
        );
        assert!(
            exact_application_compose_owner(
                "vultr-cloudflare-mesh",
                &valid_project,
                &vm_scope_test()
            )
            .is_err()
        );
    }

    #[test]
    fn native_owner_requires_exact_compose_service_identity() {
        let mut labels = HashMap::from([
            (
                "com.docker.compose.project".to_owned(),
                "vultr-edge".to_owned(),
            ),
            (
                "com.docker.compose.service".to_owned(),
                "line1-gateway".to_owned(),
            ),
        ]);
        assert_eq!(
            exact_application_compose_owner("vultr-line1-gateway", &labels, &vm_scope_test()),
            Ok(())
        );
        assert_eq!(
            exact_application_compose_owner("vultr-line2-proxy", &labels, &vm_scope_test()),
            Err("HOST_NATIVE_CONTAINER_OWNERSHIP_UNPROVEN")
        );
        assert_eq!(
            exact_application_compose_owner("vultr-cloudflare-mesh", &labels, &vm_scope_test()),
            Err("HOST_NATIVE_CONTAINER_OUTSIDE_APPLICATION_SCOPE")
        );
        labels.insert("com.docker.compose.project".into(), "foreign-stack".into());
        assert_eq!(
            exact_application_compose_owner("vultr-line1-gateway", &labels, &vm_scope_test()),
            Err("HOST_NATIVE_CONTAINER_OWNERSHIP_UNPROVEN")
        );
        labels.remove("com.docker.compose.project");
        assert!(
            exact_application_compose_owner("vultr-line1-gateway", &labels, &vm_scope_test())
                .is_err()
        );
        labels.insert("com.docker.compose.project".into(), "vultr-edge".into());
        labels.insert("com.docker.compose.service".into(), "warp-egress".into());
        assert_eq!(
            exact_application_compose_owner("vultr-warp-egress", &labels, &vm_scope_test()),
            Ok(())
        );
    }

    #[test]
    fn bollard_inspect_string_mount_type_is_exactly_bind_without_debug_quotes() {
        use bollard::models::MountPoint;

        let real_readonly_mount = MountPoint {
            typ: Some("bind".to_owned()),
            rw: Some(false),
            ..Default::default()
        };
        let positive = require_exact_readonly_config_bind(
            "vultr-line1-gateway",
            real_readonly_mount.typ.as_deref(),
            real_readonly_mount.rw,
        );
        assert_eq!(positive, Ok(()));
        // The previous Debug-based comparison quoted this String.
        assert_ne!(format!("{:?}", "bind"), "bind");

        for kind in [None, Some("volume"), Some("tmpfs"), Some("BIND"), Some("")] {
            let result =
                require_exact_readonly_config_bind("vultr-line1-gateway", kind, Some(false));
            assert!(result.is_err());
        }
        for writable in [Some(true), None] {
            let result =
                require_exact_readonly_config_bind("vultr-line2-proxy", Some("bind"), writable);
            assert!(result.is_err());
        }
        let positive =
            require_exact_readonly_config_bind("vultr-line2-proxy", Some("bind"), Some(false));
        assert_eq!(positive, Ok(()));
    }

    fn container_summary(
        name: &str,
        running: bool,
        image: &str,
        tcp_port: Option<u16>,
        udp_port: Option<u16>,
        networks: &[&str],
    ) -> ContainerSummary {
        let mut ports = Vec::new();
        if let Some(public_port) = tcp_port {
            ports.push(PortSummary {
                private_port: public_port,
                public_port: Some(public_port),
                typ: Some(PortSummaryTypeEnum::TCP),
                ..Default::default()
            });
        }
        if let Some(public_port) = udp_port {
            ports.push(PortSummary {
                private_port: public_port,
                public_port: Some(public_port),
                typ: Some(PortSummaryTypeEnum::UDP),
                ..Default::default()
            });
        }

        ContainerSummary {
            names: Some(vec![format!("/{name}")]),
            image: Some(image.to_owned()),
            state: Some(if running {
                ContainerSummaryStateEnum::RUNNING
            } else {
                ContainerSummaryStateEnum::EXITED
            }),
            ports: Some(ports),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(
                    networks
                        .iter()
                        .map(|network| ((*network).to_owned(), Default::default()))
                        .collect::<HashMap<_, _>>(),
                ),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn typed_container_models_normalize_running_names_ports_image_and_networks() {
        let observation = normalize_containers(vec![
            container_summary(
                "vultr-cloudflare-mesh",
                true,
                "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                None,
                None,
                &["z-net", "vultr-edge_mesh_net", "a-net"],
            ),
            container_summary(
                "vultr-line2-proxy",
                true,
                "example.invalid/line2@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                Some(3128),
                Some(8443),
                &["vultr-edge_edge_net"],
            ),
            container_summary(
                "stopped-container",
                false,
                "example.invalid/stopped@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                Some(9999),
                None,
                &["vultr-edge_edge_net"],
            ),
        ]);

        assert!(observation.reachable);
        assert_eq!(
            observation.running_containers,
            vec!["vultr-cloudflare-mesh", "vultr-line2-proxy"]
        );
        assert_eq!(observation.listening_tcp_ports, vec![3128]);
        assert_eq!(observation.listening_udp_ports, vec![8443]);
        assert!(observation.container_present("stopped-container"));
        assert!(!observation.container_running("stopped-container"));
        let mesh = observation
            .containers
            .iter()
            .find(|container| container.name == "vultr-cloudflare-mesh")
            .unwrap();
        assert_eq!(
            mesh.networks,
            vec![
                "a-net".to_owned(),
                "vultr-edge_mesh_net".to_owned(),
                "z-net".to_owned()
            ]
        );
        assert!(observation.container_on_mesh_network("vultr-cloudflare-mesh"));
        assert!(observation.container_exact_image_ready(
            "vultr-cloudflare-mesh",
            "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn runtime_log_tail_is_bounded_and_redacts_sensitive_lines() {
        let input = (0..45)
            .map(|index| {
                if index == 44 {
                    "password=should-not-escape".to_owned()
                } else {
                    format!("safe-line-{index}")
                }
            })
            .collect::<Vec<_>>();
        let tail = bounded_redacted_log_tail(input);

        assert_eq!(tail.len(), 40);
        assert_eq!(tail.first().map(String::as_str), Some("safe-line-5"));
        assert_eq!(
            tail.last().map(String::as_str),
            Some("[redacted sensitive runtime log line]")
        );
        assert_eq!(
            redact_runtime_log_line("MESH_NODE_TOKEN secret-value"),
            "[redacted sensitive runtime log line]"
        );
        assert_eq!(
            redact_runtime_log_line("Authorization: Bearer secret-value"),
            "[redacted sensitive runtime log line]"
        );
    }

    #[test]
    fn unrelated_network_does_not_satisfy_mesh_membership() {
        let observation = normalize_containers(vec![container_summary(
            "vultr-cloudflare-mesh",
            true,
            "docker.io/cloudflare/mesh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
            None,
            &["vultr-edge_edge_net"],
        )]);
        assert!(!observation.container_on_mesh_network("vultr-cloudflare-mesh"));
    }
}
