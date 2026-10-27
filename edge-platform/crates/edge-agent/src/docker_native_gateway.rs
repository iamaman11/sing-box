use super::*;

/// All policy/mount parsing happens before the signed durable BEGIN; no shell.
/// One parsed, bounded, immutable gateway policy shared by pre-BEGIN
/// admission and the post-BEGIN native Docker effector. Policy checking
/// cannot create directories, start processes or inspect arbitrary paths.
#[derive(Debug)]
pub(super) struct NativeGatewayPolicy {
    pub(super) ports: Vec<(String, String, String)>,
    pub(super) mounts: Vec<(String, String, String)>,
}

pub(super) fn compile_native_gateway_policy(
    host: &FleetHost,
    compose: &serde_yaml::Value,
    service: &str,
) -> Result<NativeGatewayPolicy, String> {
    if !matches!(service, "line1-gateway" | "line2-proxy") {
        return Err("HOST_VM_GATEWAY_SCOPE_UNSUPPORTED".into());
    }
    let identity = host
        .vm_containers
        .iter()
        .find(|item| item.compose_service == service)
        .ok_or("HOST_VM_GATEWAY_IDENTITY_NOT_REGISTERED")?;
    let row = compose
        .get("services")
        .and_then(|services| services.get(service))
        .ok_or("HOST_VM_GATEWAY_POLICY_MISSING")?;
    let mapping = row.as_mapping().ok_or("HOST_VM_GATEWAY_POLICY_INVALID")?;
    let expected_keys = if service == "line1-gateway" {
        BTreeSet::from([
            "image",
            "container_name",
            "restart",
            "depends_on",
            "command",
            "ports",
            "volumes",
            "networks",
            "profiles",
        ])
    } else {
        BTreeSet::from([
            "image",
            "container_name",
            "restart",
            "depends_on",
            "command",
            "ports",
            "volumes",
            "networks",
        ])
    };
    if mapping
        .keys()
        .map(|key| key.as_str().unwrap_or(""))
        .collect::<BTreeSet<_>>()
        != expected_keys
    {
        return Err("HOST_VM_GATEWAY_FIELDS_UNSUPPORTED".into());
    }
    let sequence = |name: &str| -> Result<Vec<String>, String> {
        row.get(name)
            .and_then(serde_yaml::Value::as_sequence)
            .ok_or("HOST_VM_GATEWAY_SEQUENCE_MISSING")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "HOST_VM_GATEWAY_SEQUENCE_INVALID".to_owned())
            })
            .collect()
    };
    if row
        .get("container_name")
        .and_then(serde_yaml::Value::as_str)
        != Some(identity.container_name.as_str())
        || row.get("restart").and_then(serde_yaml::Value::as_str) != Some("unless-stopped")
        || row.get("image").and_then(serde_yaml::Value::as_str)
            != Some("${EDGE_GATEWAY_IMAGE:?EDGE_GATEWAY_IMAGE is required}")
        || sequence("command")? != ["run", "-c", "/etc/sing-box/config.json"]
        || sequence("depends_on")? != ["warp-egress"]
        || sequence("networks")? != ["edge_net"]
        || (service == "line1-gateway" && sequence("profiles")? != ["tunnel"])
    {
        return Err("HOST_VM_GATEWAY_POLICY_MISMATCH".into());
    }

    let port_entries = sequence("ports")?;
    let mount_entries = sequence("volumes")?;
    if port_entries.is_empty()
        || port_entries.len() > 16
        || mount_entries.is_empty()
        || mount_entries.len() > 8
    {
        return Err("HOST_VM_GATEWAY_RESOURCE_BOUNDS_INVALID".into());
    }
    let mut ports = Vec::new();
    let mut published = BTreeSet::new();
    let mut exposed = BTreeSet::new();
    for raw in port_entries {
        let (host_port, endpoint) = raw
            .split_once(':')
            .ok_or("HOST_VM_GATEWAY_PORT_FORMAT_INVALID")?;
        let (guest_port, protocol) = endpoint
            .split_once('/')
            .ok_or("HOST_VM_GATEWAY_PORT_PROTOCOL_MISSING")?;
        if !matches!(protocol, "tcp" | "udp")
            || host_port
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .is_none()
            || guest_port
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .is_none()
            || !published.insert((host_port.to_owned(), protocol.to_owned()))
            || !exposed.insert((guest_port.to_owned(), protocol.to_owned()))
        {
            return Err("HOST_VM_GATEWAY_PORT_DUPLICATE_OR_INVALID".into());
        }
        ports.push((
            host_port.to_owned(),
            guest_port.to_owned(),
            protocol.to_owned(),
        ));
    }

    let mut mounts = Vec::new();
    let mut targets = BTreeSet::new();
    for raw in mount_entries {
        let parts = raw.split(':').collect::<Vec<_>>();
        if !(parts.len() == 2 || parts.len() == 3)
            || !(parts[0].starts_with("./") || parts[0].starts_with("../"))
            || !parts[1].starts_with('/')
            || parts[1].contains("..")
            || !matches!(parts.get(2), None | Some(&"ro"))
            || !targets.insert(parts[1].to_owned())
        {
            return Err("HOST_VM_GATEWAY_MOUNT_POLICY_INVALID".into());
        }
        // The stack is one directory below the owner root. Parent traversal
        // can reach that owner root but never the OS or another project.
        let mut depth: i32 = 1;
        for component in Path::new(parts[0]).components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::Normal(_) => depth += 1,
                std::path::Component::ParentDir => depth -= 1,
                _ => return Err("HOST_VM_GATEWAY_MOUNT_PATH_INVALID".into()),
            }
            if depth < 0 {
                return Err("HOST_VM_GATEWAY_MOUNT_ESCAPE_FORBIDDEN".into());
            }
        }
        mounts.push((
            parts[0].to_owned(),
            parts[1].to_owned(),
            parts.get(2).copied().unwrap_or("rw").to_owned(),
        ));
    }
    Ok(NativeGatewayPolicy { ports, mounts })
}

/// Build one application-owned gateway through Bollard from the *same*
/// pure admission policy. Canonicalized paths are rechecked under root;
/// symlinks leading outside the owner root are never accepted.
pub(super) fn native_gateway_create_body(
    stack_dir: &Path,
    host: &FleetHost,
    service: &str,
    image_ref: &str,
    network_id: &str,
) -> Result<bollard::models::ContainerCreateBody, String> {
    use bollard::models::{
        ContainerCreateBody, EndpointSettings, HostConfig, NetworkingConfig, PortBinding,
        RestartPolicy, RestartPolicyNameEnum,
    };
    if !matches!(service, "line1-gateway" | "line2-proxy")
        || image_ref.is_empty()
        || network_id.len() != 64
        || !network_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("HOST_VM_CREATE_NATIVE_SCOPE_INVALID".into());
    }
    let identity = host
        .vm_containers
        .iter()
        .find(|item| item.compose_service == service)
        .ok_or("HOST_VM_CREATE_NATIVE_SELECTOR_UNREGISTERED")?;
    let compose = read_native_vm_compose(stack_dir)?;
    let policy = compile_native_gateway_policy(host, &compose, service)?;
    let mut exposed_ports = Vec::new();
    let mut port_bindings = HashMap::new();
    for (host_port, guest_port, protocol) in policy.ports {
        let key = format!("{guest_port}/{protocol}");
        exposed_ports.push(key.clone());
        port_bindings.insert(
            key,
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_owned()),
                host_port: Some(host_port),
            }]),
        );
    }
    let root = stack_dir
        .parent()
        .ok_or("HOST_VM_GATEWAY_ROOT_UNAVAILABLE")?
        .canonicalize()
        .map_err(|_| "HOST_VM_GATEWAY_ROOT_UNAVAILABLE")?;
    let mut binds = Vec::new();
    for (relative, target, mode) in policy.mounts {
        let absolute = stack_dir
            .join(relative)
            .canonicalize()
            .map_err(|_| "HOST_VM_GATEWAY_MOUNT_UNAVAILABLE")?;
        if !absolute.starts_with(&root) {
            return Err("HOST_VM_GATEWAY_MOUNT_OWNER_MISMATCH".into());
        }
        binds.push(format!("{}:{target}:{mode}", absolute.display()));
    }
    let mut labels = HashMap::new();
    labels.insert(
        "com.docker.compose.project".to_owned(),
        identity.compose_project.clone(),
    );
    labels.insert(
        "com.docker.compose.service".to_owned(),
        identity.compose_service.clone(),
    );
    labels.insert(
        "com.docker.compose.depends_on".to_owned(),
        "warp-egress:service_started:false".to_owned(),
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
        image: Some(image_ref.to_owned()),
        cmd: Some(vec![
            "run".to_owned(),
            "-c".to_owned(),
            "/etc/sing-box/config.json".to_owned(),
        ]),
        exposed_ports: Some(exposed_ports),
        labels: Some(labels),
        host_config: Some(HostConfig {
            binds: Some(binds),
            port_bindings: Some(port_bindings),
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

/// One classification for native Docker API failures, irrespective of the
/// lifecycle phase or resource. Docker daemon error messages can carry
/// credentials, paths and container configuration: classify ONLY the typed
/// HTTP status, never copy the message into logs, receipts or comments.
fn native_docker_http_failure_class(status_code: u16) -> &'static str {
    match status_code {
        400 | 422 => "DAEMON_REQUEST_INVALID",
        401 | 403 => "DAEMON_AUTH_DENIED",
        404 => "DAEMON_OBJECT_NOT_FOUND",
        408 | 504 => "DAEMON_TIMEOUT",
        409 | 423 => "DAEMON_RESOURCE_CONFLICT",
        429 => "DAEMON_RATE_LIMITED",
        500..=599 => "DAEMON_SERVER_FAILURE",
        _ => "DAEMON_HTTP_UNCLASSIFIED",
    }
}

fn native_docker_api_failure_class(error: &BollardError) -> &'static str {
    match error {
        BollardError::DockerResponseServerError { status_code, .. } => {
            native_docker_http_failure_class(*status_code)
        }
        _ => "CLIENT_TRANSPORT_OR_PROTOCOL_UNPROVEN",
    }
}

fn record_native_docker_api_failure(phase: &str, service: &str, error: &BollardError) {
    eprintln!(
        "host_native_docker_api phase={phase} service={service} failure_class={}",
        native_docker_api_failure_class(error)
    );
}

/// Closed, non-secret Docker STOP observation. Only the exact registered
/// container ID and Compose owner may satisfy the transition; this result
/// NEVER authorizes a second STOP or clears a pending root journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeVmStopReadback {
    Stopped,
    Running,
    Restarting,
    Paused,
    Dead,
    Unavailable,
    Unknown,
    IdentityChanged,
}

impl NativeVmStopReadback {
    fn error_code(self) -> &'static str {
        match self {
            Self::Stopped => "HOST_VM_NATIVE_RECREATE_STOPPED",
            Self::Running => "HOST_VM_NATIVE_RECREATE_STOP_RUNNING_NO_REPLAY",
            Self::Restarting => "HOST_VM_NATIVE_RECREATE_STOP_RESTARTING_NO_REPLAY",
            Self::Paused => "HOST_VM_NATIVE_RECREATE_STOP_PAUSED_NO_REPLAY",
            Self::Dead => "HOST_VM_NATIVE_RECREATE_STOP_DEAD_NO_REPLAY",
            Self::Unavailable => "HOST_VM_NATIVE_RECREATE_STOP_INSPECT_UNAVAILABLE_NO_REPLAY",
            Self::Unknown => "HOST_VM_NATIVE_RECREATE_STOP_STATE_UNKNOWN_NO_REPLAY",
            Self::IdentityChanged => "HOST_VM_NATIVE_RECREATE_STOP_IDENTITY_CHANGED_NO_REPLAY",
        }
    }
}

fn classify_native_vm_stop_readback(
    identity_verified: bool,
    running: Option<bool>,
    restarting: Option<bool>,
    paused: Option<bool>,
    dead: Option<bool>,
) -> NativeVmStopReadback {
    if !identity_verified {
        NativeVmStopReadback::IdentityChanged
    } else if restarting == Some(true) {
        NativeVmStopReadback::Restarting
    } else if paused == Some(true) {
        NativeVmStopReadback::Paused
    } else if dead == Some(true) {
        NativeVmStopReadback::Dead
    } else if running == Some(false) {
        NativeVmStopReadback::Stopped
    } else if running == Some(true) {
        NativeVmStopReadback::Running
    } else {
        NativeVmStopReadback::Unknown
    }
}

/// Recreate one exact application-owned service through the same native
/// Docker owner and no-replay journal. WARP and gateways use pre-BEGIN
/// validated container policy; foreign Mesh and arbitrary names are refused.
pub(super) async fn recreate_native_vm_container_once(
    docker: &Docker,
    host: &FleetHost,
    service: &str,
    previous_id: &str,
    network_id: &str,
    body: bollard::models::ContainerCreateBody,
) -> Result<(), String> {
    let selector = host
        .vm_containers
        .iter()
        .find(|item| item.compose_service == service)
        .ok_or("HOST_VM_NATIVE_RECREATE_SELECTOR_MISSING_NO_REPLAY")?;
    if !matches!(service, "line1-gateway" | "line2-proxy" | "warp-egress")
        || read_owned_edge_network_id(docker, host).await?.as_str() != network_id
    {
        return Err("HOST_VM_NATIVE_RECREATE_SCOPE_CHANGED_NO_REPLAY".into());
    }
    let inspected = docker
        .inspect_container(previous_id, None)
        .await
        .map_err(|error| {
            record_native_docker_api_failure("INSPECT_PRESTATE", service, &error);
            "HOST_VM_NATIVE_RECREATE_OLD_ID_UNAVAILABLE_NO_REPLAY".to_owned()
        })?;
    let state = inspected
        .state
        .as_ref()
        .ok_or("HOST_VM_NATIVE_RECREATE_PRESTATE_CHANGED_NO_REPLAY")?;
    let known_transition_state =
        state.paused == Some(false) && state.restarting == Some(false) && state.dead == Some(false);
    let already_stopped =
        service == "warp-egress" && known_transition_state && state.running == Some(false);
    if inspected.id.as_deref() != Some(previous_id)
        || inspected.name.as_deref() != Some(format!("/{}", selector.container_name).as_str())
        || !known_transition_state
        || (state.running != Some(true) && !already_stopped)
    {
        return Err("HOST_VM_NATIVE_RECREATE_PRESTATE_CHANGED_NO_REPLAY".into());
    }
    let labels = inspected
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .ok_or("HOST_VM_NATIVE_RECREATE_OLD_LABELS_MISSING_NO_REPLAY")?;
    exact_application_compose_owner(&selector.container_name, labels, &host.vm_containers)
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_OWNER_CHANGED_NO_REPLAY")?;
    let expected_image = body
        .image
        .as_deref()
        .ok_or("HOST_VM_NATIVE_RECREATE_IMAGE_MISSING_NO_REPLAY")?;
    docker
        .inspect_image(expected_image)
        .await
        .map_err(|error| {
            record_native_docker_api_failure("INSPECT_IMAGE", service, &error);
            "HOST_VM_NATIVE_RECREATE_PINNED_IMAGE_MISSING_NO_REPLAY".to_owned()
        })?;
    // Docker may lose the STOP ACK or take time to transition. At most
    // ONE STOP is permitted by the signed owner journal; an already stopped
    // owned WARP never receives STOP again. A bounded series of
    // read-only INSPECT calls determines what actually happened to this ID.
    // Never print arbitrary daemon errors, labels or environment variables.
    let stop_started = tokio::time::Instant::now();
    let stop_ack = if already_stopped {
        None
    } else {
        Some(
            docker
                .stop_container(
                    previous_id,
                    Some(
                        bollard::query_parameters::StopContainerOptionsBuilder::default()
                            .t(20)
                            .build(),
                    ),
                )
                .await,
        )
    };
    let ack = if already_stopped {
        "NOT_REQUIRED_ALREADY_STOPPED"
    } else if stop_ack.as_ref().is_some_and(Result::is_ok) {
        "OK"
    } else {
        "ERROR"
    };
    let ack_class = stop_ack
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(native_docker_api_failure_class)
        .unwrap_or("NONE");
    let stop_api_elapsed_ms = stop_started.elapsed().as_millis();
    let observation_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut observed = NativeVmStopReadback::Unavailable;
    let mut inspections = 0u32;
    let mut state_fields = String::from("UNAVAILABLE");

    loop {
        inspections += 1;
        match docker.inspect_container(previous_id, None).await {
            Ok(container) => {
                let owner_verified = container
                    .config
                    .as_ref()
                    .and_then(|config| config.labels.as_ref())
                    .is_some_and(|labels| {
                        exact_application_compose_owner(
                            &selector.container_name,
                            labels,
                            &host.vm_containers,
                        )
                        .is_ok()
                    });
                let identity_verified = container.id.as_deref() == Some(previous_id)
                    && container.name.as_deref()
                        == Some(format!("/{}", selector.container_name).as_str())
                    && owner_verified;
                let state = container.state.as_ref();
                observed = classify_native_vm_stop_readback(
                    identity_verified,
                    state.and_then(|s| s.running),
                    state.and_then(|s| s.restarting),
                    state.and_then(|s| s.paused),
                    state.and_then(|s| s.dead),
                );
                // Only Docker's typed state and restart policy; NEVER its
                // free-form error message or any container configuration.
                state_fields = format!(
                    "running={:?} restarting={:?} paused={:?} dead={:?} exit={:?} restart_policy={:?}",
                    state.and_then(|s| s.running),
                    state.and_then(|s| s.restarting),
                    state.and_then(|s| s.paused),
                    state.and_then(|s| s.dead),
                    state.and_then(|s| s.exit_code),
                    container
                        .host_config
                        .as_ref()
                        .and_then(|h| h.restart_policy.as_ref())
                        .and_then(|p| p.name.as_ref()),
                );
            }
            Err(error) => {
                observed = NativeVmStopReadback::Unavailable;
                state_fields = format!("INSPECT_API_{}", native_docker_api_failure_class(&error));
            }
        }
        if observed == NativeVmStopReadback::Stopped
            || observed == NativeVmStopReadback::IdentityChanged
            || tokio::time::Instant::now() >= observation_deadline
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    // One compact causal trace per transition, including failures. The root
    // journal stays authoritative for no-replay; CI logs are diagnostics,
    // never accepted as a signed physical success receipt.
    eprintln!(
        "host_native_docker_stop service={service} container_id={previous_id} ack={ack} ack_class={ack_class} readback={observed:?} inspections={inspections} stop_api_elapsed_ms={stop_api_elapsed_ms} elapsed_ms={} {state_fields} next_action={}",
        stop_started.elapsed().as_millis(),
        if observed == NativeVmStopReadback::Stopped {
            "CONTINUE_REGISTERED_TRANSITION"
        } else {
            "SIGNED_RECOVER_AFTER_READ_ONLY_DIAGNOSIS"
        },
    );
    if observed != NativeVmStopReadback::Stopped {
        return Err(observed.error_code().into());
    }
    docker
        .remove_container(
            previous_id,
            None::<bollard::query_parameters::RemoveContainerOptions>,
        )
        .await
        .map_err(|error| {
            record_native_docker_api_failure("REMOVE", service, &error);
            "HOST_VM_NATIVE_RECREATE_DELETE_UNCERTAIN_NO_REPLAY".to_owned()
        })?;
    let options = bollard::query_parameters::CreateContainerOptionsBuilder::default()
        .name(&selector.container_name)
        .build();
    let created = docker
        .create_container(Some(options), body)
        .await
        .map_err(|error| {
            record_native_docker_api_failure("CREATE", service, &error);
            "HOST_VM_NATIVE_RECREATE_CREATE_UNCERTAIN_NO_REPLAY".to_owned()
        })?;
    if created.id.len() != 64 || !created.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("HOST_VM_NATIVE_RECREATE_NEW_ID_UNPROVEN_NO_REPLAY".into());
    }
    docker
        .start_container(
            &created.id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .map_err(|error| {
            record_native_docker_api_failure("START", service, &error);
            "HOST_VM_NATIVE_RECREATE_START_UNCERTAIN_NO_REPLAY".to_owned()
        })?;
    Ok(())
}

/// Keep a closed gateway-only entry point for existing config effectors.
pub(super) async fn recreate_native_gateway_once(
    docker: &Docker,
    host: &FleetHost,
    service: &str,
    previous_id: &str,
    network_id: &str,
    body: bollard::models::ContainerCreateBody,
) -> Result<(), String> {
    if !matches!(service, "line1-gateway" | "line2-proxy") {
        return Err("HOST_VM_GATEWAY_SCOPE_UNSUPPORTED".into());
    }
    recreate_native_vm_container_once(docker, host, service, previous_id, network_id, body).await
}

#[cfg(test)]
mod native_vm_stop_diagnostics_tests {
    use super::*;

    #[test]
    fn one_docker_api_classifier_covers_every_lifecycle_phase_without_daemon_text() {
        assert_eq!(
            native_docker_http_failure_class(400),
            "DAEMON_REQUEST_INVALID"
        );
        assert_eq!(native_docker_http_failure_class(401), "DAEMON_AUTH_DENIED");
        assert_eq!(native_docker_http_failure_class(403), "DAEMON_AUTH_DENIED");
        assert_eq!(
            native_docker_http_failure_class(404),
            "DAEMON_OBJECT_NOT_FOUND"
        );
        assert_eq!(native_docker_http_failure_class(408), "DAEMON_TIMEOUT");
        assert_eq!(
            native_docker_http_failure_class(409),
            "DAEMON_RESOURCE_CONFLICT"
        );
        assert_eq!(native_docker_http_failure_class(429), "DAEMON_RATE_LIMITED");
        assert_eq!(
            native_docker_http_failure_class(500),
            "DAEMON_SERVER_FAILURE"
        );
        assert_eq!(
            native_docker_http_failure_class(503),
            "DAEMON_SERVER_FAILURE"
        );
        assert_eq!(native_docker_http_failure_class(504), "DAEMON_TIMEOUT");
        assert_eq!(
            native_docker_http_failure_class(418),
            "DAEMON_HTTP_UNCLASSIFIED"
        );
        // The daemon's arbitrary response text must never be returned.
        let error = BollardError::DockerResponseServerError {
            status_code: 409,
            message: "Authorization: Bearer confidential".into(),
        };
        assert_eq!(
            native_docker_api_failure_class(&error),
            "DAEMON_RESOURCE_CONFLICT"
        );
    }

    #[test]
    fn stopped_requires_same_id_name_and_owner() {
        use NativeVmStopReadback::*;
        assert_eq!(
            classify_native_vm_stop_readback(
                true,
                Some(false),
                Some(false),
                Some(false),
                Some(false)
            ),
            Stopped
        );
        assert_eq!(
            classify_native_vm_stop_readback(
                false,
                Some(false),
                Some(false),
                Some(false),
                Some(false)
            ),
            IdentityChanged
        );
        assert_eq!(
            classify_native_vm_stop_readback(true, None, None, None, None),
            Unknown
        );
    }

    #[test]
    fn running_restart_paused_dead_and_missing_readback_are_distinct() {
        use NativeVmStopReadback::*;
        assert_eq!(
            classify_native_vm_stop_readback(
                true,
                Some(true),
                Some(false),
                Some(false),
                Some(false)
            ),
            Running
        );
        assert_eq!(
            classify_native_vm_stop_readback(
                true,
                Some(true),
                Some(true),
                Some(false),
                Some(false)
            ),
            Restarting
        );
        assert_eq!(
            classify_native_vm_stop_readback(
                true,
                Some(true),
                Some(false),
                Some(true),
                Some(false)
            ),
            Paused
        );
        assert_eq!(
            classify_native_vm_stop_readback(
                true,
                Some(false),
                Some(false),
                Some(false),
                Some(true)
            ),
            Dead
        );
        for result in [
            Running,
            Restarting,
            Paused,
            Dead,
            Unavailable,
            Unknown,
            IdentityChanged,
        ] {
            assert!(result.error_code().ends_with("_NO_REPLAY"));
        }
        assert_eq!(Stopped.error_code(), "HOST_VM_NATIVE_RECREATE_STOPPED");
    }
}
