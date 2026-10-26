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
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_OLD_ID_UNAVAILABLE_NO_REPLAY")?;
    if inspected.id.as_deref() != Some(previous_id)
        || inspected.name.as_deref() != Some(format!("/{}", selector.container_name).as_str())
        || !inspected
            .state
            .as_ref()
            .is_some_and(|state| state.running == Some(true))
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
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_PINNED_IMAGE_MISSING_NO_REPLAY")?;
    // Docker can report a failed/lost STOP ACK even though it already
    // stopped the exact container. Never issue a second STOP. Independently
    // inspect the SAME owned immutable ID under the existing root journal
    // and owner lock; only a proved stopped state may proceed to DELETE.
    let stop_ack = docker
        .stop_container(
            previous_id,
            Some(
                bollard::query_parameters::StopContainerOptionsBuilder::default()
                    .t(20)
                    .build(),
            ),
        )
        .await;
    let stopped = docker
        .inspect_container(previous_id, None)
        .await
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_STOP_UNCERTAIN_NO_REPLAY")?;
    if stopped.id.as_deref() != Some(previous_id)
        || stopped.name.as_deref() != Some(format!("/{}", selector.container_name).as_str())
        || !stopped.state.as_ref().is_some_and(|state| {
            state.running == Some(false)
                && state.paused != Some(true)
                && state.restarting != Some(true)
        })
    {
        return Err("HOST_VM_NATIVE_RECREATE_STOP_UNCERTAIN_NO_REPLAY".into());
    }
    let stopped_labels = stopped
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .ok_or("HOST_VM_NATIVE_RECREATE_STOP_OWNER_UNPROVEN_NO_REPLAY")?;
    exact_application_compose_owner(
        &selector.container_name,
        stopped_labels,
        &host.vm_containers,
    )
    .map_err(|_| "HOST_VM_NATIVE_RECREATE_STOP_OWNER_UNPROVEN_NO_REPLAY")?;
    if stop_ack.is_err() {
        eprintln!("host_native_docker_stop_ack=RECONCILED_BY_EXACT_STOPPED_ID");
    }
    docker
        .remove_container(
            previous_id,
            None::<bollard::query_parameters::RemoveContainerOptions>,
        )
        .await
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_DELETE_UNCERTAIN_NO_REPLAY")?;
    let options = bollard::query_parameters::CreateContainerOptionsBuilder::default()
        .name(&selector.container_name)
        .build();
    let created = docker
        .create_container(Some(options), body)
        .await
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_CREATE_UNCERTAIN_NO_REPLAY")?;
    if created.id.len() != 64 || !created.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("HOST_VM_NATIVE_RECREATE_NEW_ID_UNPROVEN_NO_REPLAY".into());
    }
    docker
        .start_container(
            &created.id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .map_err(|_| "HOST_VM_NATIVE_RECREATE_START_UNCERTAIN_NO_REPLAY")?;
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
