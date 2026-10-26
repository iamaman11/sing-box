#[test]
fn fatal_sensitive_tls_key_log_emits_only_constant_diagnostic_marker() {
    let raw = "FATAL[0000] tls: invalid private key password=secret credential=hidden";
    let result = redact_runtime_log_line(raw);
    assert_eq!(result, "[SAFE_FATAL_TLS_PRIVATE_KEY_ERROR]");
    assert!(!result.contains("secret"));
    assert!(!result.contains("credential="));

    let ordinary = redact_runtime_log_line("INFO[0000] tls private key loaded password=secret");
    assert_eq!(ordinary, "[redacted sensitive runtime log line]");
}

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
    use edge_shared_types::FleetVmObservedReason as Reason;
    assert_eq!(
        native_running_health_reason(true, Some("Healthy")),
        (Reason::Healthy, "HEALTHY")
    );
    assert_eq!(
        native_running_health_reason(true, Some("Starting")),
        (Reason::HealthStarting, "STARTING")
    );
    assert_eq!(
        native_running_health_reason(true, Some("Unhealthy")),
        (Reason::HealthUnhealthy, "UNHEALTHY")
    );
    assert_eq!(
        native_running_health_reason(true, None),
        (Reason::RunningNoHealthcheck, "")
    );
    assert_eq!(
        native_running_health_reason(true, Some("Unknown")),
        (Reason::HealthUnproven, "")
    );
    assert_eq!(
        native_running_health_reason(false, None),
        (Reason::Stopped, "")
    );
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
        exact_application_compose_owner("vultr-cloudflare-mesh", &valid_project, &vm_scope_test())
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
        exact_application_compose_owner("vultr-line1-gateway", &labels, &vm_scope_test()).is_err()
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
        let result = require_exact_readonly_config_bind("vultr-line1-gateway", kind, Some(false));
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
