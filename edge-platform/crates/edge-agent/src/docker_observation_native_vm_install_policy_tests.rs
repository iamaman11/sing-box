use super::*;

fn warp_host() -> FleetHost {
    FleetHost {
        vm_containers: vec![FleetVmContainer {
            container_name: "vultr-warp-egress".to_owned(),
            compose_project: "vultr-edge".to_owned(),
            compose_service: "warp-egress".to_owned(),
        }],
        ..Default::default()
    }
}

#[test]
fn signed_native_warp_admits_only_exact_immutable_compose_policy() {
    let policy = include_str!("../../../../win/vultr-waw/stack/docker-compose.yml");
    let host = warp_host();
    let valid = serde_yaml::from_str::<serde_yaml::Value>(policy).unwrap();
    assert!(validate_native_warp_install_compose(&host, &valid).is_ok());

    for changed in [
        policy.replace("      - NET_ADMIN", "      - SYS_ADMIN"),
        policy.replace(
            "      - ../warp-state:/var/lib/cloudflare-warp",
            "      - /:/host",
        ),
        policy.replace("      - edge_net", "      - host"),
    ] {
        let value = serde_yaml::from_str::<serde_yaml::Value>(&changed).unwrap();
        assert!(validate_native_warp_install_compose(&host, &value).is_err());
    }
}
