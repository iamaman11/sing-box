    use super::*;

    #[test]
    fn signed_gateway_policy_rejects_new_execution_fields_and_path_escape() {
        let compose = include_str!("../../../../win/vultr-waw/stack/docker-compose.yml");
        let host = FleetHost {
            vm_containers: vec![
                FleetVmContainer {
                    compose_project: "vultr-edge".into(),
                    compose_service: "line1-gateway".into(),
                    container_name: "vultr-line1-gateway".into(),
                },
                FleetVmContainer {
                    compose_project: "vultr-edge".into(),
                    compose_service: "line2-proxy".into(),
                    container_name: "vultr-line2-proxy".into(),
                },
            ],
            ..Default::default()
        };
        let valid = serde_yaml::from_str::<serde_yaml::Value>(compose).unwrap();
        for service in ["line1-gateway", "line2-proxy"] {
            assert!(compile_native_gateway_policy(&host, &valid, service).is_ok());
        }
        for (field, entries) in [
            ("depends_on", vec!["cloudflare-mesh"]),
            (
                "volumes",
                vec!["../../etc/passwd:/etc/sing-box/config.json:ro"],
            ),
            ("ports", vec!["3128:3128/tcp", "3128:3128/tcp"]),
            ("command", vec!["run", "-c", "/bin/sh"]),
        ] {
            let mut changed = valid.clone();
            changed["services"]["line2-proxy"][field] = serde_yaml::Value::Sequence(
                entries
                    .into_iter()
                    .map(|value| serde_yaml::Value::String(value.to_owned()))
                    .collect(),
            );
            assert!(
                compile_native_gateway_policy(&host, &changed, "line2-proxy").is_err(),
                "unexpected acceptance of changed {field}",
            );
        }
    }
