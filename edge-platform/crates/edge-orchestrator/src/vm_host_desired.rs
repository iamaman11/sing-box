//! One Git-owned per-host VM specification, decoded by the native Rust planner.
//! Buf compiles checked-out immutable textproto to a transient protobuf before
//! first-use; no text parsing, YAML/JSON adapter, or VM-side build tool exists.
use edge_controller_core::application_lifecycle::{
    ApplicationBootstrapMode, ApplicationRuntimePolicy, DesiredApplicationState,
    Line1RuntimePolicy, Line2RuntimePolicy, SUPPORTED_APPLICATION_SCHEMA,
};
use edge_controller_core::vultr_lifecycle::{DesiredState, MachineSpec, ProviderSpec};
use edge_shared_types::{
    FleetVmHostDesired, ProductionBootstrapMode, production_machine,
};
use prost::Message;
use std::fs;
use std::path::Path;

pub(crate) fn load(path: &Path) -> Result<(DesiredState, DesiredApplicationState), String> {
    let name = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or("HOST_VM_TYPED_SPEC_NAME_INVALID")?;
    if path != Path::new(&format!("infra/hosts/specs/{name}.textproto"))
        || name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("HOST_VM_TYPED_SPEC_OUTSIDE_OWNED_PATH".to_owned());
    }
    let source = fs::read(path).map_err(|_| "HOST_VM_TYPED_SOURCE_UNREADABLE")?;
    if source.is_empty() || source.len() > 131_072 {
        return Err("HOST_VM_TYPED_SOURCE_INVALID_SIZE".to_owned());
    }
    // Only the fixed trusted control-plane Buf compilation produces this
    // derived file. It is not Git desired and is never committed or sent to VM.
    let compiled = path.with_extension("binpb");
    let bytes = fs::read(&compiled).map_err(|_| "HOST_VM_TYPED_COMPILED_ABSENT")?;
    if bytes.is_empty() || bytes.len() > 131_072 {
        return Err("HOST_VM_TYPED_COMPILED_INVALID_SIZE".to_owned());
    }
    let desired = FleetVmHostDesired::decode(bytes.as_slice())
        .map_err(|_| "HOST_VM_TYPED_PROTOBUF_INVALID")?;
    convert(&desired, path, name)
}

fn convert(
    input: &FleetVmHostDesired,
    path: &Path,
    name: &str,
) -> Result<(DesiredState, DesiredApplicationState), String> {
    if input.schema_version != 1 || input.machine_id != name {
        return Err("HOST_VM_TYPED_IDENTITY_MISMATCH".to_owned());
    }
    let machine = input.machine.as_ref().ok_or("HOST_VM_TYPED_MACHINE_MISSING")?;
    let application = input.application.as_ref().ok_or("HOST_VM_TYPED_APPLICATION_MISSING")?;
    let (os_id, snapshot_id) = match machine.image.as_ref() {
        Some(production_machine::Image::OsId(n)) if *n > 0 => (Some(*n), None),
        Some(production_machine::Image::SnapshotId(s)) if !s.is_empty() => (None, Some(s.clone())),
        _ => return Err("HOST_VM_TYPED_PROVIDER_IMAGE_REQUIRED".to_owned()),
    };
    if input.firewall_profile.is_empty()
        || !machine.application_profiles.contains(&application.application_profile)
    {
        return Err("HOST_VM_TYPED_APPLICATION_PROFILE_MISMATCH".to_owned());
    }
    let vm = DesiredState {
        schema: 1,
        environment: input.environment.clone(),
        machines: vec![MachineSpec {
            id: name.to_owned(),
            role: machine.role.clone(),
            provider: ProviderSpec {
                region: machine.region.clone(),
                plan: machine.plan.clone(),
                os_id,
                snapshot_id,
                enable_ipv6: machine.enable_ipv6,
                firewall_profile: Some(input.firewall_profile.clone()),
            },
            bootstrap_profile: machine.bootstrap_profile.clone(),
            application_profiles: machine.application_profiles.clone(),
            tags: machine.tags.clone(),
        }],
    };
    vm.validate().map_err(|err| format!("HOST_VM_TYPED_PROVIDER_INVALID: {err}"))?;
    let bootstrap_mode = match ProductionBootstrapMode::try_from(application.bootstrap_mode) {
        Ok(ProductionBootstrapMode::Base) => ApplicationBootstrapMode::Base,
        Ok(ProductionBootstrapMode::Tunnel) => ApplicationBootstrapMode::Tunnel,
        Ok(ProductionBootstrapMode::Full) => ApplicationBootstrapMode::Full,
        _ => return Err("HOST_VM_TYPED_BOOTSTRAP_MODE_INVALID".to_owned()),
    };
    let app = DesiredApplicationState {
        schema: SUPPORTED_APPLICATION_SCHEMA,
        environment: input.environment.clone(),
        vultr_spec_path: path.to_string_lossy().into_owned(),
        machine_id: name.to_owned(),
        application_profile: application.application_profile.clone(),
        bundle_root: application.bundle_root.clone(),
        runtime_env_required: application.runtime_env_required,
        runtime_policy: ApplicationRuntimePolicy {
            line1: application.line1.as_ref().map(|p| Line1RuntimePolicy {
                tunnel_domain: p.tunnel_domain.clone(),
                acme_email: p.acme_email.clone(),
                acme_provider: p.acme_provider.clone(),
                reality_server_name: p.reality_server_name.clone(),
            }),
            line2: application.line2.as_ref().map(|p| Line2RuntimePolicy {
                proxy_username: p.proxy_username.clone(),
                proxy_cert_cn: p.proxy_cert_cn.clone(),
            }),
        },
        bootstrap_mode,
    };
    app.validate().map_err(|err| format!("HOST_VM_TYPED_APPLICATION_INVALID: {err}"))?;
    Ok((vm, app))
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{ProductionApplication, ProductionLine1Policy, ProductionLine2Policy, ProductionMachine, production_machine::Image};

    fn fixture() -> FleetVmHostDesired {
        FleetVmHostDesired {
            schema_version: 1,
            environment: "application-acceptance".to_owned(),
            machine_id: "acceptance-test".to_owned(),
            firewall_profile: "application-acceptance".to_owned(),
            machine: Some(ProductionMachine {
                role: "application-acceptance".to_owned(),
                region: "waw".to_owned(),
                plan: "vc2-1c-1gb".to_owned(),
                image: Some(Image::OsId(2625)),
                enable_ipv6: false,
                bootstrap_profile: "singbox-host-v2".to_owned(),
                application_profiles: vec!["application-acceptance".to_owned()],
                tags: vec!["disposable-acceptance-test".to_owned()],
            }),
            application: Some(ProductionApplication {
                application_profile: "application-acceptance".to_owned(),
                bundle_root: "win/vultr-waw/stack".to_owned(),
                runtime_env_required: true,
                bootstrap_mode: ProductionBootstrapMode::Full as i32,
                line1: Some(ProductionLine1Policy {
                    tunnel_domain: "stage2-test.alegria.by".to_owned(),
                    acme_email: "admin@alegria.by".to_owned(),
                    acme_provider: "letsencrypt".to_owned(),
                    reality_server_name: "www.microsoft.com".to_owned(),
                }),
                line2: Some(ProductionLine2Policy {
                    proxy_username: "acceptance".to_owned(),
                    proxy_cert_cn: "stage2-test.alegria.by".to_owned(),
                }),
            }),
        }
    }

    #[test]
    fn one_typed_spec_drives_provider_and_application() {
        let (vm, app) = convert(&fixture(), Path::new("infra/hosts/specs/acceptance-test.textproto"), "acceptance-test").unwrap();
        assert_eq!(vm.machines[0].id, app.machine_id);
        assert_eq!(app.vultr_spec_path, "infra/hosts/specs/acceptance-test.textproto");
    }

    #[test]
    fn wrong_id_missing_policy_and_unknown_mode_fail_closed() {
        let path = Path::new("infra/hosts/specs/acceptance-test.textproto");
        let mut bad = fixture();
        bad.machine_id = "another".into();
        assert!(convert(&bad, path, "acceptance-test").is_err());
        bad = fixture();
        bad.firewall_profile.clear();
        assert!(convert(&bad, path, "acceptance-test").is_err());
        bad = fixture();
        bad.application.as_mut().unwrap().bootstrap_mode = 999;
        assert!(convert(&bad, path, "acceptance-test").is_err());
    }
}
