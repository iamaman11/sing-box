//! Git-declared Docker volumes and networks via the existing signed
//! HostIntent, protected root journal, exact ReleaseSet and Bollard socket.
//! A runner cannot choose an ID, name, driver, labels or Docker operation.
use super::*;
use edge_shared_types::{
    FleetHost, FleetVmManagedDockerDesiredState as Desired,
    FleetVmManagedDockerKind as Kind, FleetVmManagedDockerResource,
};
use prost::Message;
use std::collections::HashMap;

const LABEL_OWNER: &str = "io.github.iamaman11.singbox.machine";
const LABEL_RESOURCE: &str = "io.github.iamaman11.singbox.resource";

#[derive(Debug)]
pub(super) struct PreparedManagedDocker {
    spec: FleetVmManagedDockerResource,
    original_fingerprint: Option<String>,
    create: bool,
}

fn resource_path_expected(
    host: &FleetHost,
    path: &str,
    spec: &FleetVmManagedDockerResource,
) -> bool {
    let kind_prefix = match Kind::try_from(spec.kind) {
        Ok(Kind::LocalVolume) => "managed/docker-volume-",
        Ok(Kind::BridgeNetwork) => "managed/docker-network-",
        _ => return false,
    };
    let Some(suffix) = path.strip_prefix(kind_prefix).and_then(|s| s.strip_suffix(".pb")) else {
        return false;
    };
    !suffix.is_empty()
        && suffix.len() <= 40
        && suffix.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && suffix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && spec.resource_name == format!("sb-{}-{suffix}", host.machine_id)
        && spec.resource_name.len() <= 112
        && spec.machine_id == host.machine_id
        && spec.schema_version == 1
        && matches!(
            Desired::try_from(spec.desired_state),
            Ok(Desired::Present | Desired::Absent)
        )
}

pub(super) fn is_managed_docker_manifest(path: &str) -> bool {
    path.starts_with("managed/docker-volume-") || path.starts_with("managed/docker-network-")
}

fn decode_exact_spec(
    host: &FleetHost,
    path: &str,
    bytes: &[u8],
) -> Result<FleetVmManagedDockerResource, String> {
    if bytes.is_empty() || bytes.len() > 2048 {
        return Err("HOST_VM_DOCKER_MANIFEST_SIZE_INVALID".into());
    }
    let spec = FleetVmManagedDockerResource::decode(bytes)
        .map_err(|_| "HOST_VM_DOCKER_MANIFEST_DECODE_INVALID")?;
    if spec.encode_to_vec() != bytes || !resource_path_expected(host, path, &spec) {
        return Err("HOST_VM_DOCKER_MANIFEST_CANONICAL_OR_SCOPE_INVALID".into());
    }
    Ok(spec)
}

fn expected_labels(spec: &FleetVmManagedDockerResource) -> HashMap<String, String> {
    HashMap::from([
        (LABEL_OWNER.to_owned(), spec.machine_id.clone()),
        (LABEL_RESOURCE.to_owned(), spec.resource_name.clone()),
    ])
}

/// Only Docker 404 means absent. Network or volume daemon failure is not
/// inferred as absence. Never adopt names with unknown ownership.
async fn observe_managed_docker_object(
    docker: &bollard::Docker,
    spec: &FleetVmManagedDockerResource,
    for_delete: bool,
) -> Result<Option<String>, String> {
    use bollard::errors::Error as DockerError;
    match Kind::try_from(spec.kind) {
        Ok(Kind::LocalVolume) => match docker.inspect_volume(&spec.resource_name).await {
            Ok(volume) => {
                if volume.name != spec.resource_name
                    || volume.driver != "local"
                    || volume.labels.get(LABEL_OWNER) != Some(&spec.machine_id)
                    || volume.labels.get(LABEL_RESOURCE) != Some(&spec.resource_name)
                    || !volume.options.is_empty()
                {
                    return Err("HOST_VM_DOCKER_VOLUME_FOREIGN_OR_DRIVER_DRIFT".into());
                }
                // Volume names have no stable daemon ID: creation timestamp
                // is the CAS guard; without it a deletion must fail closed.
                let created = volume.created_at
                    .filter(|time| !time.is_empty())
                    .ok_or("HOST_VM_DOCKER_VOLUME_IDENTITY_UNPROVEN")?;
                Ok(Some(created))
            }
            Err(DockerError::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
            Err(_) => Err("HOST_VM_DOCKER_VOLUME_READBACK_UNAVAILABLE".into()),
        },
        Ok(Kind::BridgeNetwork) => match docker.inspect_network(&spec.resource_name, None).await {
            Ok(network) => {
                if network.name.as_deref() != Some(spec.resource_name.as_str())
                    || network.driver.as_deref() != Some("bridge")
                    || network.internal != Some(true)
                    || network.labels.as_ref().and_then(|l| l.get(LABEL_OWNER)) != Some(&spec.machine_id)
                    || network.labels.as_ref().and_then(|l| l.get(LABEL_RESOURCE)) != Some(&spec.resource_name)
                {
                    return Err("HOST_VM_DOCKER_NETWORK_FOREIGN_OR_DRIVER_DRIFT".into());
                }
                if for_delete && !network.containers.as_ref().is_some_and(HashMap::is_empty) {
                    return Err("HOST_VM_DOCKER_NETWORK_ATTACHED_OR_UNPROVEN".into());
                }
                let id = network.id
                    .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                    .ok_or("HOST_VM_DOCKER_NETWORK_IDENTITY_UNPROVEN")?;
                Ok(Some(id))
            }
            Err(DockerError::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
            Err(_) => Err("HOST_VM_DOCKER_NETWORK_READBACK_UNAVAILABLE".into()),
        },
        _ => Err("HOST_VM_DOCKER_RESOURCE_KIND_UNSUPPORTED".into()),
    }
}

pub(super) async fn preflight_managed_docker_object(
    host: &FleetHost,
    path: &str,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<PreparedManagedDocker, String> {
    let previous = before.map(|b| decode_exact_spec(host, path, b)).transpose()?;
    let next = after.map(|b| decode_exact_spec(host, path, b)).transpose()?;
    let spec = next.as_ref().or(previous.as_ref())
        .ok_or("HOST_VM_DOCKER_RESOURCE_SCOPE_EMPTY")?;
    if let (Some(a), Some(b)) = (&previous, &next) {
        if a.machine_id != b.machine_id || a.resource_name != b.resource_name || a.kind != b.kind {
            return Err("HOST_VM_DOCKER_RESOURCE_IDENTITY_CHANGE_UNSUPPORTED".into());
        }
    }
    let prior = previous.as_ref()
        .is_some_and(|s| s.desired_state == Desired::Present as i32);
    let desired = next.as_ref()
        .is_some_and(|s| s.desired_state == Desired::Present as i32);
    if prior == desired {
        return Err("HOST_VM_DOCKER_OPERATION_REQUIRES_STATE_CHANGE".into());
    }
    let docker = super::docker_connection().await?;
    let physical = observe_managed_docker_object(&docker, spec, !desired).await?;
    if physical.is_some() != prior {
        return Err("HOST_VM_DOCKER_PRESTATE_NOT_CONVERGED".into());
    }
    Ok(PreparedManagedDocker {
        spec: spec.clone(), original_fingerprint: physical, create: desired,
    })
}

/// One intended remote Docker effect; any failed/uncertain acknowledgement
/// leaves the shared resource journal pending. No retries or compensation.
pub(super) async fn apply_managed_docker_object_once(
    plan: &PreparedManagedDocker,
) -> Result<(), String> {
    let docker = super::docker_connection().await?;
    let actual = observe_managed_docker_object(&docker, &plan.spec, !plan.create).await?;
    if actual != plan.original_fingerprint {
        return Err("HOST_VM_DOCKER_OBJECT_CAS_CHANGED_NO_REPLAY".into());
    }
    let name = &plan.spec.resource_name;
    if plan.create {
        let labels = expected_labels(&plan.spec);
        match Kind::try_from(plan.spec.kind) {
            Ok(Kind::LocalVolume) => {
                docker.create_volume(bollard::models::VolumeCreateRequest {
                    name: Some(name.clone()),
                    driver: Some("local".to_owned()),
                    labels: Some(labels),
                    ..Default::default()
                }).await.map_err(|_| "HOST_VM_DOCKER_VOLUME_CREATE_UNCERTAIN_NO_REPLAY")?;
            }
            Ok(Kind::BridgeNetwork) => {
                docker.create_network(bollard::models::NetworkCreateRequest {
                    name: name.clone(),
                    driver: Some("bridge".to_owned()),
                    internal: Some(true),
                    attachable: Some(false),
                    labels: Some(labels),
                    ..Default::default()
                }).await.map_err(|_| "HOST_VM_DOCKER_NETWORK_CREATE_UNCERTAIN_NO_REPLAY")?;
            }
            _ => return Err("HOST_VM_DOCKER_KIND_NOT_EXECUTABLE".into()),
        }
    } else {
        match Kind::try_from(plan.spec.kind) {
            Ok(Kind::LocalVolume) => {
                docker.remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>)
                    .await.map_err(|_| "HOST_VM_DOCKER_VOLUME_DELETE_UNCERTAIN_NO_REPLAY")?;
            }
            Ok(Kind::BridgeNetwork) => {
                docker.remove_network(name)
                    .await.map_err(|_| "HOST_VM_DOCKER_NETWORK_DELETE_UNCERTAIN_NO_REPLAY")?;
            }
            _ => return Err("HOST_VM_DOCKER_KIND_NOT_EXECUTABLE".into()),
        }
    }
    let now = observe_managed_docker_object(&docker, &plan.spec, false).await?;
    if now.is_some() != plan.create
        || plan.create && now == plan.original_fingerprint
    {
        return Err("HOST_VM_DOCKER_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_managed_docker_scope_rejects_foreign_names() {
        let host = FleetHost {
            machine_id: "application-test".into(), ..Default::default()
        };
        let correct = FleetVmManagedDockerResource {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resource_name: "sb-application-test-net1".into(),
            kind: Kind::BridgeNetwork as i32,
            desired_state: Desired::Present as i32,
        };
        assert!(resource_path_expected(&host, "managed/docker-network-net1.pb", &correct));
        assert!(decode_exact_spec(&host, "managed/docker-network-net1.pb", &correct.encode_to_vec()).is_ok());
        for foreign in [
            "managed/docker-volume-net1.pb",
            "managed/docker-network-../net1.pb",
            "managed/docker-network-another.pb",
            "/etc/docker-network-net1.pb",
        ] {
            assert!(!resource_path_expected(&host, foreign, &correct));
        }
        let mut tampered = correct.clone();
        tampered.resource_name = "other-project-net1".to_owned();
        assert!(!resource_path_expected(&host, "managed/docker-network-net1.pb", &tampered));
        tampered = correct.clone();
        tampered.desired_state = 0;
        assert!(!resource_path_expected(&host, "managed/docker-network-net1.pb", &tampered));
    }
}
