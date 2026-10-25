//! Git-declared Docker volumes and networks via the existing signed
//! HostIntent, protected root journal, exact ReleaseSet and Bollard socket.
//! A runner cannot choose an ID, name, driver, labels or Docker operation.
use super::*;
use edge_shared_types::{
    FleetHost, FleetVmManagedDockerDesiredState as Desired, FleetVmManagedDockerKind as Kind,
    FleetVmManagedDockerResource,
};
use prost::Message;
use std::collections::HashMap;

const LABEL_OWNER: &str = "io.github.iamaman11.singbox.machine";
const LABEL_RESOURCE: &str = "io.github.iamaman11.singbox.resource";

#[derive(Debug)]
pub(super) struct PreparedManagedDocker {
    spec: FleetVmManagedDockerResource,
    previous: Option<FleetVmManagedDockerResource>,
    original_fingerprint: Option<String>,
    effect: ManagedDockerEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedDockerEffect {
    Create,
    Delete,
    Start,
    Stop,
    Restart,
    Replace,
}

fn resource_path_expected(
    host: &FleetHost,
    path: &str,
    spec: &FleetVmManagedDockerResource,
) -> bool {
    let kind_prefix = match Kind::try_from(spec.kind) {
        Ok(Kind::LocalVolume) => "managed/docker-volume-",
        Ok(Kind::BridgeNetwork) => "managed/docker-network-",
        Ok(Kind::Container) => "managed/docker-container-",
        _ => return false,
    };
    let Some(suffix) = path
        .strip_prefix(kind_prefix)
        .and_then(|s| s.strip_suffix(".pb"))
    else {
        return false;
    };
    !suffix.is_empty()
        && suffix.len() <= 40
        && suffix
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && spec.resource_name == format!("sb-{}-{suffix}", host.machine_id)
        && spec.resource_name.len() <= 112
        && spec.machine_id == host.machine_id
        && spec.schema_version == 1
        && matches!(
            Desired::try_from(spec.desired_state),
            Ok(Desired::Present | Desired::Absent | Desired::Stopped)
        )
        && match Kind::try_from(spec.kind) {
            Ok(Kind::Container) => {
                let Some((image, digest)) = spec.image_ref.rsplit_once("@sha256:") else {
                    return false;
                };
                image.len() <= 180
                    && !image.is_empty()
                    && !image.contains("..")
                    && !image.contains("//")
                    && image.bytes().all(|b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'.' | b'-' | b'_' | b'/')
                    })
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && (spec.network_name.is_empty()
                        || (spec
                            .network_name
                            .starts_with(&format!("sb-{}-", host.machine_id))
                            && spec.network_name.len() <= 112))
            }
            Ok(Kind::LocalVolume | Kind::BridgeNetwork) => {
                spec.image_ref.is_empty()
                    && spec.network_name.is_empty()
                    && spec.restart_generation == 0
                    && spec.desired_state != Desired::Stopped as i32
            }
            _ => false,
        }
}

pub(super) fn is_managed_docker_manifest(path: &str) -> bool {
    path.starts_with("managed/docker-volume-")
        || path.starts_with("managed/docker-network-")
        || path.starts_with("managed/docker-container-")
}

pub(super) fn decode_exact_spec(
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
pub(super) async fn observe_managed_docker_object(
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
                let created = volume
                    .created_at
                    .filter(|time| !time.is_empty())
                    .ok_or("HOST_VM_DOCKER_VOLUME_IDENTITY_UNPROVEN")?;
                Ok(Some(created))
            }
            Err(DockerError::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(None),
            Err(_) => Err("HOST_VM_DOCKER_VOLUME_READBACK_UNAVAILABLE".into()),
        },
        Ok(Kind::BridgeNetwork) => match docker.inspect_network(&spec.resource_name, None).await {
            Ok(network) => {
                if network.name.as_deref() != Some(spec.resource_name.as_str())
                    || network.driver.as_deref() != Some("bridge")
                    || network.internal != Some(true)
                    || network.labels.as_ref().and_then(|l| l.get(LABEL_OWNER))
                        != Some(&spec.machine_id)
                    || network.labels.as_ref().and_then(|l| l.get(LABEL_RESOURCE))
                        != Some(&spec.resource_name)
                {
                    return Err("HOST_VM_DOCKER_NETWORK_FOREIGN_OR_DRIVER_DRIFT".into());
                }
                if for_delete && !network.containers.as_ref().is_some_and(HashMap::is_empty) {
                    return Err("HOST_VM_DOCKER_NETWORK_ATTACHED_OR_UNPROVEN".into());
                }
                let id = network
                    .id
                    .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                    .ok_or("HOST_VM_DOCKER_NETWORK_IDENTITY_UNPROVEN")?;
                Ok(Some(id))
            }
            Err(DockerError::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(None),
            Err(_) => Err("HOST_VM_DOCKER_NETWORK_READBACK_UNAVAILABLE".into()),
        },
        Ok(Kind::Container) => match docker.inspect_container(&spec.resource_name, None).await {
            Ok(container) => {
                let config = container
                    .config
                    .as_ref()
                    .ok_or("HOST_VM_DOCKER_CONTAINER_CONFIG_UNPROVEN")?;
                let host_config = container
                    .host_config
                    .as_ref()
                    .ok_or("HOST_VM_DOCKER_CONTAINER_HOSTCONFIG_UNPROVEN")?;
                let expected_net = if spec.network_name.is_empty() {
                    "none"
                } else {
                    spec.network_name.as_str()
                };
                if container.name.as_deref() != Some(format!("/{}", spec.resource_name).as_str())
                    || config.image.as_deref() != Some(spec.image_ref.as_str())
                    || config
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get(LABEL_OWNER))
                        != Some(&spec.machine_id)
                    || config
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get(LABEL_RESOURCE))
                        != Some(&spec.resource_name)
                    || config.user.as_deref() != Some("65534:65534")
                    || host_config.privileged != Some(false)
                    || host_config.readonly_rootfs != Some(true)
                    || host_config.network_mode.as_deref() != Some(expected_net)
                    || host_config
                        .cap_drop
                        .as_ref()
                        .is_none_or(|caps| !caps.iter().any(|cap| cap == "ALL"))
                    || container
                        .mounts
                        .as_ref()
                        .is_some_and(|mounts| !mounts.is_empty())
                {
                    return Err("HOST_VM_DOCKER_CONTAINER_FOREIGN_OR_CONFIG_DRIFT".into());
                }
                let state = container
                    .state
                    .as_ref()
                    .ok_or("HOST_VM_DOCKER_CONTAINER_STATE_UNPROVEN")?;
                let running = state
                    .running
                    .ok_or("HOST_VM_DOCKER_CONTAINER_RUNNING_UNPROVEN")?;
                let id = container
                    .id
                    .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                    .ok_or("HOST_VM_DOCKER_CONTAINER_ID_UNPROVEN")?;
                let started = state.started_at.as_deref().unwrap_or("UNPROVEN");
                if running && started == "UNPROVEN" {
                    return Err("HOST_VM_DOCKER_CONTAINER_STARTED_AT_UNPROVEN".into());
                }
                Ok(Some(format!(
                    "{id}|{}|{started}",
                    if running { "R" } else { "S" }
                )))
            }
            Err(DockerError::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(None),
            Err(_) => Err("HOST_VM_DOCKER_CONTAINER_READBACK_UNAVAILABLE".into()),
        },
        _ => Err("HOST_VM_DOCKER_RESOURCE_KIND_UNSUPPORTED".into()),
    }
}

fn present(spec: &FleetVmManagedDockerResource) -> bool {
    spec.desired_state == Desired::Present as i32
        || (spec.kind == Kind::Container as i32 && spec.desired_state == Desired::Stopped as i32)
}

fn plan_effect(
    previous: Option<&FleetVmManagedDockerResource>,
    next: Option<&FleetVmManagedDockerResource>,
) -> Result<ManagedDockerEffect, String> {
    let was_present = previous.is_some_and(present);
    let now_present = next.is_some_and(present);
    if !was_present && now_present {
        return Ok(ManagedDockerEffect::Create);
    }
    if was_present && !now_present {
        return Ok(ManagedDockerEffect::Delete);
    }
    if !was_present {
        return Err("HOST_VM_DOCKER_NO_RESOURCE_STATE_CHANGE".into());
    }
    let old = previous.ok_or("HOST_VM_DOCKER_PREVIOUS_STATE_MISSING")?;
    let new = next.ok_or("HOST_VM_DOCKER_TARGET_STATE_MISSING")?;
    if old.kind != Kind::Container as i32 {
        return Err("HOST_VM_DOCKER_CONFIG_UPDATE_UNSUPPORTED".into());
    }
    if new.restart_generation != old.restart_generation
        && new.restart_generation != old.restart_generation.saturating_add(1)
    {
        return Err("HOST_VM_DOCKER_RESTART_REVISION_NOT_MONOTONIC".into());
    }
    if old.image_ref != new.image_ref || old.network_name != new.network_name {
        return Ok(ManagedDockerEffect::Replace);
    }
    if old.desired_state != new.desired_state {
        return Ok(if new.desired_state == Desired::Present as i32 {
            ManagedDockerEffect::Start
        } else {
            ManagedDockerEffect::Stop
        });
    }
    if new.restart_generation > old.restart_generation
        && new.desired_state == Desired::Present as i32
    {
        return Ok(ManagedDockerEffect::Restart);
    }
    Err("HOST_VM_DOCKER_NO_RESOURCE_STATE_CHANGE".into())
}

pub(super) async fn preflight_managed_docker_object(
    host: &FleetHost,
    path: &str,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<PreparedManagedDocker, String> {
    let previous = before
        .map(|b| decode_exact_spec(host, path, b))
        .transpose()?;
    let next = after
        .map(|b| decode_exact_spec(host, path, b))
        .transpose()?;
    let spec = next
        .as_ref()
        .or(previous.as_ref())
        .ok_or("HOST_VM_DOCKER_RESOURCE_SCOPE_EMPTY")?;
    if let (Some(a), Some(b)) = (&previous, &next) {
        if a.machine_id != b.machine_id || a.resource_name != b.resource_name || a.kind != b.kind {
            return Err("HOST_VM_DOCKER_RESOURCE_IDENTITY_CHANGE_UNSUPPORTED".into());
        }
    }
    let effect = plan_effect(previous.as_ref(), next.as_ref())?;
    let expected_pre = previous.as_ref().is_some_and(present);
    let docker = super::super::docker_connection().await?;
    let old_spec = previous.as_ref().filter(|_| expected_pre).unwrap_or(spec);
    let physical =
        observe_managed_docker_object(&docker, old_spec, effect == ManagedDockerEffect::Delete)
            .await?;
    if physical.is_some() != expected_pre {
        return Err("HOST_VM_DOCKER_PRESTATE_NOT_CONVERGED".into());
    }
    if let (Some(old), Some(fingerprint)) = (previous.as_ref(), physical.as_deref()) {
        if old.kind == Kind::Container as i32 {
            let running = fingerprint.split('|').nth(1);
            if running
                != Some(if old.desired_state == Desired::Present as i32 {
                    "R"
                } else {
                    "S"
                })
            {
                return Err("HOST_VM_DOCKER_CONTAINER_PRESTATE_RUNNING_DRIFT".into());
            }
        }
    }
    if let Some(target) = next
        .as_ref()
        .filter(|s| s.kind == Kind::Container as i32 && present(s))
    {
        if !target.network_name.is_empty() {
            let network_spec = FleetVmManagedDockerResource {
                schema_version: 1,
                machine_id: host.machine_id.clone(),
                resource_name: target.network_name.clone(),
                kind: Kind::BridgeNetwork as i32,
                desired_state: Desired::Present as i32,
                ..Default::default()
            };
            if observe_managed_docker_object(&docker, &network_spec, false)
                .await?
                .is_none()
            {
                return Err("HOST_VM_DOCKER_CONTAINER_NETWORK_NOT_OWNED".into());
            }
        }
    }
    Ok(PreparedManagedDocker {
        spec: next.unwrap_or_else(|| previous.clone().expect("previous spec")),
        previous,
        original_fingerprint: physical,
        effect,
    })
}

/// One intended remote Docker effect; any failed/uncertain acknowledgement
/// leaves the shared resource journal pending. No retries or compensation.
async fn create_managed_container(
    docker: &bollard::Docker,
    spec: &FleetVmManagedDockerResource,
) -> Result<(), String> {
    // A manifest digest is the only image pull target. The signed BEGIN was
    // persisted BEFORE the pull; no hidden or automatic retry is permitted.
    super::super::pull_native_vm_image_once(docker, &spec.image_ref).await?;
    let network = if spec.network_name.is_empty() {
        "none".to_owned()
    } else {
        spec.network_name.clone()
    };
    let config = bollard::models::ContainerCreateBody {
        image: Some(spec.image_ref.clone()),
        labels: Some(expected_labels(spec)),
        user: Some("65534:65534".into()),
        network_disabled: Some(spec.network_name.is_empty()),
        host_config: Some(bollard::models::HostConfig {
            network_mode: Some(network),
            readonly_rootfs: Some(true),
            privileged: Some(false),
            auto_remove: Some(false),
            cap_drop: Some(vec!["ALL".into()]),
            pids_limit: Some(128),
            memory: Some(512 * 1024 * 1024),
            ..Default::default()
        }),
        ..Default::default()
    };
    docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name(&spec.resource_name)
                    .build(),
            ),
            config,
        )
        .await
        .map_err(|_| "HOST_VM_DOCKER_CONTAINER_CREATE_UNCERTAIN_NO_REPLAY")?;
    if spec.desired_state == Desired::Present as i32 {
        docker
            .start_container(
                &spec.resource_name,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await
            .map_err(|_| "HOST_VM_DOCKER_CONTAINER_START_UNCERTAIN_NO_REPLAY")?;
    }
    Ok(())
}

async fn stop_managed_container(
    docker: &bollard::Docker,
    spec: &FleetVmManagedDockerResource,
) -> Result<(), String> {
    docker
        .stop_container(
            &spec.resource_name,
            Some(
                bollard::query_parameters::StopContainerOptionsBuilder::default()
                    .t(20)
                    .build(),
            ),
        )
        .await
        .map_err(|_| "HOST_VM_DOCKER_CONTAINER_STOP_UNCERTAIN_NO_REPLAY".to_owned())
}

pub(super) async fn apply_managed_docker_object_once(
    plan: &PreparedManagedDocker,
) -> Result<(), String> {
    let docker = super::super::docker_connection().await?;
    let old_spec = plan
        .previous
        .as_ref()
        .filter(|s| present(s))
        .unwrap_or(&plan.spec);
    let actual = observe_managed_docker_object(
        &docker,
        old_spec,
        plan.effect == ManagedDockerEffect::Delete,
    )
    .await?;
    if actual != plan.original_fingerprint {
        return Err("HOST_VM_DOCKER_OBJECT_CAS_CHANGED_NO_REPLAY".into());
    }
    let name = &plan.spec.resource_name;
    match plan.effect {
        ManagedDockerEffect::Create => {
            let labels = expected_labels(&plan.spec);
            match Kind::try_from(plan.spec.kind) {
                Ok(Kind::LocalVolume) => {
                    docker
                        .create_volume(bollard::models::VolumeCreateRequest {
                            name: Some(name.clone()),
                            driver: Some("local".to_owned()),
                            labels: Some(labels),
                            ..Default::default()
                        })
                        .await
                        .map_err(|_| "HOST_VM_DOCKER_VOLUME_CREATE_UNCERTAIN_NO_REPLAY")?;
                }
                Ok(Kind::BridgeNetwork) => {
                    docker
                        .create_network(bollard::models::NetworkCreateRequest {
                            name: name.clone(),
                            driver: Some("bridge".to_owned()),
                            internal: Some(true),
                            attachable: Some(false),
                            labels: Some(labels),
                            ..Default::default()
                        })
                        .await
                        .map_err(|_| "HOST_VM_DOCKER_NETWORK_CREATE_UNCERTAIN_NO_REPLAY")?;
                }
                Ok(Kind::Container) => create_managed_container(&docker, &plan.spec).await?,
                _ => return Err("HOST_VM_DOCKER_KIND_NOT_EXECUTABLE".into()),
            }
        }
        ManagedDockerEffect::Delete => match Kind::try_from(plan.spec.kind) {
            Ok(Kind::LocalVolume) => {
                docker
                    .remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>)
                    .await
                    .map_err(|_| "HOST_VM_DOCKER_VOLUME_DELETE_UNCERTAIN_NO_REPLAY")?;
            }
            Ok(Kind::BridgeNetwork) => {
                docker
                    .remove_network(name)
                    .await
                    .map_err(|_| "HOST_VM_DOCKER_NETWORK_DELETE_UNCERTAIN_NO_REPLAY")?;
            }
            Ok(Kind::Container) => {
                if let Some(old) = plan.previous.as_ref()
                    && old.desired_state == Desired::Present as i32
                {
                    stop_managed_container(&docker, old).await?;
                }
                docker
                    .remove_container(
                        name,
                        None::<bollard::query_parameters::RemoveContainerOptions>,
                    )
                    .await
                    .map_err(|_| "HOST_VM_DOCKER_CONTAINER_DELETE_UNCERTAIN_NO_REPLAY")?;
            }
            _ => return Err("HOST_VM_DOCKER_KIND_NOT_EXECUTABLE".into()),
        },
        ManagedDockerEffect::Start => {
            docker
                .start_container(
                    name,
                    None::<bollard::query_parameters::StartContainerOptions>,
                )
                .await
                .map_err(|_| "HOST_VM_DOCKER_CONTAINER_START_UNCERTAIN_NO_REPLAY")?;
        }
        ManagedDockerEffect::Stop => stop_managed_container(&docker, &plan.spec).await?,
        ManagedDockerEffect::Restart => {
            docker
                .restart_container(
                    name,
                    Some(
                        bollard::query_parameters::RestartContainerOptionsBuilder::default()
                            .t(20)
                            .build(),
                    ),
                )
                .await
                .map_err(|_| "HOST_VM_DOCKER_CONTAINER_RESTART_UNCERTAIN_NO_REPLAY")?;
        }
        ManagedDockerEffect::Replace => {
            if let Some(old) = plan.previous.as_ref()
                && old.desired_state == Desired::Present as i32
            {
                stop_managed_container(&docker, old).await?;
            }
            docker
                .remove_container(
                    name,
                    None::<bollard::query_parameters::RemoveContainerOptions>,
                )
                .await
                .map_err(|_| "HOST_VM_DOCKER_CONTAINER_REPLACE_DELETE_UNCERTAIN_NO_REPLAY")?;
            create_managed_container(&docker, &plan.spec).await?;
        }
    }
    // An ACK alone is never terminal success. Verify exact owner, image,
    // desired running state and identity after a second independent inspect.
    let now = observe_managed_docker_object(&docker, &plan.spec, false).await?;
    let should_exist = match plan.effect {
        ManagedDockerEffect::Delete => false,
        _ => true,
    };
    if now.is_some() != should_exist {
        return Err("HOST_VM_DOCKER_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    if plan.spec.kind == Kind::Container as i32 && should_exist {
        let fingerprint = now
            .as_deref()
            .ok_or("HOST_VM_DOCKER_CONTAINER_POSTSTATE_MISSING")?;
        let running = fingerprint.split('|').nth(1);
        let expected = if plan.spec.desired_state == Desired::Present as i32 {
            "R"
        } else {
            "S"
        };
        if running != Some(expected) {
            return Err("HOST_VM_DOCKER_CONTAINER_RUNNING_POSTSTATE_UNPROVEN_NO_REPLAY".into());
        }
        if matches!(
            plan.effect,
            ManagedDockerEffect::Create | ManagedDockerEffect::Replace
        ) && now == plan.original_fingerprint
        {
            return Err("HOST_VM_DOCKER_CONTAINER_NOT_RECREATED_NO_REPLAY".into());
        }
        if plan.effect == ManagedDockerEffect::Restart && now == plan.original_fingerprint {
            return Err("HOST_VM_DOCKER_CONTAINER_RESTART_POSTSTATE_UNPROVEN_NO_REPLAY".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn container_lifecycle_is_typed_and_restart_requires_monotone_generation() {
        let mut old = FleetVmManagedDockerResource {
            schema_version: 1,
            kind: Kind::Container as i32,
            desired_state: Desired::Present as i32,
            image_ref: "ghcr.io/iamaman11/test@sha256:".to_owned() + &"a".repeat(64),
            ..Default::default()
        };
        assert_eq!(
            plan_effect(None, Some(&old)).unwrap(),
            ManagedDockerEffect::Create
        );
        let mut next = old.clone();
        next.desired_state = Desired::Stopped as i32;
        assert_eq!(
            plan_effect(Some(&old), Some(&next)).unwrap(),
            ManagedDockerEffect::Stop
        );
        next.desired_state = Desired::Present as i32;
        next.restart_generation = 1;
        assert_eq!(
            plan_effect(Some(&old), Some(&next)).unwrap(),
            ManagedDockerEffect::Restart
        );
        old.restart_generation = 2;
        assert!(plan_effect(Some(&old), Some(&next)).is_err());
        assert_eq!(
            plan_effect(Some(&old), None).unwrap(),
            ManagedDockerEffect::Delete
        );
    }

    #[test]
    fn exact_managed_docker_scope_rejects_foreign_names() {
        let host = FleetHost {
            machine_id: "application-test".into(),
            ..Default::default()
        };
        let correct = FleetVmManagedDockerResource {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resource_name: "sb-application-test-net1".into(),
            kind: Kind::BridgeNetwork as i32,
            desired_state: Desired::Present as i32,
            ..Default::default()
        };
        assert!(resource_path_expected(
            &host,
            "managed/docker-network-net1.pb",
            &correct
        ));
        assert!(
            decode_exact_spec(
                &host,
                "managed/docker-network-net1.pb",
                &correct.encode_to_vec()
            )
            .is_ok()
        );
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
        assert!(!resource_path_expected(
            &host,
            "managed/docker-network-net1.pb",
            &tampered
        ));
        tampered = correct.clone();
        tampered.desired_state = 0;
        assert!(!resource_path_expected(
            &host,
            "managed/docker-network-net1.pb",
            &tampered
        ));
    }
}
