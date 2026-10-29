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
use std::net::Ipv6Addr;

const LABEL_OWNER: &str = "io.github.iamaman11.singbox.machine";
const LABEL_RESOURCE: &str = "io.github.iamaman11.singbox.resource";

#[derive(Debug)]
pub(super) struct PreparedManagedDocker {
    spec: FleetVmManagedDockerResource,
    previous: Option<FleetVmManagedDockerResource>,
    original_fingerprint: Option<String>,
    // Never allow a pre-existing container to keep a reused or foreign
    // network name, including on stop/delete/replace operations.
    original_network_fingerprint: Option<String>,
    // The exact labeled Docker network ID admitted before BEGIN.
    target_network_fingerprint: Option<String>,
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

/// Only an exact host-owned private network may be referenced by a managed
/// container. An attacker-controlled "sb-host-..." prefix is not sufficient.
fn exact_owned_network_name(machine_id: &str, name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(&format!("sb-{machine_id}-")) else {
        return false;
    };
    !suffix.is_empty()
        && suffix.len() <= 40
        && suffix
            .bytes()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && suffix
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
        && !suffix.ends_with('-')
}

// Docker IPv6 is opt-in and only a canonical ULA /64 is supported.
// A resource cannot implicitly adopt a global prefix or foreign gateway.
fn canonical_private_ipv6_ipam(spec: &FleetVmManagedDockerResource) -> bool {
    if spec.ipv6_subnet.is_empty() && spec.ipv6_gateway.is_empty() {
        return true;
    }
    let Some(prefix) = spec.ipv6_subnet.strip_suffix("/64") else {
        return false;
    };
    let (Ok(subnet), Ok(gateway)) =
        (prefix.parse::<Ipv6Addr>(), spec.ipv6_gateway.parse::<Ipv6Addr>())
    else {
        return false;
    };
    let network = u128::from(subnet);
    let next_hop = u128::from(gateway);
    let mask = u128::MAX << 64;
    subnet.to_string() == prefix
        && gateway.to_string() == spec.ipv6_gateway
        && subnet.octets()[0] == 0xfd
        && network & !mask == 0
        && next_hop & mask == network
        && next_hop != network
}

// The resource's own manifest enforces exact IPAM. Container references
// independently require the correct owner-labelled network ID, not the
// network configuration, which is verified by its own managed resource.
fn exact_network_ipv6_ipam(
    spec: &FleetVmManagedDockerResource,
    enabled: Option<bool>,
    ipam: Option<&bollard::models::Ipam>,
) -> bool {
    let desired = !spec.ipv6_subnet.is_empty();
    if !canonical_private_ipv6_ipam(spec) || enabled.unwrap_or(false) != desired {
        return false;
    }
    let ipv6 = ipam
        .and_then(|value| value.config.as_ref())
        .into_iter()
        .flatten()
        .filter(|entry| entry.subnet.as_deref().is_some_and(|subnet| subnet.contains(':')))
        .collect::<Vec<_>>();
    if !desired {
        return ipv6.is_empty();
    }
    ipv6.len() == 1
        && ipv6[0].subnet.as_deref() == Some(spec.ipv6_subnet.as_str())
        && ipv6[0].gateway.as_deref() == Some(spec.ipv6_gateway.as_str())
        && ipv6[0].ip_range.as_deref().unwrap_or("").is_empty()
        && ipv6[0].auxiliary_addresses.as_ref().is_none_or(HashMap::is_empty)
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
                    && !digest.bytes().all(|b| b == b'0')
                    && spec.ipv6_subnet.is_empty()
                    && spec.ipv6_gateway.is_empty()
                    && (spec.network_name.is_empty()
                        || exact_owned_network_name(&host.machine_id, &spec.network_name))
            }
            Ok(Kind::LocalVolume) => {
                spec.image_ref.is_empty()
                    && spec.network_name.is_empty()
                    && spec.restart_generation == 0
                    && spec.desired_state != Desired::Stopped as i32
                    && spec.ipv6_subnet.is_empty()
                    && spec.ipv6_gateway.is_empty()
            }
            Ok(Kind::BridgeNetwork) => {
                spec.image_ref.is_empty()
                    && spec.network_name.is_empty()
                    && spec.restart_generation == 0
                    && spec.desired_state != Desired::Stopped as i32
                    && canonical_private_ipv6_ipam(spec)
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

pub(super) fn managed_network_spec(machine: &str, name: &str) -> FleetVmManagedDockerResource {
    FleetVmManagedDockerResource {
        schema_version: 1,
        machine_id: machine.to_owned(),
        resource_name: name.to_owned(),
        kind: Kind::BridgeNetwork as i32,
        desired_state: Desired::Present as i32,
        ..Default::default()
    }
}

fn exact_network_cas(expected: Option<&str>, current: Option<&str>) -> Result<(), &'static str> {
    if expected.is_some() && expected != current {
        return Err("HOST_VM_DOCKER_CONTAINER_NETWORK_CAS_CHANGED_NO_REPLAY");
    }
    Ok(())
}

// Docker allows a container to be attached to extra networks after its
// creation. HostConfig.network_mode alone does NOT prove the live graph.
fn exact_attached_networks<'a>(
    expected: &str,
    names: impl IntoIterator<Item = &'a str>,
) -> bool {
    let names = names.into_iter().collect::<Vec<_>>();
    if expected == "none" {
        names.is_empty() || names == ["none"]
    } else {
        names == [expected]
    }
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
    check_ipam: bool,
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
                    || (check_ipam
                        && !exact_network_ipv6_ipam(
                            spec,
                            network.enable_ipv6,
                            network.ipam.as_ref(),
                        ))
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
                    || host_config.auto_remove != Some(false)
                    || host_config.pids_limit != Some(128)
                    || host_config.memory != Some(512 * 1024 * 1024)
                    || host_config
                        .cap_add
                        .as_ref()
                        .is_some_and(|caps| !caps.is_empty())
                    || !exact_attached_networks(
                        expected_net,
                        container
                            .network_settings
                            .as_ref()
                            .and_then(|settings| settings.networks.as_ref())
                            .into_iter()
                            .flat_map(|networks| networks.keys().map(String::as_str)),
                    )
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
        observe_managed_docker_object(&docker, old_spec, effect == ManagedDockerEffect::Delete, true)
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
    let original_network_fingerprint = if let Some(old) = previous
        .as_ref()
        .filter(|s| s.kind == Kind::Container as i32 && present(s) && !s.network_name.is_empty())
    {
        let network_spec = managed_network_spec(&old.machine_id, &old.network_name);
        Some(
            observe_managed_docker_object(&docker, &network_spec, false, false)
                .await?
                .ok_or("HOST_VM_DOCKER_CONTAINER_PREVIOUS_NETWORK_NOT_OWNED")?,
        )
    } else {
        None
    };
    let target_network_fingerprint = if let Some(target) = next
        .as_ref()
        .filter(|s| s.kind == Kind::Container as i32 && present(s))
    {
        if target.network_name.is_empty() {
            None
        } else {
            let network_spec = managed_network_spec(&target.machine_id, &target.network_name);
            Some(
                observe_managed_docker_object(&docker, &network_spec, false, false)
                    .await?
                    .ok_or("HOST_VM_DOCKER_CONTAINER_NETWORK_NOT_OWNED")?,
            )
        }
    } else {
        None
    };
    Ok(PreparedManagedDocker {
        spec: next.unwrap_or_else(|| previous.clone().expect("previous spec")),
        previous,
        original_fingerprint: physical,
        original_network_fingerprint,
        target_network_fingerprint,
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
    let docker = super::super::docker_effect_connection().await?;
    let old_spec = plan
        .previous
        .as_ref()
        .filter(|s| present(s))
        .unwrap_or(&plan.spec);
    let actual = observe_managed_docker_object(
        &docker,
        old_spec,
        plan.effect == ManagedDockerEffect::Delete,
        true,
    )
    .await?;
    if actual != plan.original_fingerprint {
        return Err("HOST_VM_DOCKER_OBJECT_CAS_CHANGED_NO_REPLAY".into());
    }
    // Re-attest both the existing network and the target before any Docker
    // effect.  A swapped old bridge is not safe merely because the next
    // configuration wants a different bridge (or removes the container).
    if let Some(expected) = plan.original_network_fingerprint.as_deref() {
        let old = plan
            .previous
            .as_ref()
            .ok_or("HOST_VM_DOCKER_PREVIOUS_NETWORK_SPEC_MISSING_NO_REPLAY")?;
        let spec = managed_network_spec(&old.machine_id, &old.network_name);
        let observed = observe_managed_docker_object(&docker, &spec, false, false).await?;
        exact_network_cas(Some(expected), observed.as_deref()).map_err(str::to_owned)?;
    }
    // Re-attest network ID/labels after journal BEGIN, before any Docker
    // effect. A name reused by a foreign network must never be adopted.
    if let Some(expected) = plan.target_network_fingerprint.as_deref() {
        let spec = managed_network_spec(&plan.spec.machine_id, &plan.spec.network_name);
        let observed = observe_managed_docker_object(&docker, &spec, false, false).await?;
        exact_network_cas(Some(expected), observed.as_deref()).map_err(str::to_owned)?;
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
                    let ipam = if plan.spec.ipv6_subnet.is_empty() {
                        None
                    } else {
                        Some(bollard::models::Ipam {
                            driver: Some("default".into()),
                            config: Some(vec![bollard::models::IpamConfig {
                                subnet: Some(plan.spec.ipv6_subnet.clone()),
                                gateway: Some(plan.spec.ipv6_gateway.clone()),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        })
                    };
                    docker
                        .create_network(bollard::models::NetworkCreateRequest {
                            name: name.clone(),
                            driver: Some("bridge".to_owned()),
                            internal: Some(true),
                            attachable: Some(false),
                            enable_ipv6: Some(ipam.is_some()),
                            ipam,
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
    let now = observe_managed_docker_object(&docker, &plan.spec, false, true).await?;
    let should_exist = match plan.effect {
        ManagedDockerEffect::Delete => false,
        _ => true,
    };
    if now.is_some() != should_exist {
        return Err("HOST_VM_DOCKER_POSTSTATE_UNPROVEN_NO_REPLAY".into());
    }
    if let Some(expected) = plan.target_network_fingerprint.as_deref() {
        let spec = managed_network_spec(&plan.spec.machine_id, &plan.spec.network_name);
        let observed = observe_managed_docker_object(&docker, &spec, false, false).await?;
        exact_network_cas(Some(expected), observed.as_deref()).map_err(str::to_owned)?;
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
    fn private_bridge_ipv6_ipam_is_exact_and_fail_closed() {
        let mut spec = FleetVmManagedDockerResource {
            ipv6_subnet: "fd45:1234:abcd::/64".into(),
            ipv6_gateway: "fd45:1234:abcd::1".into(),
            ..Default::default()
        };
        assert!(canonical_private_ipv6_ipam(&spec));
        let ipam = bollard::models::Ipam {
            config: Some(vec![bollard::models::IpamConfig {
                subnet: Some(spec.ipv6_subnet.clone()),
                gateway: Some(spec.ipv6_gateway.clone()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert!(exact_network_ipv6_ipam(&spec, Some(true), Some(&ipam)));
        assert!(!exact_network_ipv6_ipam(&spec, Some(false), Some(&ipam)));
        for (subnet, gateway) in [
            ("2001:db8::/64", "2001:db8::1"),
            ("2001:4860::/64", "2001:4860::1"),
            ("fe80::/64", "fe80::1"),
            ("fd45:1234:abcd::1/64", "fd45:1234:abcd::2"),
            ("fd45:1234:abcd::/48", "fd45:1234:abcd::1"),
            ("fd45:1234:abcd::/64", "fd45:1234:abce::1"),
            ("fd45:1234:abcd::/64", "fd45:1234:abcd::"),
            ("fd45:1234:abcd::/64", ""),
        ] {
            spec.ipv6_subnet = subnet.into();
            spec.ipv6_gateway = gateway.into();
            assert!(!canonical_private_ipv6_ipam(&spec), "{subnet} {gateway}");
        }
        spec.ipv6_subnet.clear();
        spec.ipv6_gateway.clear();
        assert!(canonical_private_ipv6_ipam(&spec));
        assert!(exact_network_ipv6_ipam(&spec, Some(false), None));
        assert!(!exact_network_ipv6_ipam(&spec, Some(true), None));
    }

    #[test]
    fn container_live_network_graph_rejects_foreign_extra_attachments() {
        assert!(exact_attached_networks("sb-vm-test-private", ["sb-vm-test-private"]));
        assert!(!exact_attached_networks(
            "sb-vm-test-private",
            ["sb-vm-test-private", "bridge"],
        ));
        assert!(!exact_attached_networks(
            "sb-vm-test-private",
            ["bridge"],
        ));
        assert!(!exact_attached_networks("sb-vm-test-private", Vec::<&str>::new()));
        assert!(exact_attached_networks("none", Vec::<&str>::new()));
        assert!(exact_attached_networks("none", ["none"]));
        assert!(!exact_attached_networks("none", ["bridge"]));
    }

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
    fn owned_network_id_cannot_change_between_prebegin_and_poststate() {
        assert!(exact_network_cas(None, None).is_ok());
        assert!(exact_network_cas(Some("network-id-a"), Some("network-id-a")).is_ok());
        assert!(exact_network_cas(Some("network-id-a"), None).is_err());
        assert!(exact_network_cas(Some("network-id-a"), Some("network-id-b")).is_err());
        let scoped = managed_network_spec("application-test", "sb-application-test-internal");
        assert_eq!(scoped.machine_id, "application-test");
        assert_eq!(scoped.resource_name, "sb-application-test-internal");
        assert_eq!(scoped.kind, Kind::BridgeNetwork as i32);
    }

    #[test]
    fn container_network_requires_exact_owned_canonical_name() {
        let host = FleetHost {
            machine_id: "application-test".into(),
            ..Default::default()
        };
        let mut container = FleetVmManagedDockerResource {
            schema_version: 1,
            machine_id: host.machine_id.clone(),
            resource_name: "sb-application-test-worker1".into(),
            kind: Kind::Container as i32,
            desired_state: Desired::Present as i32,
            image_ref: "ghcr.io/iamaman11/test@sha256:".to_owned() + &"a".repeat(64),
            network_name: "sb-application-test-internal".into(),
            ..Default::default()
        };
        let path = "managed/docker-container-worker1.pb";
        assert!(resource_path_expected(&host, path, &container));
        assert!(decode_exact_spec(&host, path, &container.encode_to_vec()).is_ok());
        for bad in [
            "sb-application-test-",
            "sb-application-test-.",
            "sb-application-test-../external",
            "sb-application-test-network_name",
            "sb-application-test-contains space",
            "sb-foreign-internal",
            "sb-application-test-12345678901234567890123456789012345678901",
            "sb-application-test-internal-",
        ] {
            container.network_name = bad.into();
            assert!(!resource_path_expected(&host, path, &container), "{bad}");
        }
        container.network_name.clear();
        assert!(resource_path_expected(&host, path, &container));
        container.image_ref = "ghcr.io/iamaman11/test@sha256:".to_owned() + &"0".repeat(64);
        assert!(!resource_path_expected(&host, path, &container));
    }

    #[test]
    fn managed_docker_noops_or_resource_identity_churn_cannot_become_effect() {
        let base = FleetVmManagedDockerResource {
            schema_version: 1,
            kind: Kind::Container as i32,
            desired_state: Desired::Present as i32,
            image_ref: "ghcr.io/iamaman11/test@sha256:".to_owned() + &"a".repeat(64),
            ..Default::default()
        };
        assert!(plan_effect(Some(&base), Some(&base)).is_err());
        let mut invalid = base.clone();
        invalid.restart_generation = 3;
        assert!(plan_effect(Some(&base), Some(&invalid)).is_err());
        invalid.restart_generation = 1;
        assert_eq!(
            plan_effect(Some(&base), Some(&invalid)).unwrap(),
            ManagedDockerEffect::Restart
        );
        invalid.image_ref = "ghcr.io/iamaman11/test@sha256:".to_owned() + &"b".repeat(64);
        assert_eq!(
            plan_effect(Some(&base), Some(&invalid)).unwrap(),
            ManagedDockerEffect::Replace
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
