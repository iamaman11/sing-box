use edge_controller_core::orchestration::{
    DerivedDnsTarget, DerivedMeshRoute, MachineObservation, ReleaseContext,
    SupportAccessLeaseState, VpcObservation, derive_dns_target, derive_mesh_route,
};
use ring::digest::{Context as DigestContext, SHA256};
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct OrchestrationContext {
    release: ReleaseContext,
}

impl OrchestrationContext {
    pub fn new(release: ReleaseContext) -> Result<Self, String> {
        release.validate()?;
        Ok(Self { release })
    }

    pub fn from_process_env() -> Result<Self, String> {
        let context_path = env::var_os("EDGE_RELEASE_CONTEXT_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| {
                "EDGE_RELEASE_CONTEXT_PATH is required for edge-orchestrator".to_owned()
            })?;
        let expected_accepted_revision = env::var("GITHUB_SHA").ok();
        let executable = env::current_exe().map_err(|err| {
            format!("failed to resolve current edge-orchestrator executable: {err}")
        })?;
        Self::from_resolved_env_file(
            &context_path,
            expected_accepted_revision.as_deref(),
            &executable,
        )
    }

    pub fn from_resolved_env_file(
        path: &Path,
        expected_accepted_revision: Option<&str>,
        executable: &Path,
    ) -> Result<Self, String> {
        let values = parse_resolved_env(path)?;
        let accepted_revision = required(&values, "EDGE_ACCEPTED_REVISION")?;
        let source_revision = required(&values, "EDGE_CANDIDATE_REVISION")?;
        let release_set_sha256 = required(&values, "EDGE_RELEASE_SET_SHA256")?;
        let release_tag = required(&values, "EDGE_RELEASE_TAG")?;
        let expected_tag = format!("edge-release-{release_set_sha256}");
        if release_tag != expected_tag {
            return Err(format!(
                "release context tag mismatch: expected {expected_tag}, got {release_tag}"
            ));
        }
        if let Some(expected) = expected_accepted_revision {
            if accepted_revision != expected {
                return Err(format!(
                    "release context accepted revision mismatch: expected {expected}, got {accepted_revision}"
                ));
            }
        }

        let release = ReleaseContext {
            accepted_revision: accepted_revision.to_owned(),
            source_revision: source_revision.to_owned(),
            release_set_sha256: release_set_sha256.to_owned(),
            orchestrator_sha256: required(&values, "EDGE_ORCHESTRATOR_SHA256")?.to_owned(),
            agent_sha256: required(&values, "EDGE_AGENT_SHA256")?.to_owned(),
            docker_engine_version: required(&values, "EDGE_DOCKER_ENGINE_VERSION")?.to_owned(),
            containerd_version: required(&values, "EDGE_CONTAINERD_VERSION")?.to_owned(),
            compose_version: required(&values, "EDGE_COMPOSE_VERSION")?.to_owned(),
            gateway_image: required(&values, "EDGE_GATEWAY_IMAGE")?.to_owned(),
            warp_egress_image: required(&values, "EDGE_WARP_EGRESS_IMAGE")?.to_owned(),
            mesh_image: required(&values, "EDGE_MESH_IMAGE")?.to_owned(),
        };
        release.validate()?;

        let executable_sha = sha256_file(executable)?;
        if executable_sha != release.orchestrator_sha256 {
            return Err(format!(
                "edge-orchestrator executable SHA-256 mismatch: expected {}, got {executable_sha}",
                release.orchestrator_sha256
            ));
        }

        Ok(Self { release })
    }

    pub const fn release(&self) -> &ReleaseContext {
        &self.release
    }

    pub fn derive_dns_target(
        &self,
        observation: &MachineObservation,
    ) -> Result<DerivedDnsTarget, String> {
        derive_dns_target(observation)
    }

    pub fn derive_mesh_route(
        &self,
        observation: &VpcObservation,
    ) -> Result<DerivedMeshRoute, String> {
        derive_mesh_route(observation)
    }

    pub fn begin_support_access_lease(&self) -> SupportAccessLeaseState {
        SupportAccessLeaseState::default()
    }
}

fn parse_resolved_env(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read release context {}: {err}", path.display()))?;
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "invalid release context line {} in {}",
                index + 1,
                path.display()
            )
        })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid release context key {key:?}"));
        }
        if value.is_empty() {
            return Err(format!("release context value {key} must be non-empty"));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate release context key {key}"));
        }
    }
    Ok(values)
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("release context is missing {key}"))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut context = DigestContext::new(&SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn release() -> ReleaseContext {
        ReleaseContext {
            accepted_revision: "f".repeat(40),
            source_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
            orchestrator_sha256: "1".repeat(64),
            agent_sha256: "2".repeat(64),
            docker_engine_version: "5:28.4.0-1~debian.13~trixie".to_owned(),
            containerd_version: "1.7.27-1".to_owned(),
            compose_version: "2.39.4-1~debian.13~trixie".to_owned(),
            gateway_image: format!("ghcr.io/example/gateway@sha256:{}", "c".repeat(64)),
            warp_egress_image: format!("ghcr.io/example/warp@sha256:{}", "d".repeat(64)),
            mesh_image: format!("docker.io/cloudflare/mesh@sha256:{}", "e".repeat(64)),
        }
    }

    #[test]
    fn context_refuses_mutable_release_identity() {
        let mut release = release();
        release.gateway_image = "ghcr.io/example/gateway:latest".to_owned();
        assert!(OrchestrationContext::new(release).is_err());
    }

    #[test]
    fn one_context_derives_dns_and_mesh_from_observations() {
        let context = OrchestrationContext::new(release()).unwrap();

        let dns = context
            .derive_dns_target(&MachineObservation {
                provider_id: "vm-1".to_owned(),
                main_ipv4: "203.0.113.10".to_owned(),
            })
            .unwrap();
        let mesh = context
            .derive_mesh_route(&VpcObservation {
                provider_id: "vpc-1".to_owned(),
                cidr: "10.27.96.0/20".to_owned(),
                private_ipv4: "10.27.96.3".to_owned(),
            })
            .unwrap();

        assert_eq!(dns.target_ipv4, "203.0.113.10");
        assert_eq!(mesh.network, "10.27.96.0/20");
    }

    #[test]
    fn resolved_context_binds_exact_executable_and_accepted_revision() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("edge-orchestrator-context-{unique}"));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("edge-orchestrator");
        fs::write(&executable, b"exact-orchestrator").unwrap();
        let executable_sha = sha256_file(&executable).unwrap();
        let release_set_sha = "b".repeat(64);
        let accepted = "f".repeat(40);
        let context = root.join("resolved.env");
        fs::write(
            &context,
            format!(
                "EDGE_ACCEPTED_REVISION={accepted}\n\
EDGE_CANDIDATE_REVISION={}\n\
EDGE_SOURCE_TREE={}\n\
EDGE_RELEASE_ID=1\n\
EDGE_RELEASE_TAG=edge-release-{release_set_sha}\n\
EDGE_RELEASE_SET_SHA256={release_set_sha}\n\
EDGE_CONTROLLER_SHA256={}\n\
EDGE_ORCHESTRATOR_SHA256={executable_sha}\n\
EDGE_AGENT_SHA256={}\n\
EDGE_GATEWAY_IMAGE=ghcr.io/example/gateway@sha256:{}\n\
EDGE_WARP_EGRESS_IMAGE=ghcr.io/example/warp@sha256:{}\n\
EDGE_MESH_IMAGE=docker.io/cloudflare/mesh@sha256:{}\n\
EDGE_DOCKER_ENGINE_VERSION=5:28.4.0-1~debian.13~trixie\n\
EDGE_CONTAINERD_VERSION=1.7.27-1\n\
EDGE_COMPOSE_VERSION=2.39.4-1~debian.13~trixie\n",
                "a".repeat(40),
                "3".repeat(40),
                "4".repeat(64),
                "2".repeat(64),
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
            ),
        )
        .unwrap();

        let loaded =
            OrchestrationContext::from_resolved_env_file(&context, Some(&accepted), &executable)
                .unwrap();
        assert_eq!(loaded.release().orchestrator_sha256, executable_sha);

        let wrong_accepted = "0".repeat(40);
        assert!(
            OrchestrationContext::from_resolved_env_file(
                &context,
                Some(&wrong_accepted),
                &executable
            )
            .is_err()
        );

        fs::write(&executable, b"tampered").unwrap();
        assert!(
            OrchestrationContext::from_resolved_env_file(&context, Some(&accepted), &executable)
                .is_err()
        );
    }
}
