use edge_controller_core::application_lifecycle::AgentArtifactManifest;
use edge_controller_core::orchestration::{
    DerivedDnsTarget, DerivedMeshRoute, MachineObservation, ReleaseContext,
    SupportAccessLeaseState, VpcObservation, derive_dns_target, derive_mesh_route,
};
use edge_shared_types::RELEASE_SET_SCHEMA_VERSION;
use ring::digest::{Context as DigestContext, SHA256};
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationReleaseAuthority {
    pub schema_version: u32,
    pub runtime_source_revision: String,
    pub runtime_input_sha256: String,
}

#[derive(Debug, Clone)]
pub struct OrchestrationContext {
    release: ReleaseContext,
    application_release: Option<ApplicationReleaseAuthority>,
}

impl OrchestrationContext {
    pub fn new(release: ReleaseContext) -> Result<Self, String> {
        release.validate()?;
        Ok(Self {
            release,
            application_release: None,
        })
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

        let schema_version = required(&values, "EDGE_RELEASE_SCHEMA_VERSION")?
            .parse::<u32>()
            .map_err(|_| "EDGE_RELEASE_SCHEMA_VERSION must be an unsigned integer".to_owned())?;
        if schema_version != RELEASE_SET_SCHEMA_VERSION {
            return Err(format!(
                "application release context requires ReleaseSet schema {}, got {schema_version}",
                RELEASE_SET_SCHEMA_VERSION
            ));
        }
        let application_release = ApplicationReleaseAuthority {
            schema_version,
            runtime_source_revision: required(&values, "EDGE_RUNTIME_SOURCE_REVISION")?.to_owned(),
            runtime_input_sha256: required(&values, "EDGE_RUNTIME_INPUT_SHA256")?.to_owned(),
        };
        validate_lower_hex(
            "EDGE_RUNTIME_SOURCE_REVISION",
            &application_release.runtime_source_revision,
            40,
        )?;
        validate_lower_hex(
            "EDGE_RUNTIME_INPUT_SHA256",
            &application_release.runtime_input_sha256,
            64,
        )?;

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

        Ok(Self {
            release,
            application_release: Some(application_release),
        })
    }

    pub const fn release(&self) -> &ReleaseContext {
        &self.release
    }

    pub fn application_release_authority(&self) -> Result<&ApplicationReleaseAuthority, String> {
        self.application_release.as_ref().ok_or_else(|| {
            "application release authority is unavailable; use a verified durable release context"
                .to_owned()
        })
    }

    pub fn expected_application_artifact(&self) -> Result<AgentArtifactManifest, String> {
        let authority = self.application_release_authority()?;
        Ok(AgentArtifactManifest {
            schema: 1,
            source_revision: authority.runtime_source_revision.clone(),
            sha256: self.release.agent_sha256.clone(),
        })
    }

    pub fn validate_application_artifact(
        &self,
        manifest: &AgentArtifactManifest,
        artifact_path: &Path,
    ) -> Result<(), String> {
        let expected = self.expected_application_artifact()?;
        if manifest != &expected {
            return Err(format!(
                "application artifact authority mismatch: expected source_revision={} sha256={}, got source_revision={} sha256={}",
                expected.source_revision,
                expected.sha256,
                manifest.source_revision,
                manifest.sha256
            ));
        }
        let actual = sha256_file(artifact_path)?;
        if actual != expected.sha256 {
            return Err(format!(
                "application edge-agent SHA-256 mismatch: expected {}, got {actual}",
                expected.sha256
            ));
        }
        Ok(())
    }

    pub fn expected_application_image_environment(&self) -> Result<String, String> {
        self.application_release_authority()?;
        Ok(format!(
            "EDGE_GATEWAY_IMAGE={}\nEDGE_WARP_EGRESS_IMAGE={}\nCLOUDFLARE_MESH_IMAGE={}\n",
            self.release.gateway_image, self.release.warp_egress_image, self.release.mesh_image
        ))
    }

    pub fn validate_application_image_environment(&self, bundle_root: &Path) -> Result<(), String> {
        let path = bundle_root.join(".images.env");
        let actual = std::fs::read_to_string(&path).map_err(|err| {
            format!(
                "failed to read exact application image environment {}: {err}",
                path.display()
            )
        })?;
        let expected = self.expected_application_image_environment()?;
        if actual != expected {
            return Err(
                "application image environment does not match exact durable ReleaseSet authority"
                    .to_owned(),
            );
        }
        Ok(())
    }

    pub fn materialize_application_inputs(
        &self,
        bundle_root: &Path,
        artifact_manifest_path: &Path,
        artifact_path: &Path,
    ) -> Result<(), String> {
        if !bundle_root.is_dir() {
            return Err(format!(
                "application bundle root is missing: {}",
                bundle_root.display()
            ));
        }

        let manifest = self.expected_application_artifact()?;
        self.validate_application_artifact(&manifest, artifact_path)?;

        let image_environment = self.expected_application_image_environment()?;
        std::fs::write(bundle_root.join(".images.env"), image_environment)
            .map_err(|err| format!("failed to materialize exact application images: {err}"))?;
        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|err| format!("failed to serialize application artifact authority: {err}"))?;
        std::fs::write(artifact_manifest_path, manifest_json).map_err(|err| {
            format!(
                "failed to materialize application artifact authority {}: {err}",
                artifact_manifest_path.display()
            )
        })?;
        Ok(())
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
EDGE_RELEASE_SCHEMA_VERSION=5\n\
EDGE_RUNTIME_SOURCE_REVISION={}\n\
EDGE_RUNTIME_INPUT_SHA256={}\n\
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
                "5".repeat(40),
                "6".repeat(64),
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
        let authority = loaded.application_release_authority().unwrap();
        assert_eq!(authority.schema_version, RELEASE_SET_SCHEMA_VERSION);
        assert_eq!(authority.runtime_source_revision, "5".repeat(40));
        assert_eq!(authority.runtime_input_sha256, "6".repeat(64));

        let expected_artifact = loaded.expected_application_artifact().unwrap();
        assert_eq!(expected_artifact.source_revision, "5".repeat(40));
        assert_eq!(expected_artifact.sha256, "2".repeat(64));

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

    #[test]
    fn resolved_context_rejects_wrong_schema_and_runtime_identity() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("edge-orchestrator-invalid-context-{unique}"));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("edge-orchestrator");
        fs::write(&executable, b"exact-orchestrator").unwrap();
        let executable_sha = sha256_file(&executable).unwrap();
        let accepted = "f".repeat(40);
        let release_set_sha = "b".repeat(64);

        let render = |schema: &str, runtime_source: &str, runtime_input: &str| {
            format!(
                "EDGE_ACCEPTED_REVISION={accepted}\n\
EDGE_CANDIDATE_REVISION={}\n\
EDGE_SOURCE_TREE={}\n\
EDGE_RELEASE_ID=1\n\
EDGE_RELEASE_TAG=edge-release-{release_set_sha}\n\
EDGE_RELEASE_SET_SHA256={release_set_sha}\n\
EDGE_RELEASE_SCHEMA_VERSION={schema}\n\
EDGE_RUNTIME_SOURCE_REVISION={runtime_source}\n\
EDGE_RUNTIME_INPUT_SHA256={runtime_input}\n\
EDGE_WINDOWS_SOURCE_REVISION={}\n\
EDGE_WINDOWS_INPUT_SHA256={}\n\
EDGE_WINDOWS_ARTIFACT_SHA256={}\n\
EDGE_WINDOWS_CONTROLLER_SHA256={}\n\
EDGE_WINDOWS_CONSOLE_SHA256={}\n\
EDGE_WINDOWS_SING_BOX_SHA256={}\n\
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
                "7".repeat(40),
                "8".repeat(64),
                "9".repeat(64),
                "1".repeat(64),
                "2".repeat(64),
                "3".repeat(64),
                "4".repeat(64),
                "2".repeat(64),
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
            )
        };

        let path = root.join("resolved.env");
        fs::write(&path, render("4", &"5".repeat(40), &"6".repeat(64))).unwrap();
        assert!(
            OrchestrationContext::from_resolved_env_file(&path, Some(&accepted), &executable)
                .unwrap_err()
                .contains("requires ReleaseSet schema")
        );

        fs::write(&path, render("5", "not-a-revision", &"6".repeat(64))).unwrap();
        assert!(
            OrchestrationContext::from_resolved_env_file(&path, Some(&accepted), &executable)
                .unwrap_err()
                .contains("EDGE_RUNTIME_SOURCE_REVISION")
        );

        fs::write(&path, render("5", &"5".repeat(40), "not-a-digest")).unwrap();
        assert!(
            OrchestrationContext::from_resolved_env_file(&path, Some(&accepted), &executable)
                .unwrap_err()
                .contains("EDGE_RUNTIME_INPUT_SHA256")
        );

        let missing_runtime_input = render("5", &"5".repeat(40), &"6".repeat(64))
            .lines()
            .filter(|line| !line.starts_with("EDGE_RUNTIME_INPUT_SHA256="))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, format!("{missing_runtime_input}\n")).unwrap();
        assert!(
            OrchestrationContext::from_resolved_env_file(&path, Some(&accepted), &executable)
                .unwrap_err()
                .contains("missing EDGE_RUNTIME_INPUT_SHA256")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn application_materialization_is_exact_and_fail_closed() {
        let release = release();
        let agent_sha = release.agent_sha256.clone();
        let mut context = OrchestrationContext::new(release).unwrap();
        context.application_release = Some(ApplicationReleaseAuthority {
            schema_version: RELEASE_SET_SCHEMA_VERSION,
            runtime_source_revision: "5".repeat(40),
            runtime_input_sha256: "6".repeat(64),
        });

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("edge-application-materialize-{unique}"));
        let bundle = root.join("bundle");
        fs::create_dir_all(&bundle).unwrap();
        let artifact = root.join("edge-agent");
        fs::write(&artifact, b"agent").unwrap();
        let actual_agent_sha = sha256_file(&artifact).unwrap();
        context.release.agent_sha256 = actual_agent_sha.clone();
        let manifest_path = root.join("agent.json");

        context
            .materialize_application_inputs(&bundle, &manifest_path, &artifact)
            .unwrap();

        let manifest =
            AgentArtifactManifest::parse_json(&fs::read_to_string(&manifest_path).unwrap())
                .unwrap();
        assert_eq!(manifest.source_revision, "5".repeat(40));
        assert_eq!(manifest.sha256, actual_agent_sha);
        context
            .validate_application_artifact(&manifest, &artifact)
            .unwrap();
        context
            .validate_application_image_environment(&bundle)
            .unwrap();

        fs::write(
            bundle.join(".images.env"),
            context
                .expected_application_image_environment()
                .unwrap()
                .replace("gateway@sha256:", "gateway:latest#"),
        )
        .unwrap();
        assert!(
            context
                .validate_application_image_environment(&bundle)
                .is_err()
        );

        let mut stale = manifest;
        stale.source_revision = "7".repeat(40);
        assert!(
            context
                .validate_application_artifact(&stale, &artifact)
                .is_err()
        );

        assert_ne!(agent_sha, context.release.agent_sha256);
        fs::remove_dir_all(root).unwrap();
    }
}
