use serde::{Deserialize, Serialize};

pub const BUILD_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBuildManifest {
    pub schema_version: u32,
    pub candidate_source_revision: String,
    pub source_tree: String,
    pub release_input_sha256: String,
    pub windows_input_sha256: String,
    pub windows_source_revision: String,
    pub reused: bool,
    pub sing_box_version: String,
    pub sing_box_archive_sha256: String,
    pub sing_box_binary_sha256: String,
    pub artifact_sha256: String,
    pub controller_sha256: String,
    pub console_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxBuildManifest {
    pub schema_version: u32,
    pub candidate_source_revision: String,
    pub source_tree: String,
    pub release_input_sha256: String,
    pub runtime_input_sha256: String,
    pub runtime_source_revision: String,
    pub runtime_reused: bool,
    pub controller_sha256: String,
    pub orchestrator_sha256: String,
    pub agent_sha256: String,
    pub edge_gateway_image: String,
    pub edge_warp_egress_image: String,
    pub sing_box_version: String,
    pub sing_box_archive_sha256: String,
    pub sing_box_binary_sha256: String,
    pub docker_engine_version: String,
    pub containerd_version: String,
    pub compose_version: String,
    pub warp_version: String,
    pub warp_archive_sha256: String,
    pub debian_base_image: String,
    pub ubuntu_base_image: String,
    pub mesh_image: String,
}

impl WindowsBuildManifest {
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let value: Self = serde_json::from_str(raw)
            .map_err(|err| format!("invalid WindowsBuildManifest JSON: {err}"))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_schema("WindowsBuildManifest", self.schema_version)?;
        validate_lower_hex(
            "WindowsBuildManifest.candidate_source_revision",
            &self.candidate_source_revision,
            40,
        )?;
        validate_lower_hex("WindowsBuildManifest.source_tree", &self.source_tree, 40)?;
        validate_sha256(
            "WindowsBuildManifest.release_input_sha256",
            &self.release_input_sha256,
        )?;
        validate_sha256(
            "WindowsBuildManifest.windows_input_sha256",
            &self.windows_input_sha256,
        )?;
        validate_lower_hex(
            "WindowsBuildManifest.windows_source_revision",
            &self.windows_source_revision,
            40,
        )?;
        if !self.reused && self.windows_source_revision != self.candidate_source_revision {
            return Err(
                "non-reused Windows build must use the candidate source revision".to_owned(),
            );
        }
        validate_stable_semver(
            "WindowsBuildManifest.sing_box_version",
            &self.sing_box_version,
        )?;
        for (label, value) in [
            (
                "WindowsBuildManifest.sing_box_archive_sha256",
                self.sing_box_archive_sha256.as_str(),
            ),
            (
                "WindowsBuildManifest.sing_box_binary_sha256",
                self.sing_box_binary_sha256.as_str(),
            ),
            (
                "WindowsBuildManifest.artifact_sha256",
                self.artifact_sha256.as_str(),
            ),
            (
                "WindowsBuildManifest.controller_sha256",
                self.controller_sha256.as_str(),
            ),
            (
                "WindowsBuildManifest.console_sha256",
                self.console_sha256.as_str(),
            ),
        ] {
            validate_sha256(label, value)?;
        }
        Ok(())
    }
}

impl LinuxBuildManifest {
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let value: Self = serde_json::from_str(raw)
            .map_err(|err| format!("invalid LinuxBuildManifest JSON: {err}"))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_schema("LinuxBuildManifest", self.schema_version)?;
        validate_lower_hex(
            "LinuxBuildManifest.candidate_source_revision",
            &self.candidate_source_revision,
            40,
        )?;
        validate_lower_hex("LinuxBuildManifest.source_tree", &self.source_tree, 40)?;
        validate_sha256(
            "LinuxBuildManifest.release_input_sha256",
            &self.release_input_sha256,
        )?;
        validate_sha256(
            "LinuxBuildManifest.runtime_input_sha256",
            &self.runtime_input_sha256,
        )?;
        validate_lower_hex(
            "LinuxBuildManifest.runtime_source_revision",
            &self.runtime_source_revision,
            40,
        )?;
        if !self.runtime_reused && self.runtime_source_revision != self.candidate_source_revision {
            return Err(
                "non-reused Linux runtime must use the candidate source revision".to_owned(),
            );
        }
        for (label, value) in [
            (
                "LinuxBuildManifest.controller_sha256",
                self.controller_sha256.as_str(),
            ),
            (
                "LinuxBuildManifest.orchestrator_sha256",
                self.orchestrator_sha256.as_str(),
            ),
            (
                "LinuxBuildManifest.agent_sha256",
                self.agent_sha256.as_str(),
            ),
            (
                "LinuxBuildManifest.sing_box_archive_sha256",
                self.sing_box_archive_sha256.as_str(),
            ),
            (
                "LinuxBuildManifest.sing_box_binary_sha256",
                self.sing_box_binary_sha256.as_str(),
            ),
            (
                "LinuxBuildManifest.warp_archive_sha256",
                self.warp_archive_sha256.as_str(),
            ),
        ] {
            validate_sha256(label, value)?;
        }
        validate_stable_semver(
            "LinuxBuildManifest.sing_box_version",
            &self.sing_box_version,
        )?;
        validate_version_token(
            "LinuxBuildManifest.docker_engine_version",
            &self.docker_engine_version,
        )?;
        validate_version_token(
            "LinuxBuildManifest.containerd_version",
            &self.containerd_version,
        )?;
        validate_version_token("LinuxBuildManifest.compose_version", &self.compose_version)?;
        validate_version_token("LinuxBuildManifest.warp_version", &self.warp_version)?;
        validate_exact_image(
            "LinuxBuildManifest.edge_gateway_image",
            &self.edge_gateway_image,
            "ghcr.io/iamaman11/vultr-edge-gateway",
        )?;
        validate_exact_image(
            "LinuxBuildManifest.edge_warp_egress_image",
            &self.edge_warp_egress_image,
            "ghcr.io/iamaman11/vultr-warp-egress",
        )?;
        validate_exact_image(
            "LinuxBuildManifest.debian_base_image",
            &self.debian_base_image,
            "docker.io/library/debian",
        )?;
        validate_exact_image(
            "LinuxBuildManifest.ubuntu_base_image",
            &self.ubuntu_base_image,
            "docker.io/library/ubuntu",
        )?;
        validate_exact_image(
            "LinuxBuildManifest.mesh_image",
            &self.mesh_image,
            "docker.io/cloudflare/mesh",
        )?;
        Ok(())
    }
}

pub fn validate_build_manifest_pair(
    windows: &WindowsBuildManifest,
    linux: &LinuxBuildManifest,
    expected_candidate_revision: &str,
    expected_release_input_sha256: &str,
    expected_source_tree: Option<&str>,
) -> Result<(), String> {
    windows.validate()?;
    linux.validate()?;
    validate_lower_hex(
        "expected candidate revision",
        expected_candidate_revision,
        40,
    )?;
    validate_sha256(
        "expected release input SHA-256",
        expected_release_input_sha256,
    )?;

    if windows.candidate_source_revision != expected_candidate_revision
        || linux.candidate_source_revision != expected_candidate_revision
    {
        return Err("build manifests do not bind the expected candidate revision".to_owned());
    }
    if windows.release_input_sha256 != expected_release_input_sha256
        || linux.release_input_sha256 != expected_release_input_sha256
    {
        return Err("build manifests do not bind the expected release-input authority".to_owned());
    }
    if windows.source_tree != linux.source_tree {
        return Err("Windows and Linux build manifests disagree on source tree".to_owned());
    }
    if let Some(expected) = expected_source_tree {
        validate_lower_hex("expected source tree", expected, 40)?;
        if windows.source_tree != expected {
            return Err("build manifests do not bind the expected source tree".to_owned());
        }
    }
    if windows.sing_box_version != linux.sing_box_version {
        return Err("Windows and Linux build manifests disagree on sing-box version".to_owned());
    }
    Ok(())
}

fn validate_schema(label: &str, schema: u32) -> Result<(), String> {
    if schema != BUILD_MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "{label} schema_version {schema} is unsupported; expected {}",
            BUILD_MANIFEST_SCHEMA_VERSION
        ));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), String> {
    validate_lower_hex(label, value, 64)
}

fn validate_lower_hex(label: &str, value: &str, expected_len: usize) -> Result<(), String> {
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {expected_len} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_stable_semver(label: &str, value: &str) -> Result<(), String> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!("{label} must be a normalized x.y.z stable version"));
    }
    Ok(())
}

fn validate_version_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b':' | b'~' | b'_' | b'-')
        })
    {
        return Err(format!("{label} must be a safe exact version token"));
    }
    Ok(())
}

fn validate_exact_image(label: &str, value: &str, repository: &str) -> Result<(), String> {
    let prefix = format!("{repository}@sha256:");
    let digest = value
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{label} must reference exact repository {repository} by digest"))?;
    validate_sha256(label, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows() -> WindowsBuildManifest {
        WindowsBuildManifest {
            schema_version: BUILD_MANIFEST_SCHEMA_VERSION,
            candidate_source_revision: "1".repeat(40),
            source_tree: "2".repeat(40),
            release_input_sha256: "3".repeat(64),
            windows_input_sha256: "4".repeat(64),
            windows_source_revision: "5".repeat(40),
            reused: true,
            sing_box_version: "1.14.2".to_owned(),
            sing_box_archive_sha256: "6".repeat(64),
            sing_box_binary_sha256: "7".repeat(64),
            artifact_sha256: "8".repeat(64),
            controller_sha256: "9".repeat(64),
            console_sha256: "a".repeat(64),
        }
    }

    fn linux() -> LinuxBuildManifest {
        LinuxBuildManifest {
            schema_version: BUILD_MANIFEST_SCHEMA_VERSION,
            candidate_source_revision: "1".repeat(40),
            source_tree: "2".repeat(40),
            release_input_sha256: "3".repeat(64),
            runtime_input_sha256: "b".repeat(64),
            runtime_source_revision: "5".repeat(40),
            runtime_reused: true,
            controller_sha256: "c".repeat(64),
            orchestrator_sha256: "d".repeat(64),
            agent_sha256: "e".repeat(64),
            edge_gateway_image: format!(
                "ghcr.io/iamaman11/vultr-edge-gateway@sha256:{}",
                "1".repeat(64)
            ),
            edge_warp_egress_image: format!(
                "ghcr.io/iamaman11/vultr-warp-egress@sha256:{}",
                "2".repeat(64)
            ),
            sing_box_version: "1.14.2".to_owned(),
            sing_box_archive_sha256: "f".repeat(64),
            sing_box_binary_sha256: "0".repeat(64),
            docker_engine_version: "5:29.8.1-1~debian.13~trixie".to_owned(),
            containerd_version: "2.3.5-1~debian.13~trixie".to_owned(),
            compose_version: "5.5.1-1~debian.13~trixie".to_owned(),
            warp_version: "2026.7.1377.0".to_owned(),
            warp_archive_sha256: "1".repeat(64),
            debian_base_image: format!("docker.io/library/debian@sha256:{}", "3".repeat(64)),
            ubuntu_base_image: format!("docker.io/library/ubuntu@sha256:{}", "4".repeat(64)),
            mesh_image: format!("docker.io/cloudflare/mesh@sha256:{}", "5".repeat(64)),
        }
    }

    #[test]
    fn manifests_accept_exact_reused_authority() {
        validate_build_manifest_pair(
            &windows(),
            &linux(),
            &"1".repeat(40),
            &"3".repeat(64),
            Some(&"2".repeat(40)),
        )
        .unwrap();
    }

    #[test]
    fn unknown_schema_and_unknown_fields_fail_closed() {
        let mut value = serde_json::to_value(windows()).unwrap();
        value["schema_version"] = serde_json::json!(2);
        assert!(WindowsBuildManifest::parse_json(&value.to_string()).is_err());

        let mut value = serde_json::to_value(linux()).unwrap();
        value["extra"] = serde_json::json!("not allowed");
        assert!(LinuxBuildManifest::parse_json(&value.to_string()).is_err());
    }

    #[test]
    fn non_reused_builds_must_bind_candidate_source() {
        let mut windows = windows();
        windows.reused = false;
        assert!(windows.validate().is_err());

        let mut linux = linux();
        linux.runtime_reused = false;
        assert!(linux.validate().is_err());
    }

    #[test]
    fn pair_rejects_candidate_release_input_tree_and_version_drift() {
        let expected_candidate = "1".repeat(40);
        let expected_release_input = "3".repeat(64);
        let expected_tree = "2".repeat(40);

        let mut windows_revision_drift = windows();
        windows_revision_drift.candidate_source_revision = "6".repeat(40);
        assert!(
            validate_build_manifest_pair(
                &windows_revision_drift,
                &linux(),
                &expected_candidate,
                &expected_release_input,
                Some(&expected_tree),
            )
            .is_err()
        );

        let mut linux_release_input_drift = linux();
        linux_release_input_drift.release_input_sha256 = "7".repeat(64);
        assert!(
            validate_build_manifest_pair(
                &windows(),
                &linux_release_input_drift,
                &expected_candidate,
                &expected_release_input,
                Some(&expected_tree),
            )
            .is_err()
        );

        let mut linux_tree_drift = linux();
        linux_tree_drift.source_tree = "8".repeat(40);
        assert!(
            validate_build_manifest_pair(
                &windows(),
                &linux_tree_drift,
                &expected_candidate,
                &expected_release_input,
                Some(&expected_tree),
            )
            .is_err()
        );

        let mut linux_version_drift = linux();
        linux_version_drift.sing_box_version = "1.14.3".to_owned();
        assert!(
            validate_build_manifest_pair(
                &windows(),
                &linux_version_drift,
                &expected_candidate,
                &expected_release_input,
                Some(&expected_tree),
            )
            .is_err()
        );
    }

    #[test]
    fn mutable_or_wrong_repository_images_fail_closed() {
        let mut mutable_gateway = linux();
        mutable_gateway.edge_gateway_image =
            "ghcr.io/iamaman11/vultr-edge-gateway:latest".to_owned();
        assert!(mutable_gateway.validate().is_err());

        let mut wrong_mesh_repository = linux();
        wrong_mesh_repository.mesh_image =
            format!("docker.io/example/mesh@sha256:{}", "5".repeat(64));
        assert!(wrong_mesh_repository.validate().is_err());
    }
}
