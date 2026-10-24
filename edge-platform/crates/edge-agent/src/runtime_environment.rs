// Cohesive native Rust module; no new runtime owner or workflow.
use super::*;

pub(super) fn read_typed_runtime_environment(stack_dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = stack_dir.join(RUNTIME_ENV_FILE);
    let values = read_strict_env_file(&path)?;

    let allowed = BTreeSet::from([
        "PROXY_USERNAME",
        "PROXY_CERT_CN",
        "REALITY_SERVER_NAME",
        "TUNNEL_DOMAIN",
        "ACME_EMAIL",
        "ACME_PROVIDER",
        "PROXY_PASSWORD",
        "VLESS_UUID",
        "HY2_PASSWORD",
        "REALITY_PRIVATE_KEY",
        "REALITY_PUBLIC_KEY",
        "REALITY_SHORT_ID",
        "VLESS_WARP_UUID",
        "HY2_WARP_PASSWORD",
        "REALITY_WARP_PRIVATE_KEY",
        "REALITY_WARP_PUBLIC_KEY",
        "REALITY_WARP_SHORT_ID",
    ]);
    if let Some(key) = values.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(format!(
            "runtime environment contains unsupported key: {key}"
        ));
    }

    let secret_keys = [
        "PROXY_PASSWORD",
        "VLESS_UUID",
        "HY2_PASSWORD",
        "REALITY_PRIVATE_KEY",
        "REALITY_PUBLIC_KEY",
        "REALITY_SHORT_ID",
        "VLESS_WARP_UUID",
        "HY2_WARP_PASSWORD",
        "REALITY_WARP_PRIVATE_KEY",
        "REALITY_WARP_PUBLIC_KEY",
        "REALITY_WARP_SHORT_ID",
    ];
    let mut secret_env = String::new();
    for key in secret_keys {
        let value = values
            .get(key)
            .ok_or_else(|| format!("runtime environment is missing VM-owned credential: {key}"))?;
        secret_env.push_str(key);
        secret_env.push('=');
        secret_env.push_str(value);
        secret_env.push('\n');
    }
    ApplicationRuntimeSecrets::parse_env(&secret_env)
        .map_err(|err| format!("VM-owned runtime credentials are invalid: {err}"))?;

    let line2_count = ["PROXY_USERNAME", "PROXY_CERT_CN"]
        .into_iter()
        .filter(|key| values.contains_key(*key))
        .count();
    if line2_count != 0 && line2_count != 2 {
        return Err("runtime environment contains incomplete Line 2 policy".to_owned());
    }
    let line1_count = ["REALITY_SERVER_NAME", "TUNNEL_DOMAIN", "ACME_EMAIL"]
        .into_iter()
        .filter(|key| values.contains_key(*key))
        .count();
    if line1_count != 0 && line1_count != 3 {
        return Err("runtime environment contains incomplete Line 1 policy".to_owned());
    }
    if line1_count == 0 && line2_count == 0 {
        return Err("runtime environment contains no enabled application capability".to_owned());
    }

    Ok(values)
}

pub(super) fn read_exact_image_environment(stack_dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = stack_dir.join(IMAGE_ENV_FILE);
    let values = read_strict_env_file(&path)?;
    let expected = BTreeSet::from([
        EDGE_GATEWAY_IMAGE_KEY,
        EDGE_WARP_EGRESS_IMAGE_KEY,
        EDGE_MESH_IMAGE_KEY,
    ]);
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(format!(
            "{IMAGE_ENV_FILE} must contain exactly {EDGE_GATEWAY_IMAGE_KEY}, {EDGE_WARP_EGRESS_IMAGE_KEY}, and {EDGE_MESH_IMAGE_KEY}"
        ));
    }

    validate_exact_image_ref(
        EDGE_GATEWAY_IMAGE_KEY,
        values.get(EDGE_GATEWAY_IMAGE_KEY).unwrap(),
        "ghcr.io/iamaman11/vultr-edge-gateway",
    )?;
    validate_exact_image_ref(
        EDGE_WARP_EGRESS_IMAGE_KEY,
        values.get(EDGE_WARP_EGRESS_IMAGE_KEY).unwrap(),
        "ghcr.io/iamaman11/vultr-warp-egress",
    )?;
    validate_exact_image_ref(
        EDGE_MESH_IMAGE_KEY,
        values.get(EDGE_MESH_IMAGE_KEY).unwrap(),
        "docker.io/cloudflare/mesh",
    )?;
    Ok(values)
}

pub(super) fn read_strict_env_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read required environment {}: {err}",
            path.display()
        )
    })?;
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "environment {} line {} must use KEY=VALUE syntax",
                path.display(),
                index + 1
            )
        })?;
        if key.is_empty() || key.trim() != key || value.is_empty() {
            return Err(format!(
                "environment {} line {} contains an invalid key or empty value",
                path.display(),
                index + 1
            ));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!(
                "environment {} contains duplicate key: {key}",
                path.display()
            ));
        }
    }
    Ok(values)
}

pub(super) fn validate_exact_image_ref(label: &str, value: &str, repository: &str) -> Result<(), String> {
    let prefix = format!("{repository}@sha256:");
    let digest = value
        .strip_prefix(&prefix)
        .ok_or_else(|| format!("{label} must reference exact repository {repository} by digest"))?;
    validate_lower_hex(label, digest, 64)
}
