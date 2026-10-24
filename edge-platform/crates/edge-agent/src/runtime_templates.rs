// Cohesive native Rust module; no new runtime owner or workflow.
use super::*;

pub(super) fn require_line2_policy(runtime: &BTreeMap<String, String>) -> Result<(), String> {
    for key in ["PROXY_USERNAME", "PROXY_CERT_CN"] {
        if !runtime.contains_key(key) {
            return Err(format!(
                "Line 2 bootstrap requires runtime policy key: {key}"
            ));
        }
    }
    Ok(())
}

pub(super) fn require_tunnel_policy(runtime: &BTreeMap<String, String>) -> Result<(), String> {
    for key in [
        "REALITY_SERVER_NAME",
        "TUNNEL_DOMAIN",
        "ACME_EMAIL",
        "ACME_PROVIDER",
    ] {
        if !runtime.contains_key(key) {
            return Err(format!(
                "tunnel bootstrap requires runtime policy key: {key}"
            ));
        }
    }
    let domain = runtime.get("TUNNEL_DOMAIN").unwrap();
    if !valid_certificate_domain(domain) {
        return Err("TUNNEL_DOMAIN is invalid for certificate owner state".to_owned());
    }
    validate_acme_provider(runtime.get("ACME_PROVIDER").unwrap())?;
    Ok(())
}

pub(super) const LINE1_RUNTIME_TEMPLATE_KEYS: [&str; 12] = [
    "VLESS_UUID",
    "HY2_PASSWORD",
    "REALITY_SERVER_NAME",
    "REALITY_PRIVATE_KEY",
    "REALITY_SHORT_ID",
    "VLESS_WARP_UUID",
    "HY2_WARP_PASSWORD",
    "REALITY_WARP_PRIVATE_KEY",
    "REALITY_WARP_SHORT_ID",
    "TUNNEL_DOMAIN",
    "ACME_EMAIL",
    "ACME_PROVIDER",
];
pub(super) const LINE2_RUNTIME_TEMPLATE_KEYS: [&str; 4] = [
    "PROXY_USERNAME",
    "PROXY_PASSWORD",
    "PROXY_CERT_PATH",
    "PROXY_KEY_PATH",
];

pub(super) fn render_line1_runtime(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    render_runtime_template(
        stack_dir,
        "line1-gateway/config.template.json",
        "rendered/line1-gateway.json",
        runtime,
        &LINE1_RUNTIME_TEMPLATE_KEYS,
    )
}

pub(super) fn render_line2_runtime(
    stack_dir: &Path,
    runtime: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut values = runtime.clone();
    let (certificate_path, key_path) = line2_certificate_container_paths(runtime)?;
    values.insert("PROXY_CERT_PATH".to_owned(), certificate_path);
    values.insert("PROXY_KEY_PATH".to_owned(), key_path);
    render_runtime_template(
        stack_dir,
        "line2-proxy/config.template.json",
        "rendered/line2-proxy.json",
        &values,
        &LINE2_RUNTIME_TEMPLATE_KEYS,
    )
}

pub(super) fn render_runtime_template(
    stack_dir: &Path,
    template_relative: &str,
    target_relative: &str,
    values: &BTreeMap<String, String>,
    required_keys: &[&str],
) -> Result<(), String> {
    let rendered = expand_runtime_template(stack_dir, template_relative, values, required_keys)?;
    let target = stack_dir.join(target_relative);
    fs::write(&target, rendered.as_bytes()).map_err(|err| {
        format!(
            "failed to write rendered runtime {}: {err}",
            target.display()
        )
    })?;
    set_bundle_file_permissions(&target, false, true)
}

pub(super) fn expand_runtime_template(
    stack_dir: &Path,
    template_relative: &str,
    values: &BTreeMap<String, String>,
    required_keys: &[&str],
) -> Result<String, String> {
    let template_path = stack_dir.join(template_relative);
    let mut rendered = fs::read_to_string(&template_path).map_err(|err| {
        format!(
            "failed to read runtime template {}: {err}",
            template_path.display()
        )
    })?;
    for key in required_keys {
        let value = values
            .get(*key)
            .ok_or_else(|| format!("runtime template value is missing: {key}"))?;
        let token = format!("${{{key}}}");
        if !rendered.contains(&token) {
            return Err(format!(
                "runtime template {} is missing required placeholder {token}",
                template_path.display()
            ));
        }
        rendered = rendered.replace(&token, value);
    }
    if rendered.contains("${") {
        return Err(format!(
            "runtime template {} contains unresolved placeholders",
            template_path.display()
        ));
    }

    Ok(rendered)
}
