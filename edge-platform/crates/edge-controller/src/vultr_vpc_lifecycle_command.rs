use crate::vultr_host_bootstrap::{strict_ssh_capture, verify_operator_key_matches};
use crate::vultr_lifecycle_command::{
    observe_guest_boot_id, operator_private_key_path_from_env, read_canonical_ssh_public_key,
    validate_linux_boot_id,
};
use crate::vultr_vpc_lifecycle_service::{
    VpcExecutionPolicy, VultrVpcApiProvider, apply_vpc_attachment_once, apply_vpc_once,
    authorize_vpc_apply, authorize_vpc_attachment, authorize_vpc_cleanup, cleanup_vpc_once,
    observe_vpc, plan_vpc, plan_vpc_attachment, plan_vpc_cleanup, verify_vpc_ready,
};
use edge_controller_core::vultr_vpc_lifecycle::{AttachmentAction, DesiredVpcState};
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).ok_or_else(usage)?;
    match command {
        "inventory" => run_inventory(&args[1..]).await,
        "plan" => run_plan(&args[1..]).await,
        "apply" => run_apply(&args[1..]).await,
        "attachment-plan" => run_attachment_plan(&args[1..]).await,
        "attachment-apply" => run_attachment_apply(&args[1..]).await,
        "verify" => run_verify(&args[1..]).await,
        "cleanup-plan" => run_cleanup_plan(&args[1..]).await,
        "cleanup-apply" => run_cleanup_apply(&args[1..]).await,
        _ => Err(usage()),
    }
}

async fn run_inventory(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "inventory")?;
    let mut provider = provider_from_env()?;
    let observation = observe_vpc(&mut provider, &desired).await?;
    print_json(serde_json::json!({
        "desired": desired,
        "observation": observation,
        "mutations_performed": 0,
    }))
}

async fn run_plan(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "plan")?;
    let mut provider = provider_from_env()?;
    let (observation, plan) = plan_vpc(&mut provider, &desired).await?;
    let authorized = authorize_vpc_apply(&desired, &observation, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observation,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller vultr-vpc apply <spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = apply_vpc_once(
        &mut provider,
        &desired,
        &args[1],
        VpcExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

async fn run_attachment_plan(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "attachment-plan")?;
    let mut provider = provider_from_env()?;
    let (target, observation, attachments, plan) =
        plan_vpc_attachment(&mut provider, &desired).await?;
    let authorized =
        authorize_vpc_attachment(&desired, &target, &observation, &attachments, plan.clone())?;
    print_json(serde_json::json!({
        "target": target,
        "observation": observation,
        "attachments": attachments,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_attachment_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err(
            "usage: edge-controller vultr-vpc attachment-apply <spec-path> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;

    let (target_before, _observation, _attachments, plan_before) =
        plan_vpc_attachment(&mut provider, &desired).await?;
    let guest_transition_probe =
        if matches!(plan_before.action, AttachmentAction::AttachInstance { .. }) {
            let canonical_public_key = read_canonical_ssh_public_key()?;
            let operator_private_key_path = operator_private_key_path_from_env()?;
            verify_operator_key_matches(&operator_private_key_path, &canonical_public_key)?;
            let boot_id_before = observe_guest_boot_id(
                &target_before.main_ip,
                &desired.machine_id,
                &operator_private_key_path,
                &canonical_public_key,
            )?;
            Some((
                canonical_public_key,
                operator_private_key_path,
                boot_id_before,
            ))
        } else {
            None
        };

    let report = apply_vpc_attachment_once(
        &mut provider,
        &desired,
        &args[1],
        VpcExecutionPolicy::default(),
    )
    .await?;

    let guest_transition =
        if let Some((canonical_public_key, operator_private_key_path, boot_id_before)) =
            guest_transition_probe
        {
            if !matches!(report.performed, AttachmentAction::AttachInstance { .. }) {
                return Err(
                    "Vultr VPC attachment authority changed after guest boot observation"
                        .to_owned(),
                );
            }
            let private_ipv4 = report.next_plan.private_ipv4.as_deref().ok_or_else(|| {
                "Vultr VPC attachment converged to NOOP without provider private IPv4".to_owned()
            })?;
            Some(
                wait_for_guest_vpc_ready(
                    &report.target.main_ip,
                    &desired.machine_id,
                    &operator_private_key_path,
                    &canonical_public_key,
                    &boot_id_before,
                    &report.next_plan.cidr,
                    private_ipv4,
                    60,
                    Duration::from_secs(2),
                )
                .await?,
            )
        } else {
            None
        };

    let mut value = serde_json::to_value(report).map_err(|err| err.to_string())?;
    value["guest_transition"] = guest_transition.unwrap_or(serde_json::Value::Null);
    print_json(value)
}


fn validate_guest_vpc_expectation(cidr: &str, private_ipv4: &str) -> Result<u8, String> {
    let (subnet_text, prefix_text) = cidr
        .split_once('/')
        .ok_or_else(|| "verified Vultr VPC CIDR must use IPv4 prefix notation".to_owned())?;
    let subnet = subnet_text
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("verified Vultr VPC CIDR has invalid IPv4 subnet: {err}"))?;
    let prefix = prefix_text
        .parse::<u8>()
        .map_err(|err| format!("verified Vultr VPC CIDR has invalid prefix: {err}"))?;
    if !(1..=32).contains(&prefix) {
        return Err("verified Vultr VPC CIDR prefix must be in 1..=32".to_owned());
    }
    if !subnet.is_private() {
        return Err("verified Vultr VPC CIDR must be RFC1918 IPv4".to_owned());
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    if (u32::from(subnet) & mask) != u32::from(subnet) {
        return Err("verified Vultr VPC CIDR must be canonical".to_owned());
    }

    let private_ip = private_ipv4
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("verified Vultr private IPv4 is invalid: {err}"))?;
    if !private_ip.is_private() {
        return Err("verified Vultr private IPv4 must be RFC1918".to_owned());
    }
    if (u32::from(private_ip) & mask) != u32::from(subnet) {
        return Err("verified Vultr private IPv4 is outside the verified VPC CIDR".to_owned());
    }
    Ok(prefix)
}

fn parse_guest_vpc_probe_output(output: &str) -> Result<(String, String), String> {
    let line = output.trim();
    let (boot_id, interface) = line
        .split_once('\t')
        .ok_or_else(|| "guest VPC probe output is missing tab-separated fields".to_owned())?;
    if interface.is_empty()
        || interface.len() > 64
        || interface.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("guest VPC probe returned invalid interface identity".to_owned());
    }
    validate_linux_boot_id(boot_id)?;
    Ok((boot_id.to_owned(), interface.to_owned()))
}

async fn wait_for_guest_vpc_ready(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    previous_boot_id: &str,
    cidr: &str,
    private_ipv4: &str,
    attempts: usize,
    delay: Duration,
) -> Result<serde_json::Value, String> {
    if attempts == 0 {
        return Err("guest VPC readiness attempts must be greater than zero".to_owned());
    }
    validate_linux_boot_id(previous_boot_id)?;
    let prefix = validate_guest_vpc_expectation(cidr, private_ipv4)?;
    let expected_addr = format!("{private_ipv4}/{prefix}");
    let command = format!(
        "set -eu; expected_addr='{expected_addr}'; expected_cidr='{cidr}'; expected_ip='{private_ipv4}'; boot_id=$(cat /proc/sys/kernel/random/boot_id); interfaces=$(ip -o -4 addr show scope global | grep -F -- \" $expected_addr \" | awk '{{print $2}}' | sort -u); iface_count=$(printf '%s\\n' \"$interfaces\" | sed '/^$/d' | wc -l | tr -d ' '); test \"$iface_count\" = 1; iface=$(printf '%s\\n' \"$interfaces\" | sed '/^$/d'); route_count=$(ip -o -4 route show | grep -F -- \"$expected_cidr dev $iface proto kernel scope link src $expected_ip\" | wc -l | tr -d ' '); test \"$route_count\" = 1; printf '%s\\t%s\\n' \"$boot_id\" \"$iface\""
    );

    let mut last_detail = "not-observed".to_owned();
    for attempt in 0..attempts {
        match strict_ssh_capture(
            target_ip,
            logical_hostname,
            operator_private_key_path,
            canonical_operator_public_key,
            &command,
        ) {
            Ok(output) => match parse_guest_vpc_probe_output(&output) {
                Ok((boot_id_after, interface)) => {
                    return Ok(serde_json::json!({
                        "boot_id_before": previous_boot_id,
                        "boot_id_after": boot_id_after,
                        "boot_id_changed": boot_id_after != previous_boot_id,
                        "network_ready": true,
                        "interface": interface,
                        "cidr": cidr,
                        "private_ipv4": private_ipv4,
                    }));
                }
                Err(err) => last_detail = err,
            },
            Err(err) => {
                last_detail = err.chars().take(512).collect();
            }
        }

        if attempt + 1 < attempts {
            tokio::time::sleep(delay).await;
        }
    }

    Err(format!(
        "guest VPC readiness was not proven for {logical_hostname} at {target_ip} after {attempts} observations: {last_detail}"
    ))
}

async fn run_verify(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "verify")?;
    let mut provider = provider_from_env()?;
    let report = verify_vpc_ready(&mut provider, &desired).await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

async fn run_cleanup_plan(args: &[String]) -> Result<(), String> {
    let desired = one_spec_arg(args, "cleanup-plan")?;
    let mut provider = provider_from_env()?;
    let (observation, attachments, plan) = plan_vpc_cleanup(&mut provider, &desired).await?;
    let authorized = authorize_vpc_cleanup(&desired, &observation, &attachments, plan.clone())?;
    print_json(serde_json::json!({
        "observation": observation,
        "attachments": attachments,
        "plan": plan,
        "plan_authority": authorized.authority,
        "plan_disposition": authorized.disposition,
        "mutations_performed": 0,
    }))
}

async fn run_cleanup_apply(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(
            "usage: edge-controller vultr-vpc cleanup-apply <spec-path> <destructive-digest> <authorized-plan-sha256>"
                .to_owned(),
        );
    }
    let desired = load_desired(Path::new(&args[0]))?;
    let mut provider = provider_from_env()?;
    let report = cleanup_vpc_once(
        &mut provider,
        &desired,
        &args[1],
        &args[2],
        VpcExecutionPolicy::default(),
    )
    .await?;
    print_json(serde_json::to_value(report).map_err(|err| err.to_string())?)
}

fn one_spec_arg(args: &[String], command: &str) -> Result<DesiredVpcState, String> {
    if args.len() != 1 {
        return Err(format!(
            "usage: edge-controller vultr-vpc {command} <spec-path>"
        ));
    }
    load_desired(Path::new(&args[0]))
}

fn load_desired(path: &Path) -> Result<DesiredVpcState, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read Vultr VPC desired state {}: {err}",
            path.display()
        )
    })?;
    DesiredVpcState::parse_json(&raw).map_err(|err| err.to_string())
}

fn provider_from_env() -> Result<VultrVpcApiProvider, String> {
    let api_key = env::var("VULTR_API_KEY").map_err(|_| "VULTR_API_KEY is required".to_owned())?;
    VultrVpcApiProvider::new(api_key)
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(&value)
        .map_err(|err| format!("failed to serialize Vultr VPC result: {err}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    [
        "usage:",
        "  edge-controller vultr-vpc inventory <spec-path>",
        "  edge-controller vultr-vpc plan <spec-path>",
        "  edge-controller vultr-vpc apply <spec-path> <authorized-plan-sha256>",
        "  edge-controller vultr-vpc attachment-plan <spec-path>",
        "  edge-controller vultr-vpc attachment-apply <spec-path> <authorized-plan-sha256>",
        "  edge-controller vultr-vpc verify <spec-path>",
        "  edge-controller vultr-vpc cleanup-plan <spec-path>",
        "  edge-controller vultr-vpc cleanup-apply <spec-path> <destructive-digest> <authorized-plan-sha256>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_vpc_expectation_requires_canonical_private_network() {
        assert_eq!(
            validate_guest_vpc_expectation("10.0.4.0/24", "10.0.4.2").unwrap(),
            24
        );
        assert!(validate_guest_vpc_expectation("10.0.4.1/24", "10.0.4.2").is_err());
        assert!(validate_guest_vpc_expectation("203.0.113.0/24", "203.0.113.2").is_err());
        assert!(validate_guest_vpc_expectation("10.0.4.0/24", "10.0.5.2").is_err());
    }

    #[test]
    fn guest_vpc_probe_output_preserves_boot_and_interface_identity() {
        let (boot_id, interface) = parse_guest_vpc_probe_output(
            "11111111-2222-3333-4444-555555555555\tens7",
        )
        .unwrap();
        assert_eq!(boot_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(interface, "ens7");
        assert!(parse_guest_vpc_probe_output("not-a-boot-id\tens7").is_err());
        assert!(parse_guest_vpc_probe_output("11111111-2222-3333-4444-555555555555").is_err());
    }

    #[test]
    fn usage_is_closed_and_has_no_raw_provider_identity_surface() {
        let text = usage();
        assert!(text.contains("vultr-vpc attachment-apply"));
        assert!(text.contains("vultr-vpc cleanup-apply"));
        assert!(!text.contains("vpc-id"));
        assert!(!text.contains("instance-id"));
        assert!(!text.contains("subnet"));
        assert!(!text.contains("curl"));
        assert!(!text.contains("shell"));
    }
}
