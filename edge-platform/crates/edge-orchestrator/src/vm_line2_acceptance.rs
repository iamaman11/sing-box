//! Read-only host Line2 public acceptance using existing authoritative owners.
//! The GitHub runner is the independent traffic vantage, not a Docker or VM
//! mutation owner. No operator-supplied IP, TLS name or credential is trusted.
use edge_shared_types::canonical_production_desired_state;
use std::path::Path;

fn validate_witness_scope(
    machine_id: &str,
    active_machine: &str,
    dns_name: &str,
    production_name: &str,
    line1_name: &str,
    line2_name: &str,
    username: &str,
    generation: u64,
) -> Result<(), &'static str> {
    if machine_id.is_empty()
        || machine_id.len() > 64
        || !machine_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || machine_id != active_machine
    {
        return Err("HOST_VM_LINE2_WITNESS_ACTIVE_MACHINE_MISMATCH");
    }
    if dns_name.is_empty()
        || dns_name != production_name
        || line1_name != dns_name
        || line2_name != dns_name
        || username != "acceptance"
        || generation == 0
    {
        return Err("HOST_VM_LINE2_WITNESS_GIT_POLICY_MISMATCH");
    }
    Ok(())
}

pub(crate) async fn run(
    machine_id: &str,
    source_comment_id: Option<u64>,
    release: &edge_orchestrator::OrchestrationContext,
) -> Result<(), String> {
    let comment = source_comment_id
        .filter(|id| *id > 0)
        .ok_or("HOST_VM_LINE2_WITNESS_OPERATOR_COMMENT_REQUIRED")?;
    // Same protected Git and exact release authority used by /host apply.
    // The witness MUST NOT create a VM or accept an operator-supplied IP.
    release.application_release_authority()?;
    let host = release.verified_vm_first_use_host(machine_id)?;
    let generation = host
        .vm_first_use_credential
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_CREDENTIAL_GIT_PIN_MISSING")?
        .generation;
    let root = canonical_production_desired_state()?;
    let dns = root
        .dns
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_DNS_DESIRED_MISSING")?;
    let path = format!("infra/hosts/specs/{machine_id}.textproto");
    let (machine, application) = crate::vm_host_desired::load(Path::new(&path))?;
    let line1 = application
        .runtime_policy
        .line1
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_LINE1_POLICY_MISSING")?;
    let line2 = application
        .runtime_policy
        .line2
        .as_ref()
        .ok_or("HOST_VM_LINE2_WITNESS_LINE2_POLICY_MISSING")?;
    validate_witness_scope(
        machine_id,
        &dns.active_machine_id,
        &dns.record_name,
        &root.public_hostname,
        &line1.tunnel_domain,
        &line2.proxy_cert_cn,
        &line2.proxy_username,
        generation,
    )
    .map_err(str::to_owned)?;

    // The existing Vultr read-only owner requires exact machine NOOP and
    // verified firewall bindings. Only its observed main_ip is tested.
    let observed =
        crate::vultr_lifecycle_command::exact_existing_machine_observation(&machine, machine_id)
            .await?;
    let ip = observed
        .main_ip
        .ok_or("HOST_VM_LINE2_WITNESS_VULTR_PUBLIC_IP_UNPROVEN")?;
    let client_id = std::env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_ID")
        .map_err(|_| "HOST_VM_LINE2_WITNESS_ACCESS_CLIENT_ID_MISSING")?;
    let client_secret = std::env::var("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")
        .map_err(|_| "HOST_VM_LINE2_WITNESS_ACCESS_CLIENT_SECRET_MISSING")?;
    // Active Worker signer is proved using a fresh nonce against EXACT Git
    // authority, not inferred from the Access GET or provider metadata.
    if host.worker_authority_public_key.len() != 32 {
        return Err("HOST_VM_LINE2_WITNESS_WORKER_SIGNER_PIN_MISSING".to_owned());
    }
    edge_secrets::prove_canonical_host_signer_with_service_identity(
        &client_id,
        &client_secret,
        &host.worker_authority_public_key,
    )
    .await?;
    // Never print either Access value, retrieved proxy password or raw body.
    crate::line2_external_witness::witness_with_service_identity(
        generation,
        &ip,
        &dns.record_name,
        &line2.proxy_username,
        &client_id,
        &client_secret,
    )
    .await?;
    println!("host_vm_line2_witness_operation=issue1-comment-{comment}");
    println!("host_vm_line2_witness_machine={machine_id}");
    println!("host_vm_line2_witness_source=PROTECTED_GIT_AND_VULTR_READ_ONLY");
    println!(
        "host_vm_line2_witness_release={}",
        release.release().release_set_sha256
    );
    println!("host_vm_line2_witness_worker=VERIFIED_GIT_PINNED_ED25519");
    println!("host_vm_line2_witness_mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit(id: &str) -> Result<(), &'static str> {
        validate_witness_scope(
            id,
            "application-acceptance-5",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "acceptance",
            38503639351,
        )
    }

    #[test]
    fn line2_public_witness_requires_exact_git_selected_machine() {
        assert!(admit("application-acceptance-5").is_ok());
        for bad in [
            "",
            "application-acceptance-4",
            "production-1",
            "application/acceptance-5",
            "application-acceptance-5 ",
        ] {
            assert!(admit(bad).is_err());
        }
    }

    #[test]
    fn line2_public_witness_denies_hostname_tls_username_and_generation_drift() {
        let args = (
            "application-acceptance-5",
            "application-acceptance-5",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "miu.alegria.by",
            "acceptance",
            38503639351,
        );
        assert!(
            validate_witness_scope(
                args.0, args.1, args.2, args.3, args.4, args.5, args.6, args.7
            )
            .is_ok()
        );
        for (line1, line2, username, generation) in [
            ("foreign.example", args.5, args.6, args.7),
            (args.4, "foreign.example", args.6, args.7),
            (args.4, args.5, "root", args.7),
            (args.4, args.5, args.6, 0),
        ] {
            assert!(
                validate_witness_scope(
                    args.0, args.1, args.2, args.3, line1, line2, username, generation,
                )
                .is_err()
            );
        }
    }
}
