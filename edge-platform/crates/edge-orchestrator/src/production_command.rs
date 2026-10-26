use crate::cloudflare_dns_lifecycle_command::acceptance_verify_noop as dns_verify_noop;
use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::canonical_production_desired_state;
use std::path::Path;

pub(crate) fn validate(release_context: &OrchestrationContext) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let composition = ProductionComposition::from_proto(&desired).map_err(|err| err.to_string())?;
    print_identity(release_context, &composition, "PASS");
    Ok(())
}

/// Read-only provider boundary for the real GitHub operator workflow.
/// Not a DNS publish path, and does not depend on optional Android Mesh.
pub(crate) async fn verify_dns_noop(release_context: &OrchestrationContext) -> Result<(), String> {
    release_context.application_release_authority()?;
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let spec = Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH);
    dns_verify_noop(spec, spec).await.map_err(|err| {
        format!(
            "production DNS NOOP preflight refused: explicit authenticated cutover required: {err}"
        )
    })?;
    print_identity(release_context, &composition, "PASS");
    println!("operation=PRODUCTION_DNS_NOOP");
    println!("provider_mutations=0");
    println!("production_runtime_mutations=0");
    Ok(())
}

/// The former production first-use path provisioned SSH, installed the
/// runner out of band and created another owner chain. It is retired.
/// Only the Git-pinned /host native cloud-init enrollment may CREATE.
pub(crate) async fn enroll_runtime(
    _release_context: &OrchestrationContext,
    _edge_agent_artifact_path: &Path,
    _runner_installer_path: &Path,
) -> Result<(), String> {
    Err("PRODUCTION_ENROLL_SSH_RETIRED_USE_NATIVE_HOST_FIRST_USE".to_owned())
}

fn print_identity(
    release_context: &OrchestrationContext,
    composition: &ProductionComposition,
    status: &str,
) {
    let release = release_context.release();
    println!("status={status}");
    println!("production_authority={CANONICAL_PRODUCTION_AUTHORITY_PATH}");
    println!("environment={}", composition.environment);
    println!("machine_id={}", composition.machine_id);
    println!("public_hostname={}", composition.public_hostname);
    println!(
        "cloudflare_active_account_id={}",
        composition.cloudflare.active_account_id
    );
    println!(
        "cloudflare_shared_dns_account_id={}",
        composition.shared_dns_account_id
    );
    println!(
        "cloudflare_migration_target_present={}",
        composition.cloudflare.migration_target_account_id.is_some()
    );
    println!("one_production_vm=true");
    println!("production_acme=true");
    println!("mesh_routes_derived_from_vpc_observation=true");
    println!("firewall_rule_count={}", composition.firewall_rules.len());
    println!("release_set_sha256={}", release.release_set_sha256);
    println!("source_revision={}", release.source_revision);
    println!("gateway_image={}", release.gateway_image);
    println!("warp_egress_image={}", release.warp_egress_image);
    println!("mesh_image={}", release.mesh_image);
    println!("immutable_oci_release_identity=true");
}


/// One Git-selected project-owned hostname, physically attached to one VM.
/// Shared Cloudflare zone is a provider boundary, not an external owner.
pub(crate) async fn dns_reconcile(
    release_context: &OrchestrationContext,
    machine_id: &str,
    apply: bool,
) -> Result<(), String> {
    use crate::cloudflare_dns_lifecycle_service::{
        CloudflareDnsApiProvider, DnsExecutionPolicy, apply_dns_once, authorize_dns_apply,
        plan_dns_apply,
    };
    use edge_controller_core::cloudflare_dns_lifecycle::ApplyAction;
    use std::env;

    release_context.application_release_authority()?;
    let root = canonical_production_desired_state()?;
    let dns = root.dns.as_ref().ok_or("PROJECT_DNS_DESIRED_MISSING")?;
    if machine_id.is_empty()
        || machine_id.len() > 64
        || !machine_id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        || dns.active_machine_id != machine_id
    {
        return Err("PROJECT_DNS_ACTIVE_HOST_MISMATCH".to_owned());
    }
    let composition = ProductionComposition::from_proto(&root).map_err(|e| e.to_string())?;
    if composition.public_hostname != dns.record_name {
        return Err("PROJECT_DNS_HOSTNAME_DESIRED_MISMATCH".to_owned());
    }
    let spec = format!("infra/hosts/specs/{machine_id}.textproto");
    let (machine, application) = crate::vm_host_desired::load(Path::new(&spec))?;
    let line1 = application.runtime_policy.line1.as_ref().ok_or("PROJECT_DNS_LINE1_MISSING")?;
    let line2 = application.runtime_policy.line2.as_ref().ok_or("PROJECT_DNS_LINE2_MISSING")?;
    if line1.tunnel_domain != composition.public_hostname
        || line2.proxy_cert_cn != composition.public_hostname
    {
        return Err("PROJECT_DNS_APP_CERTIFICATE_NAME_MISMATCH".to_owned());
    }
    let vm = crate::vultr_lifecycle_command::exact_existing_machine_observation(&machine, machine_id).await?;
    let ip = vm.main_ip.ok_or("PROJECT_DNS_VM_PUBLIC_IP_MISSING")?;
    let token = env::var("CLOUDFLARE_DNS_TOKEN")
        .map_err(|_| "PROJECT_DNS_ENV_TOKEN_MISSING".to_owned())?;
    let mut provider = CloudflareDnsApiProvider::new(token)?;
    let (observed, plan) = plan_dns_apply(&mut provider, &composition.dns, &ip).await?;
    println!("main={}", release_context.release().source_revision);
    println!("release_set_sha256={}", release_context.release().release_set_sha256);
    println!("dns_owner=SING_BOX_SHARED_ZONE");
    println!("dns_machine_id={machine_id}");
    println!("dns_record={}", composition.public_hostname);
    println!("dns_target_ipv4={ip}");
    println!("dns_plan={:?}", plan.action);
    println!("dns_existing_records={}", observed.records.len());
    if !apply {
        println!("dns_mutations=0");
        println!("dns_verdict=PLAN_ONLY");
        return Ok(());
    }
    if !matches!(plan.action, ApplyAction::Update { .. } | ApplyAction::Noop) {
        return Err("PROJECT_DNS_EXISTING_RECORD_REQUIRED".to_owned());
    }
    let authorized = authorize_dns_apply(&composition.dns, &ip, &observed, plan)?;
    let report = apply_dns_once(
        &mut provider,
        &composition.dns,
        &ip,
        &authorized.authority.authority_digest,
        DnsExecutionPolicy::default(),
    ).await?;
    if !matches!(report.next_plan.action, ApplyAction::Noop) {
        return Err("PROJECT_DNS_POSTSTATE_NOT_CONVERGED".to_owned());
    }
    println!("dns_mutations={}", if matches!(report.performed, ApplyAction::Noop) { 0 } else { 1 });
    println!("dns_verdict=PROVIDER_EXACT_A_MATCH");
    Ok(())
}
