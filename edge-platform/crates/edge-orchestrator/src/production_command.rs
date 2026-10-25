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
