use crate::cloudflare_dns_lifecycle_command::acceptance_verify_noop as dns_verify_noop;
use crate::vultr_lifecycle_command::{
    acceptance_converge_substrate as substrate_converge, acceptance_lease_acquire as lease_acquire,
    acceptance_lease_release as lease_release, bootstrap_production_runner,
    production_converge_machine,
};
use crate::vultr_vpc_lifecycle_command::production_converge as vpc_converge;
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

pub(crate) async fn enroll_runtime(
    release_context: &OrchestrationContext,
    edge_agent_artifact_path: &Path,
    runner_installer_path: &Path,
) -> Result<(), String> {
    release_context.application_release_authority()?;
    let composition = ProductionComposition::canonical().map_err(|err| err.to_string())?;
    let spec = Path::new(CANONICAL_PRODUCTION_AUTHORITY_PATH);

    production_converge_machine(spec, &composition.machine_id).await?;
    lease_acquire(spec, &composition.machine_id).await?;

    let operation = async {
        substrate_converge(spec, &composition.machine_id).await?;
        vpc_converge(spec).await?;
        bootstrap_production_runner(
            &composition.machines,
            &composition.machine_id,
            runner_installer_path,
            edge_agent_artifact_path,
            release_context,
        )
        .await
    }
    .await;

    let release_result = lease_release(spec, &composition.machine_id).await;
    match (operation, release_result) {
        (Ok(()), Ok(())) => {
            print_identity(release_context, &composition, "PASS");
            println!("operation=ENROLL_RUNTIME");
            println!("bootstrap_transport=STRICT_SSH");
            println!("steady_state_transport=GITHUB_SELF_HOSTED_RUNNER");
            println!("transient_support_access=ABSENT");
            Ok(())
        }
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(release_err)) => Err(format!(
            "production runtime enrollment passed but transient support-access cleanup failed: {release_err}"
        )),
        (Err(err), Err(release_err)) => Err(format!(
            "{err}; transient support-access cleanup also failed: {release_err}"
        )),
    }
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
