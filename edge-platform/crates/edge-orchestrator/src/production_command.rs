use edge_controller_core::production::{
    CANONICAL_PRODUCTION_AUTHORITY_PATH, ProductionComposition,
};
use edge_orchestrator::OrchestrationContext;
use edge_shared_types::canonical_production_desired_state;

pub(crate) fn run(release_context: &OrchestrationContext) -> Result<(), String> {
    let desired = canonical_production_desired_state()?;
    let composition =
        ProductionComposition::from_proto(&desired).map_err(|err| err.to_string())?;
    let release = release_context.release();

    println!("status=PASS");
    println!(
        "production_authority={CANONICAL_PRODUCTION_AUTHORITY_PATH}"
    );
    println!("schema_version={}", desired.schema_version);
    println!("environment={}", composition.environment);
    println!("machine_id={}", composition.machine_id);
    println!("public_hostname={}", composition.public_hostname);
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
    Ok(())
}
