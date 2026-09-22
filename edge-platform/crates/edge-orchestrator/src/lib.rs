use edge_controller_core::orchestration::{
    DerivedDnsTarget, DerivedMeshRoute, MachineObservation, ReleaseContext,
    SupportAccessLeaseState, VpcObservation, derive_dns_target, derive_mesh_route,
};

#[derive(Debug, Clone)]
pub struct OrchestrationContext {
    release: ReleaseContext,
}

impl OrchestrationContext {
    pub fn new(release: ReleaseContext) -> Result<Self, String> {
        release.validate()?;
        Ok(Self { release })
    }

    pub const fn release(&self) -> &ReleaseContext {
        &self.release
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

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> ReleaseContext {
        ReleaseContext {
            source_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
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
}
