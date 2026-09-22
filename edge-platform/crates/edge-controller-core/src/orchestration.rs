use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrchestrationScope {
    Substrate,
    Application,
    Mesh,
    Production,
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineObservation {
    pub provider_id: String,
    pub main_ipv4: String,
}

impl MachineObservation {
    pub fn validate(&self) -> Result<(), String> {
        require_non_empty("machine provider_id", &self.provider_id)?;
        parse_ipv4("machine main_ipv4", &self.main_ipv4)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpcObservation {
    pub provider_id: String,
    pub cidr: String,
    pub private_ipv4: String,
}

impl VpcObservation {
    pub fn validate(&self) -> Result<(), String> {
        require_non_empty("VPC provider_id", &self.provider_id)?;
        canonical_ipv4_cidr(&self.cidr)?;
        parse_ipv4("VPC private_ipv4", &self.private_ipv4)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedDnsTarget {
    pub source_provider_id: String,
    pub target_ipv4: String,
}

pub fn derive_dns_target(observed: &MachineObservation) -> Result<DerivedDnsTarget, String> {
    observed.validate()?;
    let target = parse_ipv4("machine main_ipv4", &observed.main_ipv4)?;
    Ok(DerivedDnsTarget {
        source_provider_id: observed.provider_id.clone(),
        target_ipv4: target.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedMeshRoute {
    pub source_vpc_id: String,
    pub network: String,
    pub private_ipv4: String,
}

pub fn derive_mesh_route(observed: &VpcObservation) -> Result<DerivedMeshRoute, String> {
    observed.validate()?;
    Ok(DerivedMeshRoute {
        source_vpc_id: observed.provider_id.clone(),
        network: canonical_ipv4_cidr(&observed.cidr)?,
        private_ipv4: parse_ipv4("VPC private_ipv4", &observed.private_ipv4)?.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportAccessLeasePhase {
    Absent,
    Acquired,
    Ready,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportAccessLeaseState {
    phase: SupportAccessLeasePhase,
}

impl Default for SupportAccessLeaseState {
    fn default() -> Self {
        Self {
            phase: SupportAccessLeasePhase::Absent,
        }
    }
}

impl SupportAccessLeaseState {
    pub const fn phase(&self) -> SupportAccessLeasePhase {
        self.phase
    }

    pub fn acquired(&mut self) -> Result<(), String> {
        self.transition(
            SupportAccessLeasePhase::Absent,
            SupportAccessLeasePhase::Acquired,
        )
    }

    pub fn ready(&mut self) -> Result<(), String> {
        self.transition(
            SupportAccessLeasePhase::Acquired,
            SupportAccessLeasePhase::Ready,
        )
    }

    pub fn released(&mut self) -> Result<(), String> {
        self.transition(
            SupportAccessLeasePhase::Ready,
            SupportAccessLeasePhase::Released,
        )
    }

    fn transition(
        &mut self,
        expected: SupportAccessLeasePhase,
        next: SupportAccessLeasePhase,
    ) -> Result<(), String> {
        if self.phase != expected {
            return Err(format!(
                "invalid support-access lease transition: current={:?}, expected={expected:?}, next={next:?}",
                self.phase
            ));
        }
        self.phase = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseContext {
    pub source_revision: String,
    pub release_set_sha256: String,
    pub docker_engine_version: String,
    pub containerd_version: String,
    pub compose_version: String,
    pub gateway_image: String,
    pub warp_egress_image: String,
    pub mesh_image: String,
}

impl ReleaseContext {
    pub fn validate(&self) -> Result<(), String> {
        validate_lower_hex("source_revision", &self.source_revision, 40)?;
        validate_lower_hex("release_set_sha256", &self.release_set_sha256, 64)?;
        validate_package_version("docker_engine_version", &self.docker_engine_version)?;
        validate_package_version("containerd_version", &self.containerd_version)?;
        validate_package_version("compose_version", &self.compose_version)?;
        validate_digest_pinned_image("gateway_image", &self.gateway_image)?;
        validate_digest_pinned_image("warp_egress_image", &self.warp_egress_image)?;
        validate_digest_pinned_image("mesh_image", &self.mesh_image)?;
        Ok(())
    }
}

fn parse_ipv4(label: &str, value: &str) -> Result<Ipv4Addr, String> {
    Ipv4Addr::from_str(value.trim()).map_err(|_| format!("{label} must be an exact IPv4 address"))
}

fn canonical_ipv4_cidr(value: &str) -> Result<String, String> {
    let (address, prefix) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| "VPC cidr must be an IPv4 CIDR".to_owned())?;
    let address = parse_ipv4("VPC cidr address", address)?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "VPC cidr prefix must be an integer".to_owned())?;
    if prefix > 32 {
        return Err("VPC cidr prefix must be <= 32".to_owned());
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let raw = u32::from(address);
    let network = Ipv4Addr::from(raw & mask);
    if network != address {
        return Err(format!(
            "VPC cidr must be canonical network address: expected {network}/{prefix}"
        ));
    }
    Ok(format!("{network}/{prefix}"))
}

fn require_non_empty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(())
}

fn validate_lower_hex(label: &str, value: &str, length: usize) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {length} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_package_version(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b':' | b'~' | b'_' | b'-')
        })
    {
        return Err(format!("{label} must be a safe exact package version"));
    }
    Ok(())
}

fn validate_digest_pinned_image(label: &str, value: &str) -> Result<(), String> {
    let (_, digest) = value
        .rsplit_once("@sha256:")
        .ok_or_else(|| format!("{label} must be digest-pinned with @sha256:"))?;
    validate_lower_hex(label, digest, 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(ip: &str) -> MachineObservation {
        MachineObservation {
            provider_id: "vm-1".to_owned(),
            main_ipv4: ip.to_owned(),
        }
    }

    fn vpc(cidr: &str) -> VpcObservation {
        VpcObservation {
            provider_id: "vpc-1".to_owned(),
            cidr: cidr.to_owned(),
            private_ipv4: "10.27.96.3".to_owned(),
        }
    }

    #[test]
    fn dns_target_is_derived_only_from_current_machine_observation() {
        let first = derive_dns_target(&machine("203.0.113.10")).unwrap();
        let second = derive_dns_target(&machine("203.0.113.11")).unwrap();

        assert_eq!(first.target_ipv4, "203.0.113.10");
        assert_eq!(second.target_ipv4, "203.0.113.11");
        assert_ne!(first, second);
    }

    #[test]
    fn changed_machine_observation_changes_dns_plan_without_source_edit() {
        use crate::cloudflare_dns_lifecycle::{
            ApplyAction, DesiredDnsState, DnsObservation, ObservedDnsRecord, plan_apply,
        };

        let desired = DesiredDnsState {
            schema: 1,
            environment: "acceptance".to_owned(),
            zone_name: "example.com".to_owned(),
            record_name: "edge.example.com".to_owned(),
        };
        let observed_dns = DnsObservation {
            records: vec![ObservedDnsRecord {
                id: "record-1".to_owned(),
                name: "edge.example.com".to_owned(),
                ip: "203.0.113.10".to_owned(),
            }],
        };

        let first = derive_dns_target(&machine("203.0.113.10")).unwrap();
        let second = derive_dns_target(&machine("203.0.113.11")).unwrap();
        let first_plan = plan_apply(&desired, &first.target_ipv4, &observed_dns).unwrap();
        let second_plan = plan_apply(&desired, &second.target_ipv4, &observed_dns).unwrap();

        assert!(matches!(first_plan.action, ApplyAction::Noop));
        assert!(matches!(second_plan.action, ApplyAction::Update { .. }));
    }

    #[test]
    fn mesh_route_is_derived_only_from_verified_vpc_observation() {
        let first = derive_mesh_route(&vpc("10.27.96.0/20")).unwrap();
        let second = derive_mesh_route(&vpc("10.28.0.0/20")).unwrap();

        assert_eq!(first.network, "10.27.96.0/20");
        assert_eq!(second.network, "10.28.0.0/20");
        assert_ne!(first, second);
    }

    #[test]
    fn non_canonical_vpc_cidr_fails_closed() {
        let error = derive_mesh_route(&vpc("10.27.96.3/20")).unwrap_err();
        assert!(error.contains("canonical network address"));
    }

    #[test]
    fn support_access_lease_requires_exact_order() {
        let mut lease = SupportAccessLeaseState::default();
        assert_eq!(lease.phase(), SupportAccessLeasePhase::Absent);
        lease.acquired().unwrap();
        lease.ready().unwrap();
        lease.released().unwrap();
        assert_eq!(lease.phase(), SupportAccessLeasePhase::Released);
    }

    #[test]
    fn support_access_lease_rejects_skipped_or_replayed_transitions() {
        let mut lease = SupportAccessLeaseState::default();
        assert!(lease.ready().is_err());
        lease.acquired().unwrap();
        assert!(lease.acquired().is_err());
        lease.ready().unwrap();
        lease.released().unwrap();
        assert!(lease.released().is_err());
    }

    #[test]
    fn release_context_requires_exact_immutable_inputs() {
        let context = ReleaseContext {
            source_revision: "a".repeat(40),
            release_set_sha256: "b".repeat(64),
            docker_engine_version: "5:28.4.0-1~debian.13~trixie".to_owned(),
            containerd_version: "1.7.27-1".to_owned(),
            compose_version: "2.39.4-1~debian.13~trixie".to_owned(),
            gateway_image: format!("ghcr.io/example/gateway@sha256:{}", "c".repeat(64)),
            warp_egress_image: format!("ghcr.io/example/warp@sha256:{}", "d".repeat(64)),
            mesh_image: format!("docker.io/cloudflare/mesh@sha256:{}", "e".repeat(64)),
        };

        context.validate().unwrap();

        let mut mutable = context;
        mutable.mesh_image = "docker.io/cloudflare/mesh:latest".to_owned();
        assert!(mutable.validate().is_err());
    }
}
