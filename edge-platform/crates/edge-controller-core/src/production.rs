use crate::application_lifecycle::{
    ApplicationBootstrapMode, ApplicationRuntimePolicy, DesiredApplicationState,
    Line1RuntimePolicy, Line2RuntimePolicy, SUPPORTED_APPLICATION_SCHEMA,
};
use crate::cloudflare_dns_lifecycle::DesiredDnsState;
use crate::cloudflare_mesh_lifecycle::{DesiredMeshState, MeshRouteSpec};
use crate::vultr_lifecycle::{DesiredState as DesiredMachineState, MachineSpec, ProviderSpec};
use crate::vultr_vpc_lifecycle::DesiredVpcState;
use edge_shared_types::{
    ProductionBootstrapMode, ProductionDesiredState, ProductionIpFamily,
    ProductionTransportProtocol, production_machine,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

pub const SUPPORTED_PRODUCTION_SCHEMA: u32 = 1;
pub const CANONICAL_PRODUCTION_AUTHORITY_PATH: &str =
    "infra/production/production.textproto";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionFirewallRule {
    pub protocol: &'static str,
    pub port: u16,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionComposition {
    pub environment: String,
    pub machine_id: String,
    pub public_hostname: String,
    pub machines: DesiredMachineState,
    pub vpc: DesiredVpcState,
    pub application: DesiredApplicationState,
    pub dns: DesiredDnsState,
    pub mesh: DesiredMeshState,
    pub firewall_rules: Vec<ProductionFirewallRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionSpecError {
    UnsupportedSchema(u32),
    Validation(String),
}

impl fmt::Display for ProductionSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported production desired-state schema {schema}")
            }
            Self::Validation(detail) => write!(f, "invalid production desired state: {detail}"),
        }
    }
}

impl Error for ProductionSpecError {}

impl ProductionComposition {
    pub fn from_proto(root: &ProductionDesiredState) -> Result<Self, ProductionSpecError> {
        validate_root_identity(root)?;

        let machine = root
            .machine
            .as_ref()
            .ok_or_else(|| validation("machine is required"))?;
        let vpc = root
            .vpc
            .as_ref()
            .ok_or_else(|| validation("vpc is required"))?;
        let application = root
            .application
            .as_ref()
            .ok_or_else(|| validation("application is required"))?;
        let dns = root
            .dns
            .as_ref()
            .ok_or_else(|| validation("dns is required"))?;
        let mesh = root
            .mesh
            .as_ref()
            .ok_or_else(|| validation("mesh is required"))?;
        let firewall = root
            .firewall
            .as_ref()
            .ok_or_else(|| validation("firewall is required"))?;

        let (os_id, snapshot_id) = match machine.image.as_ref() {
            Some(production_machine::Image::OsId(value)) if *value > 0 => (Some(*value), None),
            Some(production_machine::Image::SnapshotId(value)) => {
                validate_identifier("machine.snapshot_id", value)?;
                (None, Some(value.clone()))
            }
            Some(production_machine::Image::OsId(_)) => {
                return Err(validation("machine.os_id must be greater than zero"));
            }
            None => return Err(validation("machine image identity is required")),
        };

        let machines = DesiredMachineState {
            schema: 1,
            environment: root.environment.clone(),
            machines: vec![MachineSpec {
                id: root.machine_id.clone(),
                role: machine.role.clone(),
                provider: ProviderSpec {
                    region: machine.region.clone(),
                    plan: machine.plan.clone(),
                    os_id,
                    snapshot_id,
                    enable_ipv6: machine.enable_ipv6,
                    firewall_profile: Some("production".to_owned()),
                },
                bootstrap_profile: machine.bootstrap_profile.clone(),
                application_profiles: machine.application_profiles.clone(),
                tags: machine.tags.clone(),
            }],
        };
        machines
            .validate()
            .map_err(|err| component("machine", err))?;

        let vpc = DesiredVpcState {
            schema: 1,
            environment: root.environment.clone(),
            region: vpc.region.clone(),
            machine_id: root.machine_id.clone(),
        };
        vpc.validate().map_err(|err| component("vpc", err))?;

        let bootstrap_mode = ProductionBootstrapMode::try_from(application.bootstrap_mode)
            .map_err(|_| validation("application.bootstrap_mode is unknown"))?;
        let bootstrap_mode = match bootstrap_mode {
            ProductionBootstrapMode::Base => ApplicationBootstrapMode::Base,
            ProductionBootstrapMode::Tunnel => ApplicationBootstrapMode::Tunnel,
            ProductionBootstrapMode::Full => ApplicationBootstrapMode::Full,
            ProductionBootstrapMode::Unspecified => {
                return Err(validation("application.bootstrap_mode is required"));
            }
        };

        let line1 = application
            .line1
            .as_ref()
            .ok_or_else(|| validation("application.line1 is required"))?;
        let line2 = application
            .line2
            .as_ref()
            .ok_or_else(|| validation("application.line2 is required"))?;

        let application = DesiredApplicationState {
            schema: SUPPORTED_APPLICATION_SCHEMA,
            environment: root.environment.clone(),
            vultr_spec_path: CANONICAL_PRODUCTION_AUTHORITY_PATH.to_owned(),
            machine_id: root.machine_id.clone(),
            application_profile: application.application_profile.clone(),
            bundle_root: application.bundle_root.clone(),
            runtime_env_required: application.runtime_env_required,
            runtime_policy: ApplicationRuntimePolicy {
                line1: Some(Line1RuntimePolicy {
                    tunnel_domain: line1.tunnel_domain.clone(),
                    acme_email: line1.acme_email.clone(),
                    acme_provider: line1.acme_provider.clone(),
                    reality_server_name: line1.reality_server_name.clone(),
                }),
                line2: Some(Line2RuntimePolicy {
                    proxy_username: line2.proxy_username.clone(),
                    proxy_cert_cn: line2.proxy_cert_cn.clone(),
                }),
            },
            bootstrap_mode,
        };
        application
            .validate()
            .map_err(|err| component("application", err))?;

        let dns = DesiredDnsState {
            schema: 1,
            environment: root.environment.clone(),
            zone_name: dns.zone_name.clone(),
            record_name: dns.record_name.clone(),
        };
        dns.validate().map_err(|err| component("dns", err))?;

        let mesh = DesiredMeshState {
            schema: 1,
            account_id: mesh.account_id.clone(),
            environment: root.environment.clone(),
            node_name: mesh.node_name.clone(),
            routes: mesh
                .routes
                .iter()
                .map(|network| MeshRouteSpec {
                    network: network.clone(),
                })
                .collect(),
        };
        mesh.validate().map_err(|err| component("mesh", err))?;

        let firewall_rules = validate_firewall(firewall)?;

        let composition = Self {
            environment: root.environment.clone(),
            machine_id: root.machine_id.clone(),
            public_hostname: root.public_hostname.clone(),
            machines,
            vpc,
            application,
            dns,
            mesh,
            firewall_rules,
        };
        composition.validate_cross_domain()?;
        Ok(composition)
    }

    pub fn validate_cross_domain(&self) -> Result<(), ProductionSpecError> {
        let [machine] = self.machines.machines.as_slice() else {
            return Err(validation(
                "production authority must contain exactly one logical machine",
            ));
        };

        if machine.id != self.machine_id
            || self.vpc.machine_id != self.machine_id
            || self.application.machine_id != self.machine_id
        {
            return Err(validation(
                "machine, VPC and application identities must equal the production machine_id",
            ));
        }
        if self.vpc.region != machine.provider.region {
            return Err(validation(
                "VPC region must equal the production machine provider region",
            ));
        }
        if !machine
            .application_profiles
            .iter()
            .any(|profile| profile == &self.application.application_profile)
        {
            return Err(validation(
                "production machine must declare the selected application profile",
            ));
        }
        if machine.provider.firewall_profile.as_deref() != Some("production") {
            return Err(validation(
                "production machine must use the typed production firewall policy",
            ));
        }
        if self.application.bootstrap_mode != ApplicationBootstrapMode::Full {
            return Err(validation(
                "production application bootstrap_mode must be full",
            ));
        }

        let line1 = self
            .application
            .runtime_policy
            .line1
            .as_ref()
            .ok_or_else(|| validation("production runtime requires Line 1"))?;
        let line2 = self
            .application
            .runtime_policy
            .line2
            .as_ref()
            .ok_or_else(|| validation("production runtime requires Line 2"))?;

        if line1.tunnel_domain != self.public_hostname
            || line2.proxy_cert_cn != self.public_hostname
            || self.dns.record_name != self.public_hostname
        {
            return Err(validation(
                "public hostname must match Line 1, Line 2 certificate CN and DNS record",
            ));
        }
        if line1.acme_provider != "letsencrypt" {
            return Err(validation(
                "production Line 1 must use the Let’s Encrypt production authority",
            ));
        }
        if !self
            .public_hostname
            .strip_suffix(&format!(".{}", self.dns.zone_name))
            .is_some_and(|prefix| !prefix.is_empty())
        {
            return Err(validation(
                "production public hostname must be a child of the configured DNS zone",
            ));
        }

        let expected_mesh_name = format!("singbox-line3-{}", self.environment);
        if self.mesh.node_name != expected_mesh_name {
            return Err(validation(format!(
                "production Mesh node must be named {expected_mesh_name}"
            )));
        }
        if !self.mesh.routes.is_empty() {
            return Err(validation(
                "production Mesh base authority must not persist provider-derived routes",
            ));
        }

        validate_exact_firewall_surface(&self.firewall_rules)
    }
}

fn validate_root_identity(root: &ProductionDesiredState) -> Result<(), ProductionSpecError> {
    if root.schema_version != SUPPORTED_PRODUCTION_SCHEMA {
        return Err(ProductionSpecError::UnsupportedSchema(root.schema_version));
    }
    if root.environment != "production" {
        return Err(validation("environment must be exactly production"));
    }
    validate_identifier("machine_id", &root.machine_id)?;
    validate_dns_name("public_hostname", &root.public_hostname)?;
    Ok(())
}

fn validate_firewall(
    firewall: &edge_shared_types::ProductionFirewallPolicy,
) -> Result<Vec<ProductionFirewallRule>, ProductionSpecError> {
    let mut seen = BTreeSet::new();
    let mut rules = Vec::with_capacity(firewall.rules.len());

    for rule in &firewall.rules {
        let family = ProductionIpFamily::try_from(rule.ip_family)
            .map_err(|_| validation("firewall rule has an unknown IP family"))?;
        if family != ProductionIpFamily::V4 {
            return Err(validation(
                "production firewall currently permits only explicit IPv4 public listeners",
            ));
        }
        if rule.subnet != "0.0.0.0" || rule.prefix_length != 0 {
            return Err(validation(
                "production public firewall rules must use canonical 0.0.0.0/0",
            ));
        }

        let protocol = ProductionTransportProtocol::try_from(rule.protocol)
            .map_err(|_| validation("firewall rule has an unknown transport protocol"))?;
        let protocol = match protocol {
            ProductionTransportProtocol::Tcp => "tcp",
            ProductionTransportProtocol::Udp => "udp",
            ProductionTransportProtocol::Unspecified => {
                return Err(validation("firewall rule protocol is required"));
            }
        };
        let port = rule
            .port
            .parse::<u16>()
            .map_err(|_| validation("firewall rule port must be one numeric port"))?;
        if port == 0 {
            return Err(validation("firewall rule port must be non-zero"));
        }
        if rule.purpose.is_empty() || rule.purpose.len() > 160 {
            return Err(validation(
                "firewall rule purpose must be a bounded non-empty description",
            ));
        }

        if !seen.insert((protocol, port)) {
            return Err(validation(format!(
                "duplicate production firewall listener {protocol}:{port}"
            )));
        }
        rules.push(ProductionFirewallRule {
            protocol,
            port,
            purpose: rule.purpose.clone(),
        });
    }

    validate_exact_firewall_surface(&rules)?;
    Ok(rules)
}

fn validate_exact_firewall_surface(
    rules: &[ProductionFirewallRule],
) -> Result<(), ProductionSpecError> {
    let observed = rules
        .iter()
        .map(|rule| (rule.protocol, rule.port))
        .collect::<BTreeSet<_>>();
    let expected = [
        ("tcp", 80),
        ("tcp", 443),
        ("udp", 8443),
        ("tcp", 5443),
        ("udp", 9444),
        ("tcp", 3128),
        ("tcp", 1080),
        ("tcp", 9443),
        ("tcp", 4128),
        ("tcp", 4080),
        ("tcp", 4443),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    if observed != expected {
        return Err(validation(format!(
            "production firewall surface differs from the exact Line 1/Line 2 listener set: expected {expected:?}, observed {observed:?}"
        )));
    }
    if observed.iter().any(|(_, port)| *port == 22) {
        return Err(validation(
            "production firewall must not contain persistent public SSH",
        ));
    }
    Ok(())
}

fn component(label: &str, err: impl fmt::Display) -> ProductionSpecError {
    validation(format!("{label} desired state is invalid: {err}"))
}

fn validation(message: impl Into<String>) -> ProductionSpecError {
    ProductionSpecError::Validation(message.into())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ProductionSpecError> {
    if value.is_empty()
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(validation(format!(
            "{label} must be a non-empty canonical identifier"
        )));
    }
    Ok(())
}

fn validate_dns_name(label: &str, value: &str) -> Result<(), ProductionSpecError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || !value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
    {
        return Err(validation(format!(
            "{label} must be a canonical lowercase DNS name"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{
        ProductionFirewallRule as ProtoFirewallRule, canonical_production_desired_state,
    };

    fn canonical() -> ProductionDesiredState {
        canonical_production_desired_state().unwrap()
    }

    #[test]
    fn canonical_production_composition_is_exact_and_closed() {
        let composition = ProductionComposition::from_proto(&canonical()).unwrap();
        assert_eq!(composition.machine_id, "production-1");
        assert_eq!(composition.public_hostname, "miu.alegria.by");
        assert_eq!(composition.machines.machines.len(), 1);
        assert_eq!(composition.firewall_rules.len(), 11);
    }

    #[test]
    fn production_authority_rejects_nonproduction_environment() {
        let mut desired = canonical();
        desired.environment = "staging".to_owned();
        assert!(
            ProductionComposition::from_proto(&desired)
                .unwrap_err()
                .to_string()
                .contains("exactly production")
        );
    }

    #[test]
    fn production_authority_rejects_staging_acme() {
        let mut desired = canonical();
        desired
            .application
            .as_mut()
            .unwrap()
            .line1
            .as_mut()
            .unwrap()
            .acme_provider =
            "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned();
        assert!(
            ProductionComposition::from_proto(&desired)
                .unwrap_err()
                .to_string()
                .contains("production authority")
        );
    }

    #[test]
    fn production_authority_rejects_provider_derived_mesh_routes() {
        let mut desired = canonical();
        desired
            .mesh
            .as_mut()
            .unwrap()
            .routes
            .push("10.0.0.0/24".to_owned());
        assert!(
            ProductionComposition::from_proto(&desired)
                .unwrap_err()
                .to_string()
                .contains("provider-derived routes")
        );
    }

    #[test]
    fn production_authority_rejects_extra_public_listener() {
        let mut desired = canonical();
        desired
            .firewall
            .as_mut()
            .unwrap()
            .rules
            .push(ProtoFirewallRule {
                ip_family: ProductionIpFamily::V4 as i32,
                protocol: ProductionTransportProtocol::Tcp as i32,
                subnet: "0.0.0.0".to_owned(),
                prefix_length: 0,
                port: "22".to_owned(),
                purpose: "forbidden persistent SSH".to_owned(),
            });
        assert!(ProductionComposition::from_proto(&desired).is_err());
    }
}
