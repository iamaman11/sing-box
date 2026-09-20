use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use std::net::Ipv4Addr;

pub const CURRENT_SCHEMA: u32 = 1;
const DESCRIPTION_PREFIX: &str = "managed-by-sing-box:vpc:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredVpcState {
    pub schema: u32,
    pub environment: String,
    pub region: String,
    pub machine_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedVpc {
    pub provider_id: String,
    pub region: String,
    pub description: String,
    pub v4_subnet: String,
    pub v4_subnet_mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VpcObservation {
    pub vpcs: Vec<ObservedVpc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedVpcAttachment {
    pub attachment_id: String,
    pub subscription_id: String,
    pub private_ipv4: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VpcAttachmentObservation {
    pub attachments: Vec<ObservedVpcAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VpcApplyAction {
    Noop,
    CreateVpc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpcApplyPlan {
    pub action: VpcApplyAction,
    pub provider_id: Option<String>,
    pub cidr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttachmentAction {
    Noop,
    AttachInstance { vpc_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentPlan {
    pub action: AttachmentAction,
    pub cidr: String,
    pub private_ipv4: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupAction {
    Noop,
    DetachInstance { vpc_id: String, instance_id: String },
    DeleteVpc { vpc_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupPlan {
    pub action: CleanupAction,
    pub destructive_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpcLifecycleError {
    Json(String),
    UnsupportedSchema(u32),
    Validation(String),
    Ambiguous(String),
    Conflict(String),
    Serialization(String),
}

impl fmt::Display for VpcLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message)
            | Self::Validation(message)
            | Self::Ambiguous(message)
            | Self::Conflict(message)
            | Self::Serialization(message) => f.write_str(message),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported Vultr VPC lifecycle schema {schema}")
            }
        }
    }
}

impl std::error::Error for VpcLifecycleError {}

impl DesiredVpcState {
    pub fn parse_json(input: &str) -> Result<Self, VpcLifecycleError> {
        let desired: Self =
            serde_json::from_str(input).map_err(|err| VpcLifecycleError::Json(err.to_string()))?;
        desired.validate()?;
        Ok(desired)
    }

    pub fn validate(&self) -> Result<(), VpcLifecycleError> {
        if self.schema != CURRENT_SCHEMA {
            return Err(VpcLifecycleError::UnsupportedSchema(self.schema));
        }
        validate_identifier("environment", &self.environment, 64)?;
        validate_identifier("machine_id", &self.machine_id, 64)?;
        if self.region.is_empty()
            || self.region.len() > 32
            || !self
                .region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(VpcLifecycleError::Validation(
                "region must be 1..=32 lowercase ASCII alphanumeric or '-' characters".to_owned(),
            ));
        }
        if self.ownership_description().len() > 255 {
            return Err(VpcLifecycleError::Validation(
                "derived Vultr VPC ownership description exceeds 255 characters".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn ownership_description(&self) -> String {
        format!(
            "{DESCRIPTION_PREFIX}{}:{}",
            self.environment, self.machine_id
        )
    }
}

pub fn plan_vpc_apply(
    desired: &DesiredVpcState,
    observed: &VpcObservation,
) -> Result<VpcApplyPlan, VpcLifecycleError> {
    desired.validate()?;
    let Some(vpc) = select_exact_vpc(desired, observed)? else {
        return Ok(VpcApplyPlan {
            action: VpcApplyAction::CreateVpc,
            provider_id: None,
            cidr: None,
        });
    };
    if vpc.region != desired.region {
        return Err(VpcLifecycleError::Conflict(format!(
            "owned Vultr VPC {} is in region {}, expected {}",
            vpc.provider_id, vpc.region, desired.region
        )));
    }
    let cidr = observed_cidr(vpc)?;
    Ok(VpcApplyPlan {
        action: VpcApplyAction::Noop,
        provider_id: Some(vpc.provider_id.clone()),
        cidr: Some(cidr),
    })
}

pub fn plan_attachment(
    desired: &DesiredVpcState,
    observed: &VpcObservation,
    attachments: &VpcAttachmentObservation,
    target_instance_id: &str,
) -> Result<AttachmentPlan, VpcLifecycleError> {
    desired.validate()?;
    if target_instance_id.trim().is_empty() {
        return Err(VpcLifecycleError::Validation(
            "target Vultr instance provider id is required".to_owned(),
        ));
    }
    let vpc = select_exact_vpc(desired, observed)?.ok_or_else(|| {
        VpcLifecycleError::Conflict(
            "owned Vultr VPC is absent; create it before attachment".to_owned(),
        )
    })?;
    if vpc.region != desired.region {
        return Err(VpcLifecycleError::Conflict(format!(
            "owned Vultr VPC {} is in region {}, expected {}",
            vpc.provider_id, vpc.region, desired.region
        )));
    }
    let cidr = observed_cidr(vpc)?;
    reject_foreign_attachments(attachments, target_instance_id)?;

    let matching = attachments
        .attachments
        .iter()
        .filter(|attachment| attachment.subscription_id == target_instance_id)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [] => Ok(AttachmentPlan {
            action: AttachmentAction::AttachInstance {
                vpc_id: vpc.provider_id.clone(),
            },
            cidr,
            private_ipv4: None,
        }),
        [attachment] => {
            validate_private_ip_in_cidr(&attachment.private_ipv4, vpc)?;
            Ok(AttachmentPlan {
                action: AttachmentAction::Noop,
                cidr,
                private_ipv4: Some(attachment.private_ipv4.clone()),
            })
        }
        _ => Err(VpcLifecycleError::Ambiguous(format!(
            "Vultr VPC {} has multiple attachments for target instance {}",
            vpc.provider_id, target_instance_id
        ))),
    }
}

pub fn plan_cleanup(
    desired: &DesiredVpcState,
    observed: &VpcObservation,
    attachments: &VpcAttachmentObservation,
    target_instance_id: Option<&str>,
) -> Result<CleanupPlan, VpcLifecycleError> {
    desired.validate()?;
    let Some(vpc) = select_exact_vpc(desired, observed)? else {
        return Ok(CleanupPlan {
            action: CleanupAction::Noop,
            destructive_digest: None,
        });
    };
    if vpc.region != desired.region {
        return Err(VpcLifecycleError::Conflict(format!(
            "refusing Vultr VPC cleanup because owned identity is in region {}, expected {}",
            vpc.region, desired.region
        )));
    }
    observed_cidr(vpc)?;

    let action = if attachments.attachments.is_empty() {
        CleanupAction::DeleteVpc {
            vpc_id: vpc.provider_id.clone(),
        }
    } else {
        let target_instance_id = target_instance_id.ok_or_else(|| {
            VpcLifecycleError::Conflict(
                "refusing Vultr VPC cleanup because attachments exist but target instance is absent"
                    .to_owned(),
            )
        })?;
        reject_foreign_attachments(attachments, target_instance_id)?;
        let matching = attachments
            .attachments
            .iter()
            .filter(|attachment| attachment.subscription_id == target_instance_id)
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [attachment] => {
                validate_private_ip_in_cidr(&attachment.private_ipv4, vpc)?;
                CleanupAction::DetachInstance {
                    vpc_id: vpc.provider_id.clone(),
                    instance_id: target_instance_id.to_owned(),
                }
            }
            [] => {
                return Err(VpcLifecycleError::Conflict(
                    "Vultr VPC reports attachments but none belong to the exact target instance"
                        .to_owned(),
                ));
            }
            _ => {
                return Err(VpcLifecycleError::Ambiguous(format!(
                    "Vultr VPC {} has multiple attachments for target instance {}",
                    vpc.provider_id, target_instance_id
                )));
            }
        }
    };

    Ok(CleanupPlan {
        destructive_digest: Some(cleanup_digest(desired, observed, attachments, &action)?),
        action,
    })
}

pub fn verify_cleanup_digest(
    desired: &DesiredVpcState,
    observed: &VpcObservation,
    attachments: &VpcAttachmentObservation,
    target_instance_id: Option<&str>,
    expected_digest: &str,
) -> Result<CleanupPlan, VpcLifecycleError> {
    if !is_sha256_hex(expected_digest) {
        return Err(VpcLifecycleError::Validation(
            "Vultr VPC cleanup digest must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    let plan = plan_cleanup(desired, observed, attachments, target_instance_id)?;
    let Some(actual) = plan.destructive_digest.as_deref() else {
        return Err(VpcLifecycleError::Conflict(
            "Vultr VPC cleanup target is already absent".to_owned(),
        ));
    };
    if actual != expected_digest {
        return Err(VpcLifecycleError::Conflict(
            "Vultr VPC cleanup digest is stale".to_owned(),
        ));
    }
    Ok(plan)
}

fn select_exact_vpc<'a>(
    desired: &DesiredVpcState,
    observed: &'a VpcObservation,
) -> Result<Option<&'a ObservedVpc>, VpcLifecycleError> {
    let description = desired.ownership_description();
    let matches = observed
        .vpcs
        .iter()
        .filter(|vpc| vpc.description == description)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [vpc] => Ok(Some(*vpc)),
        _ => Err(VpcLifecycleError::Ambiguous(format!(
            "Vultr VPC ownership description {} is ambiguous: observed {} exact matches",
            description,
            matches.len()
        ))),
    }
}

fn observed_cidr(vpc: &ObservedVpc) -> Result<String, VpcLifecycleError> {
    let subnet = vpc.v4_subnet.parse::<Ipv4Addr>().map_err(|err| {
        VpcLifecycleError::Conflict(format!(
            "Vultr VPC {} returned invalid IPv4 subnet {}: {err}",
            vpc.provider_id, vpc.v4_subnet
        ))
    })?;
    if !subnet.is_private() {
        return Err(VpcLifecycleError::Conflict(format!(
            "Vultr VPC {} returned non-private IPv4 subnet {}",
            vpc.provider_id, vpc.v4_subnet
        )));
    }
    if !(1..=32).contains(&vpc.v4_subnet_mask) {
        return Err(VpcLifecycleError::Conflict(format!(
            "Vultr VPC {} returned invalid IPv4 prefix length {}",
            vpc.provider_id, vpc.v4_subnet_mask
        )));
    }
    let mask = u32::MAX << (32 - u32::from(vpc.v4_subnet_mask));
    let canonical = Ipv4Addr::from(u32::from(subnet) & mask);
    if canonical != subnet {
        return Err(VpcLifecycleError::Conflict(format!(
            "Vultr VPC {} returned non-canonical subnet {}/{}; expected {}/{}",
            vpc.provider_id, vpc.v4_subnet, vpc.v4_subnet_mask, canonical, vpc.v4_subnet_mask
        )));
    }
    Ok(format!("{subnet}/{}", vpc.v4_subnet_mask))
}

fn validate_private_ip_in_cidr(value: &str, vpc: &ObservedVpc) -> Result<(), VpcLifecycleError> {
    let ip = value.parse::<Ipv4Addr>().map_err(|err| {
        VpcLifecycleError::Conflict(format!(
            "Vultr VPC attachment returned invalid private IPv4 {value}: {err}"
        ))
    })?;
    if !ip.is_private() {
        return Err(VpcLifecycleError::Conflict(format!(
            "Vultr VPC attachment returned non-private IPv4 {value}"
        )));
    }
    let subnet = vpc.v4_subnet.parse::<Ipv4Addr>().map_err(|err| {
        VpcLifecycleError::Conflict(format!(
            "Vultr VPC {} returned invalid IPv4 subnet {}: {err}",
            vpc.provider_id, vpc.v4_subnet
        ))
    })?;
    let mask = u32::MAX << (32 - u32::from(vpc.v4_subnet_mask));
    if (u32::from(ip) & mask) != u32::from(subnet) {
        return Err(VpcLifecycleError::Conflict(format!(
            "Vultr VPC attachment private IPv4 {value} is outside {}/{}",
            vpc.v4_subnet, vpc.v4_subnet_mask
        )));
    }
    Ok(())
}

fn reject_foreign_attachments(
    attachments: &VpcAttachmentObservation,
    target_instance_id: &str,
) -> Result<(), VpcLifecycleError> {
    if let Some(foreign) = attachments
        .attachments
        .iter()
        .find(|attachment| attachment.subscription_id != target_instance_id)
    {
        return Err(VpcLifecycleError::Conflict(format!(
            "owned disposable Vultr VPC has foreign attachment {}",
            foreign.attachment_id
        )));
    }
    Ok(())
}

fn cleanup_digest(
    desired: &DesiredVpcState,
    observed: &VpcObservation,
    attachments: &VpcAttachmentObservation,
    action: &CleanupAction,
) -> Result<String, VpcLifecycleError> {
    let description = desired.ownership_description();
    let mut vpcs = observed
        .vpcs
        .iter()
        .filter(|vpc| vpc.description == description)
        .cloned()
        .collect::<Vec<_>>();
    vpcs.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));

    let mut attached = attachments.attachments.clone();
    attached.sort_by(|left, right| {
        left.subscription_id
            .cmp(&right.subscription_id)
            .then_with(|| left.attachment_id.cmp(&right.attachment_id))
    });

    let value = json!({
        "schema": desired.schema,
        "environment": desired.environment,
        "region": desired.region,
        "machine_id": desired.machine_id,
        "vpcs": vpcs,
        "attachments": attached,
        "action": action,
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|err| VpcLifecycleError::Serialization(err.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn validate_identifier(label: &str, value: &str, max_len: usize) -> Result<(), VpcLifecycleError> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err(VpcLifecycleError::Validation(format!(
            "{label} must be 1..={max_len} ASCII alphanumeric, '-' or '_' characters"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> DesiredVpcState {
        DesiredVpcState {
            schema: 1,
            environment: "application-acceptance".to_owned(),
            region: "waw".to_owned(),
            machine_id: "application-acceptance-1".to_owned(),
        }
    }

    fn vpc() -> ObservedVpc {
        ObservedVpc {
            provider_id: "vpc-1".to_owned(),
            region: "waw".to_owned(),
            description: "managed-by-sing-box:vpc:application-acceptance:application-acceptance-1"
                .to_owned(),
            v4_subnet: "10.0.4.0".to_owned(),
            v4_subnet_mask: 24,
        }
    }

    fn attachment(instance: &str, ip: &str) -> ObservedVpcAttachment {
        ObservedVpcAttachment {
            attachment_id: "attachment-1".to_owned(),
            subscription_id: instance.to_owned(),
            private_ipv4: ip.to_owned(),
        }
    }

    #[test]
    fn strict_spec_derives_owned_description_without_cidr_authority() {
        let parsed = DesiredVpcState::parse_json(
            r#"{"schema":1,"environment":"application-acceptance","region":"waw","machine_id":"application-acceptance-1"}"#,
        )
        .unwrap();
        assert_eq!(
            parsed.ownership_description(),
            "managed-by-sing-box:vpc:application-acceptance:application-acceptance-1"
        );
        assert!(DesiredVpcState::parse_json(
            r#"{"schema":1,"environment":"application-acceptance","region":"waw","machine_id":"application-acceptance-1","cidr":"10.0.0.0/24"}"#
        )
        .is_err());
    }

    #[test]
    fn vpc_apply_is_create_then_noop_with_provider_observed_cidr() {
        let empty = VpcObservation::default();
        assert_eq!(
            plan_vpc_apply(&desired(), &empty).unwrap().action,
            VpcApplyAction::CreateVpc
        );

        let observed = VpcObservation { vpcs: vec![vpc()] };
        let plan = plan_vpc_apply(&desired(), &observed).unwrap();
        assert_eq!(plan.action, VpcApplyAction::Noop);
        assert_eq!(plan.cidr.as_deref(), Some("10.0.4.0/24"));
    }

    #[test]
    fn vpc_apply_fails_closed_on_ambiguity_or_wrong_region() {
        let observed = VpcObservation {
            vpcs: vec![
                vpc(),
                ObservedVpc {
                    provider_id: "vpc-2".to_owned(),
                    ..vpc()
                },
            ],
        };
        assert!(matches!(
            plan_vpc_apply(&desired(), &observed),
            Err(VpcLifecycleError::Ambiguous(_))
        ));

        let wrong = VpcObservation {
            vpcs: vec![ObservedVpc {
                region: "fra".to_owned(),
                ..vpc()
            }],
        };
        assert!(matches!(
            plan_vpc_apply(&desired(), &wrong),
            Err(VpcLifecycleError::Conflict(_))
        ));
    }

    #[test]
    fn provider_observed_subnet_must_be_private_and_canonical() {
        for subnet in ["203.0.113.0", "10.0.4.7"] {
            let observed = VpcObservation {
                vpcs: vec![ObservedVpc {
                    v4_subnet: subnet.to_owned(),
                    ..vpc()
                }],
            };
            assert!(plan_vpc_apply(&desired(), &observed).is_err());
        }
    }

    #[test]
    fn attachment_is_attach_then_noop_and_validates_private_ip() {
        let observed = VpcObservation { vpcs: vec![vpc()] };
        let target = "instance-1";
        let plan = plan_attachment(
            &desired(),
            &observed,
            &VpcAttachmentObservation::default(),
            target,
        )
        .unwrap();
        assert!(matches!(
            plan.action,
            AttachmentAction::AttachInstance { .. }
        ));

        let attachments = VpcAttachmentObservation {
            attachments: vec![attachment(target, "10.0.4.2")],
        };
        let plan = plan_attachment(&desired(), &observed, &attachments, target).unwrap();
        assert_eq!(plan.action, AttachmentAction::Noop);
        assert_eq!(plan.private_ipv4.as_deref(), Some("10.0.4.2"));
    }

    #[test]
    fn foreign_vpc_attachment_is_never_adopted() {
        let observed = VpcObservation { vpcs: vec![vpc()] };
        let attachments = VpcAttachmentObservation {
            attachments: vec![attachment("foreign-instance", "10.0.4.3")],
        };
        assert!(matches!(
            plan_attachment(&desired(), &observed, &attachments, "instance-1"),
            Err(VpcLifecycleError::Conflict(_))
        ));
    }

    #[test]
    fn cleanup_is_detach_then_delete_and_digest_bound() {
        let observed = VpcObservation { vpcs: vec![vpc()] };
        let attachments = VpcAttachmentObservation {
            attachments: vec![attachment("instance-1", "10.0.4.2")],
        };
        let detach = plan_cleanup(&desired(), &observed, &attachments, Some("instance-1")).unwrap();
        assert!(matches!(
            detach.action,
            CleanupAction::DetachInstance { .. }
        ));
        let digest = detach.destructive_digest.clone().unwrap();
        verify_cleanup_digest(
            &desired(),
            &observed,
            &attachments,
            Some("instance-1"),
            &digest,
        )
        .unwrap();

        let absent_attachment = VpcAttachmentObservation::default();
        let delete = plan_cleanup(
            &desired(),
            &observed,
            &absent_attachment,
            Some("instance-1"),
        )
        .unwrap();
        assert!(matches!(delete.action, CleanupAction::DeleteVpc { .. }));
        assert!(
            verify_cleanup_digest(
                &desired(),
                &observed,
                &absent_attachment,
                Some("instance-1"),
                &digest
            )
            .is_err()
        );
    }
}
