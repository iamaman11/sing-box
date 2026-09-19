use edge_controller_core::vultr_lifecycle::{
    DesiredState, LifecycleInventory, MachineSpec, ObservedMachine, build_inventory,
    decode_provider_tags, provider_tags_for_machine,
};
use edge_provider_vultr::VultrInstance;
use std::collections::BTreeMap;

pub fn normalize_vultr_instance(instance: &VultrInstance) -> Result<ObservedMachine, String> {
    normalize_vultr_instance_with_firewall_profiles(instance, &BTreeMap::new())
}

pub fn normalize_vultr_instance_with_firewall_profiles(
    instance: &VultrInstance,
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<ObservedMachine, String> {
    let decoded = decode_provider_tags(&instance.tags).map_err(|err| {
        format!(
            "invalid lifecycle identity on Vultr instance {}: {err}",
            instance.id
        )
    })?;
    let firewall_group_id = nonempty(&instance.firewall_group_id);
    let firewall_profile = firewall_group_id
        .as_ref()
        .and_then(|group_id| verified_firewall_profiles.get(group_id))
        .cloned();

    Ok(ObservedMachine {
        provider_id: instance.id.clone(),
        label: instance.label.clone(),
        ownership: decoded.ownership,
        region: instance.region.clone(),
        plan: instance.plan.clone(),
        main_ip: nonempty(&instance.main_ip),
        v6_main_ip: nonempty(&instance.v6_main_ip),
        firewall_group_id,
        date_created: nonempty(&instance.date_created),
        os_id: (instance.os_id != 0).then_some(instance.os_id),
        snapshot_id: instance.snapshot_id.clone(),
        enable_ipv6: instance.enable_ipv6,
        firewall_profile,
        tags: decoded.user_tags,
        spec_digest: decoded.spec_digest,
    })
}

fn nonempty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

pub fn normalize_vultr_inventory(
    desired: &DesiredState,
    instances: &[VultrInstance],
) -> Result<LifecycleInventory, String> {
    normalize_vultr_inventory_with_firewall_profiles(desired, instances, &BTreeMap::new())
}

pub fn normalize_vultr_inventory_with_firewall_profiles(
    desired: &DesiredState,
    instances: &[VultrInstance],
    verified_firewall_profiles: &BTreeMap<String, String>,
) -> Result<LifecycleInventory, String> {
    let resources = instances
        .iter()
        .map(|instance| {
            normalize_vultr_instance_with_firewall_profiles(instance, verified_firewall_profiles)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(build_inventory(desired, resources))
}

pub fn managed_provider_tags(
    desired: &DesiredState,
    machine: &MachineSpec,
) -> Result<Vec<String>, String> {
    provider_tags_for_machine(desired, machine).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_controller_core::vultr_lifecycle::{MANAGED_BY_IDENTITY, PlanClass, plan_machine};
    use edge_provider_vultr::mock_instance;

    fn desired() -> DesiredState {
        DesiredState::parse_json(
            r#"{
  "schema": 1,
  "environment": "production",
  "machines": [
    {
      "id": "edge-1",
      "role": "edge",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "os_id": 2625,
        "enable_ipv6": false
      },
      "bootstrap_profile": "singbox-host-v1",
      "application_profiles": ["singbox-edge"],
      "tags": ["primary"]
    }
  ]
}"#,
        )
        .unwrap()
    }

    #[test]
    fn projects_real_provider_shape_into_exact_noop_identity() {
        let desired = desired();
        let machine = &desired.machines[0];
        let mut instance = mock_instance("edge-1", "waw", "vc2-1c-1gb", "203.0.113.10");
        instance.os_id = 2625;
        instance.tags = managed_provider_tags(&desired, machine).unwrap();

        let inventory = normalize_vultr_inventory(&desired, &[instance]).unwrap();
        let observed = &inventory.resources[0];
        assert_eq!(
            observed.ownership.managed_by.as_deref(),
            Some(MANAGED_BY_IDENTITY)
        );
        assert_eq!(
            observed.ownership.environment.as_deref(),
            Some("production")
        );
        assert_eq!(observed.ownership.logical_id.as_deref(), Some("edge-1"));
        assert_eq!(observed.tags, vec!["primary".to_owned()]);

        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::Noop);
    }

    #[test]
    fn provider_verified_firewall_binding_projects_profile() {
        let desired = DesiredState::parse_json(
            r#"{
  "schema": 1,
  "environment": "production",
  "machines": [
    {
      "id": "edge-1",
      "role": "edge",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "os_id": 2625,
        "enable_ipv6": false,
        "firewall_profile": "edge"
      },
      "bootstrap_profile": "singbox-host-v1",
      "tags": ["primary"]
    }
  ]
}"#,
        )
        .unwrap();
        let machine = &desired.machines[0];
        let mut instance = mock_instance("edge-1", "waw", "vc2-1c-1gb", "203.0.113.10");
        instance.os_id = 2625;
        instance.firewall_group_id = "fw-1".to_owned();
        instance.tags = managed_provider_tags(&desired, machine).unwrap();
        let verified = BTreeMap::from([("fw-1".to_owned(), "edge".to_owned())]);

        let inventory =
            normalize_vultr_inventory_with_firewall_profiles(&desired, &[instance], &verified)
                .unwrap();
        let plan = plan_machine(&desired, machine, &inventory).unwrap();

        assert_eq!(
            inventory.resources[0].firewall_profile.as_deref(),
            Some("edge")
        );
        assert_eq!(plan.class, PlanClass::Noop);
    }

    #[test]
    fn rejects_legacy_partial_managed_identity_instead_of_adopting_it() {
        let desired = desired();
        let mut instance = mock_instance("edge-1", "waw", "vc2-1c-1gb", "203.0.113.10");
        instance.os_id = 2625;
        instance.tags = vec!["managed-by-sing-box".to_owned(), "edge-1".to_owned()];

        let error = normalize_vultr_inventory(&desired, &[instance]).unwrap_err();
        assert!(error.contains("incomplete managed lifecycle identity"));
    }

    #[test]
    fn projects_snapshot_origin_even_when_provider_reports_os_id_too() {
        let desired = DesiredState::parse_json(
            r#"{
  "schema": 1,
  "environment": "production",
  "machines": [
    {
      "id": "proxy-1",
      "role": "remote-proxy",
      "provider": {
        "region": "waw",
        "plan": "vc2-1c-1gb",
        "snapshot_id": "snapshot-1",
        "enable_ipv6": true
      },
      "bootstrap_profile": "singbox-host-v1"
    }
  ]
}"#,
        )
        .unwrap();
        let machine = &desired.machines[0];
        let mut instance = mock_instance("proxy-1", "waw", "vc2-1c-1gb", "203.0.113.11");
        instance.os_id = 2625;
        instance.snapshot_id = Some("snapshot-1".to_owned());
        instance.enable_ipv6 = true;
        instance.tags = managed_provider_tags(&desired, machine).unwrap();

        let inventory = normalize_vultr_inventory(&desired, &[instance]).unwrap();
        let plan = plan_machine(&desired, machine, &inventory).unwrap();
        assert_eq!(plan.class, PlanClass::Noop);
    }
}
