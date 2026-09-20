use std::net::{IpAddr, Ipv4Addr};

use edge_shared_types::{
    Ipv4AddressObservation, Ipv4LinkObservation, Ipv4NetworkObservation, Ipv4RouteObservation,
};
use futures_util::TryStreamExt;
use rtnetlink::{
    RouteMessageBuilder, new_connection,
    packet_route::{
        AddressFamily,
        address::{AddressAttribute, AddressMessage, AddressScope},
        link::{LinkAttribute, LinkFlags, LinkMessage},
        route::{
            RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        },
    },
};

pub(crate) async fn observe_ipv4_network() -> Result<Ipv4NetworkObservation, String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("failed to open rtnetlink connection: {err}"))?;
    tokio::spawn(connection);

    let mut observation = Ipv4NetworkObservation {
        links: Vec::new(),
        addresses: Vec::new(),
        routes: Vec::new(),
    };

    let mut links = handle.link().get().execute();
    while let Some(message) = links
        .try_next()
        .await
        .map_err(|err| format!("failed to observe network links: {err}"))?
    {
        observation.links.push(normalize_link(&message)?);
    }

    let mut addresses = handle.address().get().execute();
    while let Some(message) = addresses
        .try_next()
        .await
        .map_err(|err| format!("failed to observe IPv4 addresses: {err}"))?
    {
        if let Some(address) = normalize_address(&message) {
            observation.addresses.push(address);
        }
    }

    let route_request = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut routes = handle.route().get(route_request).execute();
    while let Some(message) = routes
        .try_next()
        .await
        .map_err(|err| format!("failed to observe IPv4 routes: {err}"))?
    {
        if let Some(route) = normalize_route(&message) {
            observation.routes.push(route);
        }
    }

    Ok(normalize_observation(observation))
}

fn normalize_link(message: &LinkMessage) -> Result<Ipv4LinkObservation, String> {
    let name = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            format!(
                "network link {} has no interface name",
                message.header.index
            )
        })?;

    Ok(Ipv4LinkObservation {
        interface_index: message.header.index,
        name,
        up: message.header.flags.contains(LinkFlags::Up),
        lower_up: message.header.flags.contains(LinkFlags::LowerUp),
        loopback: message.header.flags.contains(LinkFlags::Loopback),
    })
}

fn normalize_address(message: &AddressMessage) -> Option<Ipv4AddressObservation> {
    if message.header.family != AddressFamily::Inet {
        return None;
    }

    let local = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(IpAddr::V4(address)) => Some(*address),
            _ => None,
        })
        .or_else(|| {
            message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Address(IpAddr::V4(address)) => Some(*address),
                    _ => None,
                })
        })?;

    Some(Ipv4AddressObservation {
        interface_index: message.header.index,
        address: local.to_string(),
        prefix_length: u32::from(message.header.prefix_len),
        global_scope: message.header.scope == AddressScope::Universe,
    })
}

fn normalize_route(message: &RouteMessage) -> Option<Ipv4RouteObservation> {
    if message.header.address_family != AddressFamily::Inet
        || message.header.table != RouteHeader::RT_TABLE_MAIN
    {
        return None;
    }

    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(*address),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let output_interface_index = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
        .unwrap_or_default();
    let preferred_source = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::PrefSource(RouteAddress::Inet(address)) => Some(address.to_string()),
            _ => None,
        });

    Some(Ipv4RouteObservation {
        destination: destination.to_string(),
        prefix_length: u32::from(message.header.destination_prefix_length),
        output_interface_index,
        preferred_source,
        kernel_protocol: message.header.protocol == RouteProtocol::Kernel,
        link_scope: message.header.scope == RouteScope::Link,
    })
}

fn normalize_observation(mut observation: Ipv4NetworkObservation) -> Ipv4NetworkObservation {
    observation.links.sort_by(|left, right| {
        (left.interface_index, &left.name).cmp(&(right.interface_index, &right.name))
    });
    observation.addresses.sort_by(|left, right| {
        (
            left.interface_index,
            &left.address,
            left.prefix_length,
            left.global_scope,
        )
            .cmp(&(
                right.interface_index,
                &right.address,
                right.prefix_length,
                right.global_scope,
            ))
    });
    observation.routes.sort_by(|left, right| {
        (
            &left.destination,
            left.prefix_length,
            left.output_interface_index,
            &left.preferred_source,
            left.kernel_protocol,
            left.link_scope,
        )
            .cmp(&(
                &right.destination,
                right.prefix_length,
                right.output_interface_index,
                &right.preferred_source,
                right.kernel_protocol,
                right.link_scope,
            ))
    });
    observation
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    use rtnetlink::{AddressMessageBuilder, LinkUnspec};

    #[test]
    fn raw_link_flags_normalize_to_admin_and_carrier_state() {
        let mut link = LinkUnspec::new_with_name("ens7").index(7).build();
        link.header.flags = LinkFlags::Up | LinkFlags::LowerUp;

        let normalized = normalize_link(&link).unwrap();
        assert_eq!(normalized.interface_index, 7);
        assert_eq!(normalized.name, "ens7");
        assert!(normalized.up);
        assert!(normalized.lower_up);
        assert!(!normalized.loopback);

        link.header.flags = LinkFlags::Up;
        let normalized = normalize_link(&link).unwrap();
        assert!(normalized.up);
        assert!(!normalized.lower_up);
    }

    #[test]
    fn raw_addresses_filter_ipv6_and_preserve_interface_prefix_and_scope() {
        let mut ipv4 = AddressMessageBuilder::<Ipv4Addr>::new()
            .index(7)
            .address(Ipv4Addr::new(10, 2, 0, 5), 24)
            .build();
        ipv4.header.scope = AddressScope::Universe;

        let normalized = normalize_address(&ipv4).unwrap();
        assert_eq!(normalized.interface_index, 7);
        assert_eq!(normalized.address, "10.2.0.5");
        assert_eq!(normalized.prefix_length, 24);
        assert!(normalized.global_scope);

        let ipv6 = AddressMessageBuilder::<Ipv6Addr>::new()
            .index(7)
            .address(Ipv6Addr::LOCALHOST, 128)
            .build();
        assert!(normalize_address(&ipv6).is_none());
    }

    #[test]
    fn raw_routes_filter_ipv6_and_preserve_connected_route_semantics() {
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(10, 2, 0, 0), 24)
            .output_interface(7)
            .pref_source(Ipv4Addr::new(10, 2, 0, 5))
            .protocol(RouteProtocol::Kernel)
            .scope(RouteScope::Link)
            .build();

        let normalized = normalize_route(&route).unwrap();
        assert_eq!(normalized.destination, "10.2.0.0");
        assert_eq!(normalized.prefix_length, 24);
        assert_eq!(normalized.output_interface_index, 7);
        assert_eq!(normalized.preferred_source.as_deref(), Some("10.2.0.5"));
        assert!(normalized.kernel_protocol);
        assert!(normalized.link_scope);

        let ipv6 = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(Ipv6Addr::LOCALHOST, 128)
            .output_interface(7)
            .build();
        assert!(normalize_route(&ipv6).is_none());
    }

    #[test]
    fn normalization_is_deterministic() {
        let observation = Ipv4NetworkObservation {
            links: vec![
                Ipv4LinkObservation {
                    interface_index: 3,
                    name: "ens8".to_owned(),
                    up: true,
                    lower_up: true,
                    loopback: false,
                },
                Ipv4LinkObservation {
                    interface_index: 1,
                    name: "lo".to_owned(),
                    up: true,
                    lower_up: true,
                    loopback: true,
                },
            ],
            addresses: vec![
                Ipv4AddressObservation {
                    interface_index: 3,
                    address: "10.2.0.5".to_owned(),
                    prefix_length: 24,
                    global_scope: true,
                },
                Ipv4AddressObservation {
                    interface_index: 1,
                    address: "127.0.0.1".to_owned(),
                    prefix_length: 8,
                    global_scope: false,
                },
            ],
            routes: vec![
                Ipv4RouteObservation {
                    destination: "10.2.0.0".to_owned(),
                    prefix_length: 24,
                    output_interface_index: 3,
                    preferred_source: Some("10.2.0.5".to_owned()),
                    kernel_protocol: true,
                    link_scope: true,
                },
                Ipv4RouteObservation {
                    destination: "0.0.0.0".to_owned(),
                    prefix_length: 0,
                    output_interface_index: 2,
                    preferred_source: None,
                    kernel_protocol: false,
                    link_scope: false,
                },
            ],
        };

        let normalized = normalize_observation(observation);
        assert_eq!(normalized.links[0].interface_index, 1);
        assert_eq!(normalized.addresses[0].interface_index, 1);
        assert_eq!(normalized.routes[0].destination, "0.0.0.0");
    }
}
