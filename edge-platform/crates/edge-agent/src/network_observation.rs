use std::net::{IpAddr, Ipv4Addr};

use edge_shared_types::{
    Ipv4AddressObservation, Ipv4LinkObservation, Ipv4NetworkObservation, Ipv4RouteObservation,
};
use futures_util::TryStreamExt;
use rtnetlink::{
    RouteMessageBuilder, new_connection,
    packet_route::{
        AddressFamily,
        address::{AddressAttribute, AddressScope},
        link::{LinkAttribute, LinkFlags},
        route::{RouteAddress, RouteAttribute, RouteHeader, RouteProtocol, RouteScope},
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
        observation.links.push(Ipv4LinkObservation {
            interface_index: message.header.index,
            name,
            up: message.header.flags.contains(LinkFlags::Up),
            lower_up: message.header.flags.contains(LinkFlags::LowerUp),
            loopback: message.header.flags.contains(LinkFlags::Loopback),
        });
    }

    let mut addresses = handle.address().get().execute();
    while let Some(message) = addresses
        .try_next()
        .await
        .map_err(|err| format!("failed to observe IPv4 addresses: {err}"))?
    {
        if message.header.family != AddressFamily::Inet {
            continue;
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
            });
        let Some(local) = local else {
            continue;
        };
        observation.addresses.push(Ipv4AddressObservation {
            interface_index: message.header.index,
            address: local.to_string(),
            prefix_length: u32::from(message.header.prefix_len),
            global_scope: message.header.scope == AddressScope::Universe,
        });
    }

    let route_request = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut routes = handle.route().get(route_request).execute();
    while let Some(message) = routes
        .try_next()
        .await
        .map_err(|err| format!("failed to observe IPv4 routes: {err}"))?
    {
        if message.header.address_family != AddressFamily::Inet
            || message.header.table != RouteHeader::RT_TABLE_MAIN
        {
            continue;
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
                RouteAttribute::PrefSource(RouteAddress::Inet(address)) => {
                    Some(address.to_string())
                }
                _ => None,
            });

        observation.routes.push(Ipv4RouteObservation {
            destination: destination.to_string(),
            prefix_length: u32::from(message.header.destination_prefix_length),
            output_interface_index,
            preferred_source,
            kernel_protocol: message.header.protocol == RouteProtocol::Kernel,
            link_scope: message.header.scope == RouteScope::Link,
        });
    }

    Ok(normalize_observation(observation))
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
