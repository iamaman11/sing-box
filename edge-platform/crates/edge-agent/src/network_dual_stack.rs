//! Read-only host-namespace rtnetlink IPv4+IPv6 observations.
//! Includes route tables outside MAIN; this is NOT a mutation or egress proof.
use super::*;
use edge_shared_types::{
    FleetVmDualStackNetwork, FleetVmIpFamily, FleetVmKernelAddress, FleetVmKernelRoute,
};
use prost::Message;
use std::net::Ipv6Addr;

fn normalize_dual_address(message: &AddressMessage) -> Option<FleetVmKernelAddress> {
    let family = match message.header.family {
        AddressFamily::Inet => FleetVmIpFamily::V4,
        AddressFamily::Inet6 => FleetVmIpFamily::V6,
        _ => return None,
    };
    let address = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(address) => Some(*address),
            _ => None,
        })
        .or_else(|| {
            message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Address(address) => Some(*address),
                    _ => None,
                })
        })?;
    if !matches!(
        (&address, family),
        (IpAddr::V4(_), FleetVmIpFamily::V4) | (IpAddr::V6(_), FleetVmIpFamily::V6)
    ) {
        return None;
    }
    Some(FleetVmKernelAddress {
        interface_index: message.header.index,
        family: family as i32,
        address: address.to_string(),
        prefix_length: u32::from(message.header.prefix_len),
        global_scope: message.header.scope == AddressScope::Universe,
    })
}

fn normalize_dual_route(message: &RouteMessage) -> Option<FleetVmKernelRoute> {
    let family = match message.header.address_family {
        AddressFamily::Inet => FleetVmIpFamily::V4,
        AddressFamily::Inet6 => FleetVmIpFamily::V6,
        _ => return None,
    };
    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match (family, attribute) {
            (FleetVmIpFamily::V4, RouteAttribute::Destination(RouteAddress::Inet(ip))) => {
                Some(ip.to_string())
            }
            (FleetVmIpFamily::V6, RouteAttribute::Destination(RouteAddress::Inet6(ip))) => {
                Some(ip.to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| match family {
            FleetVmIpFamily::V4 => Ipv4Addr::UNSPECIFIED.to_string(),
            _ => Ipv6Addr::UNSPECIFIED.to_string(),
        });
    let gateway = message
        .attributes
        .iter()
        .find_map(|attribute| match (family, attribute) {
            (FleetVmIpFamily::V4, RouteAttribute::Gateway(RouteAddress::Inet(ip))) => {
                Some(ip.to_string())
            }
            (FleetVmIpFamily::V6, RouteAttribute::Gateway(RouteAddress::Inet6(ip))) => {
                Some(ip.to_string())
            }
            _ => None,
        })
        .unwrap_or_default();
    let preferred_source = message
        .attributes
        .iter()
        .find_map(|attribute| match (family, attribute) {
            (FleetVmIpFamily::V4, RouteAttribute::PrefSource(RouteAddress::Inet(ip))) => {
                Some(ip.to_string())
            }
            (FleetVmIpFamily::V6, RouteAttribute::PrefSource(RouteAddress::Inet6(ip))) => {
                Some(ip.to_string())
            }
            _ => None,
        })
        .unwrap_or_default();
    let table_id = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table));
    let metric = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(priority) => Some(*priority),
            _ => None,
        })
        .unwrap_or_default();
    let output_interface_index = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
        .unwrap_or_default();
    Some(FleetVmKernelRoute {
        family: family as i32,
        destination,
        prefix_length: u32::from(message.header.destination_prefix_length),
        output_interface_index,
        gateway,
        preferred_source,
        table_id,
        metric,
        kernel_protocol: message.header.protocol == RouteProtocol::Kernel,
        link_scope: message.header.scope == RouteScope::Link,
    })
}

fn sorted_dual_stack(mut result: FleetVmDualStackNetwork) -> FleetVmDualStackNetwork {
    result
        .links
        .sort_by(|a, b| (a.interface_index, &a.name).cmp(&(b.interface_index, &b.name)));
    result.addresses.sort_by(|a, b| {
        (a.family, a.interface_index, &a.address, a.prefix_length).cmp(&(
            b.family,
            b.interface_index,
            &b.address,
            b.prefix_length,
        ))
    });
    result.routes.sort_by(|a, b| {
        (
            a.family,
            a.table_id,
            &a.destination,
            a.prefix_length,
            a.output_interface_index,
            &a.gateway,
            a.metric,
        )
            .cmp(&(
                b.family,
                b.table_id,
                &b.destination,
                b.prefix_length,
                b.output_interface_index,
                &b.gateway,
                b.metric,
            ))
    });
    result
}

/// Native kernel dump of BOTH IP families and all routing tables.
/// Errors are closed stage codes rather than raw netlink exception text.
pub(crate) async fn observe_dual_stack() -> Result<FleetVmDualStackNetwork, &'static str> {
    let (connection, handle, _) = new_connection().map_err(|_| "NETLINK_OPEN_FAILED")?;
    tokio::spawn(connection);
    let mut result = FleetVmDualStackNetwork::default();
    let mut links = handle.link().get().execute();
    while let Some(link) = links.try_next().await.map_err(|_| "LINK_DUMP_FAILED")? {
        result
            .links
            .push(normalize_link(&link).map_err(|_| "LINK_INVALID")?);
        if result.links.len() > 128 {
            return Err("LINK_COUNT_EXCEEDED");
        }
    }
    let mut addresses = handle.address().get().execute();
    while let Some(addr) = addresses
        .try_next()
        .await
        .map_err(|_| "ADDRESS_DUMP_FAILED")?
    {
        if let Some(normalized) = normalize_dual_address(&addr) {
            result.addresses.push(normalized);
            if result.addresses.len() > 256 {
                return Err("ADDRESS_COUNT_EXCEEDED");
            }
        }
    }
    let mut ipv4 = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute();
    while let Some(route) = ipv4
        .try_next()
        .await
        .map_err(|_| "IPV4_ROUTE_DUMP_FAILED")?
    {
        if let Some(normalized) = normalize_dual_route(&route) {
            result.routes.push(normalized);
            if result.routes.len() > 512 {
                return Err("ROUTE_COUNT_EXCEEDED");
            }
        }
    }
    result.ipv4_route_dump_complete = true;
    let mut ipv6 = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute();
    while let Some(route) = ipv6
        .try_next()
        .await
        .map_err(|_| "IPV6_ROUTE_DUMP_FAILED")?
    {
        if let Some(normalized) = normalize_dual_route(&route) {
            result.routes.push(normalized);
            if result.routes.len() > 512 {
                return Err("ROUTE_COUNT_EXCEEDED");
            }
        }
    }
    result.ipv6_route_dump_complete = true;
    result = sorted_dual_stack(result);
    if result.encode_to_vec().len() > 24_576 {
        return Err("DUAL_STACK_REPORT_TOO_LARGE");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::AddressMessageBuilder;

    #[test]
    fn ipv4_ipv6_address_and_route_dump_include_non_main_tables() {
        let v4 = AddressMessageBuilder::<Ipv4Addr>::new()
            .index(7)
            .address(Ipv4Addr::new(10, 1, 0, 2), 24)
            .build();
        let v6 = AddressMessageBuilder::<Ipv6Addr>::new()
            .index(7)
            .address("2001:db8::10".parse().unwrap(), 64)
            .build();
        assert_eq!(
            normalize_dual_address(&v4).unwrap().family,
            FleetVmIpFamily::V4 as i32
        );
        assert_eq!(
            normalize_dual_address(&v6).unwrap().family,
            FleetVmIpFamily::V6 as i32
        );
        let mut r4 = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(10, 20, 0, 0), 16)
            .output_interface(7)
            .build();
        r4.attributes.push(RouteAttribute::Table(10001));
        let mut r6 = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix("2001:db8:1234::".parse().unwrap(), 48)
            .output_interface(7)
            .build();
        r6.attributes.push(RouteAttribute::Table(10002));
        r6.attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet6(
                "fe80::1".parse().unwrap(),
            )));
        let a = normalize_dual_route(&r4).unwrap();
        let b = normalize_dual_route(&r6).unwrap();
        assert_eq!((a.family, a.table_id), (FleetVmIpFamily::V4 as i32, 10001));
        assert_eq!((b.family, b.table_id), (FleetVmIpFamily::V6 as i32, 10002));
        assert_eq!(b.gateway, "fe80::1");
        assert_eq!(b.prefix_length, 48);
    }
}
