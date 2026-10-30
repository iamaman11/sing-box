//! Native read-only Windows network ownership evidence. No PowerShell,
//! netsh, route mutation, extra service or runner-provided NIC inventory.
//!
//! This is a necessary but NOT sufficient prerequisite for future ManagedTun
//! admission. It proves only that the exact sing-box-owned interface is
//! absent from the live OS interface table. It also enumerates current
//! IPv4/IPv6 routes and adapter DNS endpoints, but counting those facts does
//! not prove their restoration, WARP health, Line1, or future TUN safety.
use std::collections::BTreeSet;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    GetAdaptersAddresses, GetIfTable2, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IF_TABLE2,
    MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

const OWNED_TUN_ALIAS: &str = "sing-box-tun";
const MAX_NATIVE_INTERFACES: usize = 4096;
const MAX_NATIVE_ROUTES: usize = 32768;
const MAX_NATIVE_ADAPTERS: usize = 512;
const MAX_DNS_LINKS: usize = 1024;
const MAX_ADAPTER_BUFFER_BYTES: usize = 1024 * 1024;

/// Transient native observation only, never a Git value, persisted config,
/// authorization or permission to touch a route. The logical owner stays
/// SYSTEM; Windows IP Helper owns the physical network tables.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NativeNetworkReadback {
    pub ipv4_routes: u32,
    pub ipv6_routes: u32,
    pub ipv4_default_routes: u32,
    pub ipv6_default_routes: u32,
    pub ipv4_dns_servers: u32,
    pub ipv6_dns_servers: u32,
    pub active_dns_adapters: u32,
}

/// Stable OS identities, not route/DNS counts. A canonical ordered value
/// supports exact pre/post comparison without copying uninitialised Win32
/// struct padding, OS-owned pointers, route ages or changing lifetimes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteIdentity {
    pub interface_luid: u64,
    pub family: u16,
    pub prefix: Vec<u8>,
    pub prefix_length: u8,
    pub next_hop: Vec<u8>,
    pub metric: u32,
    pub protocol: i32,
    pub origin: i32,
    pub site_prefix_length: u8,
    pub loopback: bool,
    pub published: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsIdentity {
    pub interface_luid: u64,
    pub order: u32,
    pub family: u16,
    pub server: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManagedAdapterIdentity {
    pub alias: String,
    pub interface_luid: u64,
    pub oper_status: i32,
}

/// Never a second desired-state model. This is an in-memory readback of the
/// same Windows network stack before and after an admitted operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NativeNetworkIdentity {
    pub routes: Vec<RouteIdentity>,
    pub dns: Vec<DnsIdentity>,
    pub foreign_warp_adapters: Vec<ManagedAdapterIdentity>,
}

impl NativeNetworkIdentity {
    /// No tolerance for a changed native route, resolver order or foreign
    /// Cloudflare One interface during an exact restoration proof. A change
    /// needs a separately signed RECOVER; guessing a correction is forbidden.
    pub fn require_restored(&self, after: &Self) -> Result<(), &'static str> {
        if self.routes != after.routes {
            return Err("HOST_WINDOWS_NETWORK_ROUTES_NOT_RESTORED");
        }
        if self.dns != after.dns {
            return Err("HOST_WINDOWS_NETWORK_DNS_NOT_RESTORED");
        }
        if self.foreign_warp_adapters != after.foreign_warp_adapters {
            return Err("HOST_WINDOWS_NETWORK_CLOUDFLARE_ONE_CHANGED");
        }
        Ok(())
    }
    /// A ManagedTun candidate cannot even be considered when the foreign
    /// Cloudflare One device is missing, down, or ambiguous. The interface
    /// alone does not attest its control/mesh transport or Line1 reachability.
    pub fn require_foreign_warp_up(&self) -> Result<(), &'static str> {
        if self.foreign_warp_adapters.len() == 1 && self.foreign_warp_adapters[0].oper_status == 1 {
            Ok(())
        } else {
            Err("HOST_WINDOWS_CLOUDFLARE_ONE_NATIVE_IDENTITY_UNPROVEN")
        }
    }
}

fn address_bytes(addr: &SOCKADDR_INET) -> Result<(u16, Vec<u8>), &'static str> {
    // SAFETY: si_family is the documented active discriminator for the
    // SOCKADDR_INET union returned by Windows IP Helper.
    let family = unsafe { addr.si_family };
    match family {
        AF_INET => {
            // SAFETY: the IPv4 union member is active for AF_INET.
            let value = unsafe { addr.Ipv4.sin_addr.S_un.S_addr };
            Ok((family, value.to_ne_bytes().to_vec()))
        }
        AF_INET6 => {
            // SAFETY: the IPv6 union member is active for AF_INET6.
            let bytes = unsafe { addr.Ipv6.sin6_addr.u.Byte };
            Ok((family, bytes.to_vec()))
        }
        _ => Err("HOST_WINDOWS_NETWORK_ADDRESS_FAMILY_INVALID"),
    }
}

fn warp_alias(alias: &str) -> bool {
    // Match exactly the Windows Cloudflare One adapter identity. Never
    // infer foreign interface ownership from its IP range or mutate it.
    alias.eq_ignore_ascii_case("CloudflareWARP")
}

fn add_route(
    result: &mut NativeNetworkReadback,
    family: u16,
    prefix_len: u8,
) -> Result<(), &'static str> {
    match family {
        AF_INET if prefix_len <= 32 => {
            result.ipv4_routes += 1;
            if prefix_len == 0 {
                result.ipv4_default_routes += 1;
            }
        }
        AF_INET6 if prefix_len <= 128 => {
            result.ipv6_routes += 1;
            if prefix_len == 0 {
                result.ipv6_default_routes += 1;
            }
        }
        _ => return Err("HOST_WINDOWS_NETWORK_ROUTE_FAMILY_OR_PREFIX_INVALID"),
    }
    Ok(())
}

fn add_dns(result: &mut NativeNetworkReadback, family: u16) -> Result<(), &'static str> {
    match family {
        AF_INET => result.ipv4_dns_servers += 1,
        AF_INET6 => result.ipv6_dns_servers += 1,
        _ => return Err("HOST_WINDOWS_NETWORK_DNS_FAMILY_INVALID"),
    }
    Ok(())
}

/// IP Helper allocates each routing table; FreeMibTable is its only owner.
fn read_native_routes(
    result: &mut NativeNetworkReadback,
    identity: &mut BTreeSet<RouteIdentity>,
) -> Result<(), &'static str> {
    struct RouteTable(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for RouteTable {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: matched GetIpForwardTable2 allocation, once.
                unsafe { FreeMibTable(self.0.cast()) };
            }
        }
    }
    let mut table = RouteTable(std::ptr::null_mut());
    // AF_UNSPEC includes BOTH IPv4 and IPv6, including zero-default families.
    // SAFETY: OS writes an allocated MIB_IPFORWARD_TABLE2 pointer.
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table.0) } != 0 || table.0.is_null() {
        return Err("HOST_WINDOWS_NETWORK_ROUTE_TABLE_UNAVAILABLE");
    }
    // SAFETY: NumEntries/Table are allocated together by IP Helper.
    let len = unsafe { (*table.0).NumEntries as usize };
    if len > MAX_NATIVE_ROUTES {
        return Err("HOST_WINDOWS_NETWORK_ROUTE_TABLE_UNBOUNDED");
    }
    let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), len) };
    for row in rows {
        // SAFETY: documented SOCKADDR_INET union discriminator.
        let family = unsafe { row.DestinationPrefix.Prefix.si_family };
        add_route(result, family, row.DestinationPrefix.PrefixLength)?;
        let (prefix_family, prefix) = address_bytes(&row.DestinationPrefix.Prefix)?;
        let (next_family, next_hop) = address_bytes(&row.NextHop)?;
        if prefix_family != family || next_family != family {
            return Err("HOST_WINDOWS_NETWORK_ROUTE_ADDRESS_FAMILY_MISMATCH");
        }
        let key = RouteIdentity {
            interface_luid: row.InterfaceLuid.Value,
            family,
            prefix,
            prefix_length: row.DestinationPrefix.PrefixLength,
            next_hop,
            metric: row.Metric,
            protocol: row.Protocol,
            origin: row.Origin,
            site_prefix_length: row.SitePrefixLength,
            loopback: row.Loopback != 0,
            published: row.Publish != 0,
        };
        if !identity.insert(key) {
            return Err("HOST_WINDOWS_NETWORK_DUPLICATE_ROUTE_IDENTITY");
        }
    }
    Ok(())
}

fn in_native_buffer<T>(buffer: &[u64], ptr: *const T) -> bool {
    let start = buffer.as_ptr() as usize;
    let end = start.saturating_add(std::mem::size_of_val(buffer));
    let address = ptr as usize;
    address >= start
        && address % std::mem::align_of::<T>() == 0
        && address
            .checked_add(std::mem::size_of::<T>())
            .is_some_and(|last| last <= end)
}

/// GetAdaptersAddresses is read-only and returns one bounded, caller-owned
/// allocation. Reject malformed/cyclic links without dereferencing outside
/// the returned buffer. Never execute shell/netsh/PowerShell commands.
fn read_native_dns(
    result: &mut NativeNetworkReadback,
    identity: &mut BTreeSet<DnsIdentity>,
) -> Result<(), &'static str> {
    let mut bytes = 15 * 1024;
    for _attempt in 0..3 {
        if bytes > MAX_ADAPTER_BUFFER_BYTES {
            return Err("HOST_WINDOWS_NETWORK_DNS_BUFFER_UNBOUNDED");
        }
        // u64 allocation provides the 8-byte Win32 adapter alignment.
        let mut buffer = vec![0u64; bytes.div_ceil(8)];
        let mut size = (buffer.len() * std::mem::size_of::<u64>()) as u32;
        // SAFETY: aligned writable buffer with accurate length; pointers
        // returned are validated before every adapter and DNS dereference.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        if status == 111 {
            // ERROR_BUFFER_OVERFLOW: interface inventory changed or grew.
            bytes = (size as usize).max(bytes + 8);
            continue;
        }
        if status != 0 {
            return Err("HOST_WINDOWS_NETWORK_DNS_TABLE_UNAVAILABLE");
        }
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut count = 0usize;
        let mut links = 0usize;
        while !adapter.is_null() {
            if count == MAX_NATIVE_ADAPTERS || !in_native_buffer(&buffer, adapter) {
                return Err("HOST_WINDOWS_NETWORK_ADAPTER_CHAIN_INVALID");
            }
            count += 1;
            // SAFETY: validated pointer within retained caller allocation.
            let entry = unsafe { &*adapter };
            // IF_OPER_STATUS_UP == 1. Inactive adapter DNS is not evidence
            // for the effective physical network's resolver configuration.
            if entry.OperStatus == 1 {
                let mut dns = entry.FirstDnsServerAddress;
                let mut ordinal = 0u32;
                if !dns.is_null() {
                    result.active_dns_adapters += 1;
                }
                while !dns.is_null() {
                    if links == MAX_DNS_LINKS || !in_native_buffer(&buffer, dns) {
                        return Err("HOST_WINDOWS_NETWORK_DNS_CHAIN_INVALID");
                    }
                    links += 1;
                    // SAFETY: the DNS node is inside the returned buffer.
                    let row = unsafe { &*dns };
                    let socket = row.Address.lpSockaddr;
                    if !in_native_buffer(&buffer, socket) || row.Address.iSockaddrLength < 16 {
                        return Err("HOST_WINDOWS_NETWORK_DNS_SOCKET_INVALID");
                    }
                    // SAFETY: at least SOCKADDR bytes exist in the buffer.
                    let family = unsafe { (*socket).sa_family };
                    if family == AF_INET6
                        && (row.Address.iSockaddrLength < 28
                            || !in_native_buffer(
                                &buffer,
                                socket
                                    .cast::<windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6>(
                                    ),
                            ))
                    {
                        return Err("HOST_WINDOWS_NETWORK_DNS_SOCKET_INVALID");
                    }
                    add_dns(result, family)?;
                    // DNS server order per interface matters to resolution.
                    // Both the address and interface LUID come from the same
                    // verified native adapter buffer; never trust a name.
                    let address = match family {
                        AF_INET => {
                            // SAFETY: at least 16 verified bytes, AF_INET.
                            let native = unsafe {
                                &*(socket
                                    as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN)
                            };
                            unsafe { native.sin_addr.S_un.S_addr }
                                .to_ne_bytes()
                                .to_vec()
                        }
                        AF_INET6 => {
                            // SAFETY: at least 28 verified bytes, AF_INET6.
                            let native = unsafe {
                                &*(socket
                                    as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6)
                            };
                            unsafe { native.sin6_addr.u.Byte }.to_vec()
                        }
                        _ => return Err("HOST_WINDOWS_NETWORK_DNS_FAMILY_INVALID"),
                    };
                    if !identity.insert(DnsIdentity {
                        interface_luid: entry.Luid.Value,
                        order: ordinal,
                        family,
                        server: address,
                    }) {
                        return Err("HOST_WINDOWS_NETWORK_DUPLICATE_DNS_IDENTITY");
                    }
                    ordinal += 1;
                    dns = row.Next;
                }
            }
            adapter = entry.Next;
        }
        return Ok(());
    }
    Err("HOST_WINDOWS_NETWORK_DNS_BUFFER_UNSTABLE")
}

/// Native, bounded readback of all three physical facts. Counts are for
/// diagnostics and subsequent independent before/after comparison; they
/// are NOT a safe baseline digest and DO NOT authorize ManagedTun START.
pub fn observe_native_route_dns() -> Result<NativeNetworkReadback, &'static str> {
    Ok(observe_native_network_identity()?.0)
}

/// One exact native snapshot: counts for diagnostics and canonical route/DNS
/// identities for restoration comparison. Does not capture routes or DNS.
pub fn observe_native_network_identity()
-> Result<(NativeNetworkReadback, NativeNetworkIdentity), &'static str> {
    let mut result = NativeNetworkReadback::default();
    let mut routes = BTreeSet::new();
    let mut dns = BTreeSet::new();
    let warp = observe_owned_foreign_interfaces()?;
    read_native_routes(&mut result, &mut routes)?;
    read_native_dns(&mut result, &mut dns)?;
    Ok((
        result,
        NativeNetworkIdentity {
            routes: routes.into_iter().collect(),
            dns: dns.into_iter().collect(),
            foreign_warp_adapters: warp,
        },
    ))
}

fn is_owned_tun_alias(raw: &[u16]) -> Result<bool, &'static str> {
    let end = raw
        .iter()
        .position(|v| *v == 0)
        .ok_or("HOST_WINDOWS_NETWORK_INTERFACE_ALIAS_UNTERMINATED")?;
    let alias = String::from_utf16(&raw[..end])
        .map_err(|_| "HOST_WINDOWS_NETWORK_INTERFACE_ALIAS_INVALID")?;
    Ok(alias.eq_ignore_ascii_case(OWNED_TUN_ALIAS))
}

/// Refuse an unproven native Windows route-capture owner even if the
/// *process* is stopped or Git currently requests ProxyOnly. Windows may
/// retain a TUN adapter after process loss; trusting SCM alone is unsafe.
pub fn require_owned_tun_absent() -> Result<(), &'static str> {
    observe_owned_foreign_interfaces().map(|_| ())
}

/// The same native interface table both excludes our stale TUN and observes
/// Cloudflare One, without claiming foreign ownership or changing it.
fn observe_owned_foreign_interfaces() -> Result<Vec<ManagedAdapterIdentity>, &'static str> {
    struct OwnedTable(*mut MIB_IF_TABLE2);
    impl Drop for OwnedTable {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetIfTable2 allocates this buffer; exactly one
                // FreeMibTable is performed on all return paths.
                unsafe { FreeMibTable(self.0.cast()) };
            }
        }
    }

    let mut table = OwnedTable(std::ptr::null_mut());
    // SAFETY: the OS fills a writable pointer to its own allocation.
    let status = unsafe { GetIfTable2(&mut table.0) };
    if status != 0 || table.0.is_null() {
        return Err("HOST_WINDOWS_NETWORK_INTERFACE_READBACK_UNAVAILABLE");
    }
    // SAFETY: the OS allocated the MIB_IF_TABLE2, including its first row.
    let count = unsafe { (*table.0).NumEntries as usize };
    if count > MAX_NATIVE_INTERFACES {
        return Err("HOST_WINDOWS_NETWORK_INTERFACE_READBACK_UNBOUNDED");
    }
    // SAFETY: the table buffer is valid for its reported NumEntries; the
    // RAII owner stays alive throughout the read and uses the API-defined
    // MIB_IF_ROW2 element stride, not a hand-computed byte offset.
    let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), count) };
    let mut foreign = BTreeSet::new();
    for row in rows {
        if is_owned_tun_alias(&row.Alias)? {
            return Err("HOST_WINDOWS_NETWORK_MANAGED_TUN_INTERFACE_STILL_PRESENT");
        }
        let end = row
            .Alias
            .iter()
            .position(|v| *v == 0)
            .ok_or("HOST_WINDOWS_NETWORK_INTERFACE_ALIAS_UNTERMINATED")?;
        let alias = String::from_utf16(&row.Alias[..end])
            .map_err(|_| "HOST_WINDOWS_NETWORK_INTERFACE_ALIAS_INVALID")?;
        if warp_alias(&alias)
            && !foreign.insert(ManagedAdapterIdentity {
                alias: alias.to_ascii_lowercase(),
                interface_luid: row.InterfaceLuid.Value,
                oper_status: row.OperStatus,
            })
        {
            return Err("HOST_WINDOWS_NETWORK_DUPLICATE_FOREIGN_ADAPTER");
        }
    }
    Ok(foreign.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_native_tun_alias_proof_is_case_insensitive_and_fail_closed() {
        let name = |value: &str| {
            let mut raw: Vec<u16> = value.encode_utf16().collect();
            raw.push(0);
            raw
        };
        assert_eq!(is_owned_tun_alias(&name("sing-box-tun")), Ok(true));
        assert_eq!(is_owned_tun_alias(&name("SING-BOX-TUN")), Ok(true));
        assert_eq!(is_owned_tun_alias(&name("CloudflareWARP")), Ok(false));
        assert_eq!(is_owned_tun_alias(&name("sing-box-tun-other")), Ok(false));
        assert_eq!(
            is_owned_tun_alias(&[0xD800, 0]),
            Err("HOST_WINDOWS_NETWORK_INTERFACE_ALIAS_INVALID")
        );
        assert_eq!(
            is_owned_tun_alias(&[b'x' as u16]),
            Err("HOST_WINDOWS_NETWORK_INTERFACE_ALIAS_UNTERMINATED")
        );
    }

    #[test]
    fn dual_stack_route_and_dns_counts_do_not_imply_restoration() {
        let mut obs = NativeNetworkReadback::default();
        add_route(&mut obs, AF_INET, 0).unwrap();
        add_route(&mut obs, AF_INET6, 0).unwrap();
        add_route(&mut obs, AF_INET, 32).unwrap();
        add_route(&mut obs, AF_INET6, 128).unwrap();
        add_dns(&mut obs, AF_INET).unwrap();
        add_dns(&mut obs, AF_INET6).unwrap();
        assert_eq!(obs.ipv4_routes, 2);
        assert_eq!(obs.ipv6_routes, 2);
        assert_eq!(obs.ipv4_default_routes, 1);
        assert_eq!(obs.ipv6_default_routes, 1);
        assert_eq!(obs.ipv4_dns_servers, 1);
        assert_eq!(obs.ipv6_dns_servers, 1);
        for invalid in [(AF_INET, 33), (AF_INET6, 129), (AF_UNSPEC, 0)] {
            assert_eq!(
                add_route(&mut obs, invalid.0, invalid.1),
                Err("HOST_WINDOWS_NETWORK_ROUTE_FAMILY_OR_PREFIX_INVALID")
            );
        }
        assert_eq!(
            add_dns(&mut obs, AF_UNSPEC),
            Err("HOST_WINDOWS_NETWORK_DNS_FAMILY_INVALID")
        );
        assert_eq!(obs.ipv4_routes, 2);
        assert_eq!(obs.ipv6_routes, 2);
    }

    #[test]
    fn dns_buffer_access_rejects_out_of_range_pointer() {
        let buffer = [0u64; 8];
        assert!(in_native_buffer(&buffer, buffer.as_ptr()));
        let outside = 1usize as *const u64;
        assert!(!in_native_buffer(&buffer, outside));
        assert!(!in_native_buffer(&buffer, std::ptr::null::<u64>()));
    }

    #[test]
    fn exact_restore_requires_native_routes_dns_order_and_cloudflare_unchanged() {
        let baseline = NativeNetworkIdentity {
            routes: vec![RouteIdentity {
                interface_luid: 8,
                family: AF_INET,
                prefix: vec![0, 0, 0, 0],
                prefix_length: 0,
                next_hop: vec![192, 0, 2, 1],
                metric: 10,
                protocol: 3,
                origin: 2,
                site_prefix_length: 0,
                loopback: false,
                published: false,
            }],
            dns: vec![DnsIdentity {
                interface_luid: 8,
                order: 0,
                family: AF_INET6,
                server: vec![0; 16],
            }],
            foreign_warp_adapters: vec![ManagedAdapterIdentity {
                alias: "cloudflarewarp".into(),
                interface_luid: 7,
                oper_status: 1,
            }],
        };
        assert!(baseline.require_foreign_warp_up().is_ok());
        assert_eq!(baseline.require_restored(&baseline), Ok(()));
        let mut changed = baseline.clone();
        changed.routes[0].metric += 1;
        assert_eq!(
            baseline.require_restored(&changed),
            Err("HOST_WINDOWS_NETWORK_ROUTES_NOT_RESTORED")
        );
        changed = baseline.clone();
        changed.routes[0].interface_luid += 1;
        assert_eq!(
            baseline.require_restored(&changed),
            Err("HOST_WINDOWS_NETWORK_ROUTES_NOT_RESTORED")
        );
        changed = baseline.clone();
        changed.dns[0].order += 1;
        assert_eq!(
            baseline.require_restored(&changed),
            Err("HOST_WINDOWS_NETWORK_DNS_NOT_RESTORED")
        );
        changed = baseline.clone();
        changed.foreign_warp_adapters[0].oper_status = 2;
        assert_eq!(
            baseline.require_restored(&changed),
            Err("HOST_WINDOWS_NETWORK_CLOUDFLARE_ONE_CHANGED")
        );
        assert!(changed.require_foreign_warp_up().is_err());
        let mut changed = baseline.clone();
        changed.dns[0].server[0] ^= 1;
        assert_eq!(
            baseline.require_restored(&changed),
            Err("HOST_WINDOWS_NETWORK_DNS_NOT_RESTORED")
        );
        changed = baseline.clone();
        changed.foreign_warp_adapters.clear();
        assert!(changed.require_foreign_warp_up().is_err());
        assert_eq!(
            baseline.require_restored(&changed),
            Err("HOST_WINDOWS_NETWORK_CLOUDFLARE_ONE_CHANGED")
        );
    }

    #[test]
    fn ipv4_and_ipv6_native_sockaddrs_preserve_exact_bytes() {
        use windows_sys::Win32::Networking::WinSock::SOCKADDR_INET;
        let mut v4 = SOCKADDR_INET::default();
        // SAFETY: the active union member is written and then read as AF_INET.
        unsafe {
            v4.Ipv4.sin_family = AF_INET;
            v4.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([203, 0, 113, 10]);
        }
        assert_eq!(address_bytes(&v4), Ok((AF_INET, vec![203, 0, 113, 10])));
        let mut v6 = SOCKADDR_INET::default();
        // SAFETY: the active union member is written and then read as AF_INET6.
        unsafe {
            v6.Ipv6.sin6_family = AF_INET6;
            v6.Ipv6.sin6_addr.u.Byte = [0x20; 16];
        }
        assert_eq!(address_bytes(&v6), Ok((AF_INET6, vec![0x20; 16])));
        let mut unknown = SOCKADDR_INET::default();
        unknown.si_family = AF_UNSPEC;
        assert_eq!(
            address_bytes(&unknown),
            Err("HOST_WINDOWS_NETWORK_ADDRESS_FAMILY_INVALID")
        );
        assert!(warp_alias("CloudflareWARP"));
        assert!(!warp_alias("CloudflareWARP-untrusted"));
        assert!(!warp_alias("sing-box-tun"));
    }

    #[test]
    fn windows_native_interface_table_is_observable_without_mutation() {
        // This native observation makes no changes to network resources.
        // A CI host with an existing exact TUN must be rejected, not cleaned.
        let result = require_owned_tun_absent();
        assert!(
            result.is_ok()
                || matches!(
                    result,
                    Err("HOST_WINDOWS_NETWORK_MANAGED_TUN_INTERFACE_STILL_PRESENT")
                        | Err("HOST_WINDOWS_NETWORK_INTERFACE_READBACK_UNAVAILABLE")
                        | Err("HOST_WINDOWS_NETWORK_INTERFACE_READBACK_UNBOUNDED")
                ),
            "unexpected Windows network readback failure: {result:?}"
        );
    }
}
