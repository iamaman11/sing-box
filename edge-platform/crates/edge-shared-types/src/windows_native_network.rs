//! Native read-only Windows network ownership evidence. No PowerShell,
//! netsh, route mutation, extra service or runner-provided NIC inventory.
//!
//! This is a necessary but NOT sufficient prerequisite for future ManagedTun
//! admission. It proves only that the exact sing-box-owned interface is
//! absent from the live OS interface table. It also enumerates current
//! IPv4/IPv6 routes and adapter DNS endpoints, but counting those facts does
//! not prove their restoration, WARP health, Line1, or future TUN safety.
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIfTable2, GetIpForwardTable2,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    IP_ADAPTER_ADDRESSES_LH, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

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

fn add_dns(
    result: &mut NativeNetworkReadback,
    family: u16,
) -> Result<(), &'static str> {
    match family {
        AF_INET => result.ipv4_dns_servers += 1,
        AF_INET6 => result.ipv6_dns_servers += 1,
        _ => return Err("HOST_WINDOWS_NETWORK_DNS_FAMILY_INVALID"),
    }
    Ok(())
}

/// IP Helper allocates each routing table; FreeMibTable is its only owner.
fn read_native_routes(result: &mut NativeNetworkReadback) -> Result<(), &'static str> {
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
fn read_native_dns(result: &mut NativeNetworkReadback) -> Result<(), &'static str> {
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
                    if family == AF_INET6 && row.Address.iSockaddrLength < 28 {
                        return Err("HOST_WINDOWS_NETWORK_DNS_SOCKET_INVALID");
                    }
                    add_dns(result, family)?;
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
    let mut result = NativeNetworkReadback::default();
    require_owned_tun_absent()?;
    read_native_routes(&mut result)?;
    read_native_dns(&mut result)?;
    Ok(result)
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
    for row in rows {
        if is_owned_tun_alias(&row.Alias)? {
            return Err("HOST_WINDOWS_NETWORK_MANAGED_TUN_INTERFACE_STILL_PRESENT");
        }
    }
    Ok(())
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
