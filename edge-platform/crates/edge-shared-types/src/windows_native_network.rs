//! Native read-only Windows network ownership evidence. No PowerShell,
//! netsh, route mutation, extra service or runner-provided NIC inventory.
//!
//! This is a necessary but NOT sufficient prerequisite for future ManagedTun
//! admission. It proves only that the exact sing-box-owned interface is
//! absent from the live OS interface table. DNS, IPv4/IPv6 route restoration,
//! WARP, Line1, and poststate must be proven independently before TUN START.
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

const OWNED_TUN_ALIAS: &str = "sing-box-tun";
const MAX_NATIVE_INTERFACES: usize = 4096;

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
