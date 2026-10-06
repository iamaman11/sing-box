use edge_shared_types::{
    WindowsDatapathMode, canonical_production_desired_state, decode_windows_activation_state,
    decode_windows_runtime_state, verify_windows_activation_files,
};
use std::path::{Path, PathBuf};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::ptr::null_mut;
#[cfg(windows)]
use windows_service::service::ServiceAccess;
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetExtendedTcpTable, GetExtendedUdpTable, GetIpForwardTable,
    GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_TABLE2, MIB_IPFORWARDTABLE,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

const WINDOWS_CONTROLLER_SERVICE_NAME: &str = "EdgePlatformController";
const MANAGED_TUN_INTERFACE_NAME: &str = "sing-box-tun";

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    if command != "doctor" {
        return Err(usage());
    }
    let state_path = PathBuf::from(args.next().ok_or_else(usage)?);
    if args.next().is_some() {
        return Err(usage());
    }

    let bytes = std::fs::read(&state_path).map_err(|err| {
        format!(
            "failed to read activation state {}: {err}",
            state_path.display()
        )
    })?;
    let state = decode_windows_activation_state(&bytes)?;
    verify_windows_activation_files(&state)?;
    let desired = canonical_production_desired_state()?;
    let datapath_mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "embedded canonical Windows datapath mode is invalid".to_owned())?;
    if datapath_mode == WindowsDatapathMode::Unspecified {
        return Err("embedded canonical Windows datapath mode is unspecified".to_owned());
    }

    let expected_controller = PathBuf::from(&state.controller_path);
    let controller_running = process_running_at(&expected_controller);

    println!("status=PASS");
    println!("release_set_sha256={}", state.release_set_sha256);
    println!("source_revision={}", state.source_revision);
    println!("windows_datapath_mode={datapath_mode:?}");
    println!("release_dir={}", state.release_dir);
    println!("controller_path={}", state.controller_path);
    println!("console_path={}", state.console_path);
    println!("sing_box_path={}", state.sing_box_path);
    println!("diagnostic_path={}", state.diagnostic_path);
    println!("controller_running={controller_running}");
    println!("controller_required_for_diagnostics=false");
    println!("exact_release_files=PASS");

    #[cfg(windows)]
    let controller_pid = observe_windows_service(&expected_controller)?;
    #[cfg(windows)]
    observe_singbox_processes(&state_path, datapath_mode, controller_pid)?;
    #[cfg(windows)]
    observe_project_listeners()?;
    #[cfg(windows)]
    observe_windows_network(&state_path, datapath_mode)?;

    Ok(())
}

fn process_running_at(expected: &Path) -> bool {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    system
        .processes()
        .values()
        .any(|process| process.exe().is_some_and(|path| same_path(path, expected)))
}

fn same_path(observed: &Path, expected: &Path) -> bool {
    if observed == expected {
        return true;
    }
    match (observed.canonicalize(), expected.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(windows)]
fn service_binary_path(command: &Path) -> PathBuf {
    let text = command.to_string_lossy();
    if let Some(rest) = text.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        return PathBuf::from(&rest[..end]);
    }
    PathBuf::from(text.split_whitespace().next().unwrap_or_default())
}

#[cfg(windows)]
fn observe_windows_service(expected_controller: &Path) -> Result<Option<u32>, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|err| format!("failed to open Windows SCM: {err}"))?;
    let service = manager
        .open_service(
            WINDOWS_CONTROLLER_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|err| {
            format!("failed to open {WINDOWS_CONTROLLER_SERVICE_NAME} service: {err}")
        })?;
    let config = service
        .query_config()
        .map_err(|err| format!("failed to query controller service config: {err}"))?;
    let status = service
        .query_status()
        .map_err(|err| format!("failed to query controller service status: {err}"))?;

    let configured_command = config.executable_path.clone();
    let configured_binary = service_binary_path(&configured_command);
    let binary_matches = configured_binary == expected_controller
        || same_path(&configured_binary, expected_controller);
    println!("scm_service_name={WINDOWS_CONTROLLER_SERVICE_NAME}");
    println!("scm_start_type={:?}", config.start_type);
    println!(
        "scm_account={}",
        config
            .account_name
            .as_deref()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "LocalSystem".to_owned())
    );
    println!("scm_executable_path={}", configured_command.display());
    println!("scm_binary_path={}", configured_binary.display());
    println!("scm_executable_matches_release={binary_matches}");
    println!("scm_state={:?}", status.current_state);
    println!(
        "scm_process_id={}",
        status
            .process_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "ABSENT".to_owned())
    );
    Ok(status.process_id)
}

#[cfg(windows)]
fn observe_singbox_processes(
    state_path: &Path,
    datapath_mode: WindowsDatapathMode,
    controller_pid: Option<u32>,
) -> Result<(), String> {
    let install_root = state_path
        .parent()
        .ok_or_else(|| "activation state has no install-root parent".to_owned())?;
    let expected_config = install_root.join("runtime").join("sing-box.json");

    let mut system = System::new_all();
    system.refresh_all();
    let mut managed = 0usize;
    let mut conflicting = 0usize;
    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        if !name.contains("sing-box") {
            continue;
        }
        let arguments = process
            .cmd()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let config = extract_config_argument(&arguments);
        let parent_pid = process.parent().map(|value| value.as_u32());
        let config_matches = config
            .as_deref()
            .is_some_and(|value| same_path(Path::new(value), &expected_config));
        let parent_matches = controller_pid.is_some() && parent_pid == controller_pid;
        let is_managed = config_matches || parent_matches;
        if is_managed {
            managed += 1;
        } else {
            conflicting += 1;
        }
        println!(
            "singbox_process=pid:{} managed:{} parent:{} exe:{} config:{} cmd:{}",
            pid.as_u32(),
            is_managed,
            parent_pid
                .map(|value| value.to_string())
                .unwrap_or_else(|| "UNKNOWN".to_owned()),
            process
                .exe()
                .map(|value| value.display().to_string())
                .unwrap_or_else(|| "UNKNOWN".to_owned()),
            config.unwrap_or_else(|| "UNKNOWN".to_owned()),
            arguments.join(" ").replace('\n', " ")
        );
    }
    println!("managed_singbox_process_count={managed}");
    println!("conflicting_singbox_process_count={conflicting}");
    if managed > 1 {
        return Err("multiple managed sing-box processes violate single-owner runtime".to_owned());
    }
    if datapath_mode == WindowsDatapathMode::ManagedTun && conflicting > 0 {
        return Err(
            "MANAGED_TUN activation still observes conflicting external sing-box process ownership"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn extract_config_argument(arguments: &[String]) -> Option<String> {
    arguments.windows(2).find_map(|window| {
        if window[0] == "-c" || window[0] == "--config" {
            Some(window[1].clone())
        } else {
            None
        }
    })
}

#[cfg(windows)]
#[derive(Debug)]
struct AdapterObservation {
    index: u32,
    name: String,
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    dns_ipv4: Vec<Ipv4Addr>,
    dns_ipv6: Vec<Ipv6Addr>,
}

#[cfg(windows)]
fn observe_windows_network(
    state_path: &Path,
    datapath_mode: WindowsDatapathMode,
) -> Result<(), String> {
    let adapters = windows_adapters()?;
    let managed = adapters.iter().find(|adapter| {
        adapter
            .name
            .eq_ignore_ascii_case(MANAGED_TUN_INTERFACE_NAME)
    });
    println!("managed_tun_present={}", managed.is_some());
    if let Some(adapter) = managed {
        println!("managed_tun_interface_index={}", adapter.index);
        println!("managed_tun_ipv4={}", join_values(&adapter.ipv4));
        println!("managed_tun_ipv6={}", join_values(&adapter.ipv6));
        println!("managed_tun_dns_ipv4={}", join_values(&adapter.dns_ipv4));
        println!("managed_tun_dns_ipv6={}", join_values(&adapter.dns_ipv6));
    } else {
        println!("managed_tun_interface_index=ABSENT");
        println!("managed_tun_ipv4=ABSENT");
        println!("managed_tun_ipv6=ABSENT");
        println!("managed_tun_dns_ipv4=ABSENT");
        println!("managed_tun_dns_ipv6=ABSENT");
    }

    if datapath_mode == WindowsDatapathMode::ProxyOnly && managed.is_some() {
        return Err("PROXY_ONLY activation unexpectedly observes managed TUN interface".to_owned());
    }

    for adapter in &adapters {
        if !adapter.ipv4.is_empty()
            || !adapter.ipv6.is_empty()
            || !adapter.dns_ipv4.is_empty()
            || !adapter.dns_ipv6.is_empty()
        {
            println!(
                "adapter=index:{} name:{} ipv4:{} ipv6:{} dns_ipv4:{} dns_ipv6:{}",
                adapter.index,
                adapter.name.replace('\n', " "),
                join_values(&adapter.ipv4),
                join_values(&adapter.ipv6),
                join_values(&adapter.dns_ipv4),
                join_values(&adapter.dns_ipv6)
            );
        }
    }

    let install_root = state_path
        .parent()
        .ok_or_else(|| "activation state has no install-root parent".to_owned())?;
    let runtime_state_path = install_root
        .join("state")
        .join("secrets")
        .join("runtime-state.pb");
    let server_ip = if runtime_state_path.is_file() {
        let bytes = std::fs::read(&runtime_state_path).map_err(|err| {
            format!("failed to read Windows runtime state for route diagnostics: {err}")
        })?;
        Some(decode_windows_runtime_state(&bytes)?.server_ip)
    } else {
        None
    };
    if let Some(server_ip) = server_ip.as_deref() {
        println!("runtime_server_ip={server_ip}");
    } else {
        println!("runtime_server_ip=ABSENT");
    }
    let managed_tun_index = managed.map(|adapter| adapter.index);
    observe_ipv4_routes(&adapters, managed_tun_index, server_ip.as_deref())?;
    observe_ipv6_route_interfaces(&adapters, managed_tun_index)?;
    Ok(())
}

#[cfg(windows)]
fn windows_adapters() -> Result<Vec<AdapterObservation>, String> {
    const INITIAL_BYTES: usize = 15 * 1024;
    const MAX_TRIES: usize = 3;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut required_bytes = INITIAL_BYTES as u32;

    for _ in 0..MAX_TRIES {
        let words = (required_bytes as usize)
            .div_ceil(size_of::<usize>())
            .max(1);
        let mut buffer = vec![0usize; words];
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                null_mut(),
                adapters,
                &mut required_bytes,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if result != 0 {
            return Err(format!(
                "GetAdaptersAddresses failed with Win32 error {result}"
            ));
        }

        let mut out = Vec::new();
        let mut adapter = adapters;
        while !adapter.is_null() {
            let mut index = 0u32;
            let status = unsafe { ConvertInterfaceLuidToIndex(&(*adapter).Luid, &mut index) };
            if status != 0 {
                return Err(format!(
                    "ConvertInterfaceLuidToIndex failed with Win32 error {status}"
                ));
            }
            let name = wide_ptr_to_string(unsafe { (*adapter).FriendlyName });
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            let mut unicast = unsafe { (*adapter).FirstUnicastAddress };
            while !unicast.is_null() {
                let socket = unsafe { (*unicast).Address.lpSockaddr };
                if let Some(value) = sockaddr_ipv4(socket) {
                    ipv4.push(value);
                }
                if let Some(value) = sockaddr_ipv6(socket) {
                    ipv6.push(value);
                }
                unicast = unsafe { (*unicast).Next };
            }
            let mut dns_ipv4 = Vec::new();
            let mut dns_ipv6 = Vec::new();
            let mut dns = unsafe { (*adapter).FirstDnsServerAddress };
            while !dns.is_null() {
                let socket = unsafe { (*dns).Address.lpSockaddr };
                if let Some(value) = sockaddr_ipv4(socket) {
                    dns_ipv4.push(value);
                }
                if let Some(value) = sockaddr_ipv6(socket) {
                    dns_ipv6.push(value);
                }
                dns = unsafe { (*dns).Next };
            }
            ipv4.sort_unstable();
            ipv4.dedup();
            ipv6.sort_unstable();
            ipv6.dedup();
            dns_ipv4.sort_unstable();
            dns_ipv4.dedup();
            dns_ipv6.sort_unstable();
            dns_ipv6.dedup();
            out.push(AdapterObservation {
                index,
                name,
                ipv4,
                ipv6,
                dns_ipv4,
                dns_ipv6,
            });
            adapter = unsafe { (*adapter).Next };
        }
        out.sort_by_key(|adapter| adapter.index);
        return Ok(out);
    }
    Err(format!(
        "GetAdaptersAddresses exceeded {MAX_TRIES} bounded buffer attempts"
    ))
}

#[cfg(windows)]
fn sockaddr_ipv4(
    socket: *mut windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<Ipv4Addr> {
    if socket.is_null() || unsafe { (*socket).sa_family } != AF_INET {
        return None;
    }
    let value = unsafe { &*socket.cast::<SOCKADDR_IN>() };
    Some(Ipv4Addr::from(unsafe {
        value.sin_addr.S_un.S_addr.to_ne_bytes()
    }))
}

#[cfg(windows)]
fn sockaddr_ipv6(socket: *mut SOCKADDR) -> Option<Ipv6Addr> {
    if socket.is_null() || unsafe { (*socket).sa_family } != AF_INET6 {
        return None;
    }
    let value = unsafe { &*socket.cast::<SOCKADDR_IN6>() };
    let bytes = unsafe { *(&value.sin6_addr as *const _ as *const [u8; 16]) };
    Some(Ipv6Addr::from(bytes))
}

#[cfg(windows)]
fn sockaddr_inet_ipv6(socket: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET) -> Ipv6Addr {
    let value = unsafe { &*(socket as *const _ as *const SOCKADDR_IN6) };
    let bytes = unsafe { *(&value.sin6_addr as *const _ as *const [u8; 16]) };
    Ipv6Addr::from(bytes)
}

#[cfg(windows)]
fn wide_ptr_to_string(value: *mut u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) })
}

#[cfg(windows)]
fn observe_ipv4_routes(
    adapters: &[AdapterObservation],
    managed_tun_index: Option<u32>,
    server_ip: Option<&str>,
) -> Result<(), String> {
    let server_ip = server_ip.and_then(|value| value.parse::<Ipv4Addr>().ok());
    let mut bytes = 0u32;
    let first = unsafe { GetIpForwardTable(null_mut(), &mut bytes, 0) };
    if first != ERROR_INSUFFICIENT_BUFFER || bytes == 0 {
        return Err(format!(
            "GetIpForwardTable size query failed with Win32 error {first}"
        ));
    }
    let words = (bytes as usize).div_ceil(size_of::<usize>()).max(1);
    let mut buffer = vec![0usize; words];
    let table = buffer.as_mut_ptr().cast::<MIB_IPFORWARDTABLE>();
    let result = unsafe { GetIpForwardTable(table, &mut bytes, 0) };
    if result != 0 {
        return Err(format!(
            "GetIpForwardTable failed with Win32 error {result}"
        ));
    }

    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { (*table).table.as_ptr() };
    let mut relevant = 0usize;
    let mut by_interface = BTreeMap::<u32, (usize, usize, usize, Vec<String>)>::new();
    for offset in 0..count {
        let row = unsafe { &*rows.add(offset) };
        let destination = Ipv4Addr::from(row.dwForwardDest.to_ne_bytes());
        let next_hop = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
        let prefix = row.dwForwardMask.count_ones();
        let is_default = row.dwForwardDest == 0 && row.dwForwardMask == 0;
        let is_tun = managed_tun_index == Some(row.dwForwardIfIndex);
        let is_server = server_ip.is_some_and(|server| destination == server && prefix == 32);
        let summary = by_interface.entry(row.dwForwardIfIndex).or_default();
        summary.0 += 1;
        summary.1 += usize::from(is_default);
        summary.2 += usize::from(is_server);
        summary.3.push(format!(
            "{destination}/{prefix}|{next_hop}|{}|{}",
            row.dwForwardMetric1, row.dwForwardIfIndex
        ));
        if is_default || is_tun || is_server {
            relevant += 1;
            println!(
                "route_ipv4={destination}/{prefix} if:{} next_hop:{} metric:{} default:{} managed_tun:{} server_bypass:{}",
                row.dwForwardIfIndex, next_hop, row.dwForwardMetric1, is_default, is_tun, is_server
            );
        }
    }
    println!("relevant_ipv4_route_count={relevant}");
    println!("routed_interface_count={}", by_interface.len());
    for (index, (routes, defaults, server_bypasses, mut normalized_routes)) in by_interface {
        normalized_routes.sort_unstable();
        let fingerprint = sha256_lines(&normalized_routes);
        let name = adapters
            .iter()
            .find(|adapter| adapter.index == index)
            .map(|adapter| adapter.name.replace('\n', " "))
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        println!(
            "route_interface=if:{index} name:{name} routes:{routes} defaults:{defaults} managed_tun:{} server_bypasses:{server_bypasses} sha256:{fingerprint}",
            managed_tun_index == Some(index)
        );
    }
    Ok(())
}

#[cfg(windows)]
fn observe_ipv6_route_interfaces(
    adapters: &[AdapterObservation],
    managed_tun_index: Option<u32>,
) -> Result<(), String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    let result = unsafe { GetIpForwardTable2(AF_INET6 as u16, &mut table) };
    if result != 0 {
        return Err(format!(
            "GetIpForwardTable2(AF_INET6) failed with Win32 error {result}"
        ));
    }
    if table.is_null() {
        return Err("GetIpForwardTable2(AF_INET6) returned a null table".to_owned());
    }

    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { (*table).Table.as_ptr() };
    let mut by_interface = BTreeMap::<u32, (usize, usize, Vec<String>)>::new();
    for offset in 0..count {
        let row = unsafe { &*rows.add(offset) };
        let destination = sockaddr_inet_ipv6(&row.DestinationPrefix.Prefix);
        let next_hop = sockaddr_inet_ipv6(&row.NextHop);
        let prefix = row.DestinationPrefix.PrefixLength;
        let summary = by_interface.entry(row.InterfaceIndex).or_default();
        summary.0 += 1;
        summary.1 += usize::from(prefix == 0);
        summary.2.push(format!(
            "{destination}/{prefix}|{next_hop}|{}|{}",
            row.Metric, row.InterfaceIndex
        ));
    }
    unsafe { FreeMibTable(table.cast()) };

    println!("routed_interface_ipv6_count={}", by_interface.len());
    for (index, (routes, defaults, mut normalized_routes)) in by_interface {
        normalized_routes.sort_unstable();
        let fingerprint = sha256_lines(&normalized_routes);
        let name = adapters
            .iter()
            .find(|adapter| adapter.index == index)
            .map(|adapter| adapter.name.replace('\n', " "))
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        println!(
            "route_interface_ipv6=if:{index} name:{name} routes:{routes} defaults:{defaults} managed_tun:{} sha256:{fingerprint}",
            managed_tun_index == Some(index)
        );
    }
    Ok(())
}

#[cfg(windows)]
fn join_values<T: ToString>(values: &[T]) -> String {
    if values.is_empty() {
        "NONE".to_owned()
    } else {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(windows)]
fn sha256_lines(lines: &[String]) -> String {
    sha256_bytes(lines.join("\n").as_bytes())
}

#[cfg(windows)]
fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
fn project_processes() -> BTreeMap<u32, String> {
    let mut system = System::new_all();
    system.refresh_all();
    system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let name = process.name().to_string_lossy().to_ascii_lowercase();
            if name.contains("sing-box")
                || name.contains("edge-controller")
                || name.contains("edge-console")
            {
                Some((
                    pid.as_u32(),
                    format!(
                        "{}|{}",
                        process.name().to_string_lossy().replace('\n', " "),
                        process
                            .exe()
                            .map(|value| value.display().to_string())
                            .unwrap_or_else(|| "UNKNOWN".to_owned())
                            .replace('\n', " ")
                    ),
                ))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(windows)]
fn observe_project_listeners() -> Result<(), String> {
    let projects = project_processes();
    let mut observed = 0usize;
    observed += observe_tcp4_listeners(&projects)?;
    observed += observe_tcp6_listeners(&projects)?;
    observed += observe_udp4_listeners(&projects)?;
    observed += observe_udp6_listeners(&projects)?;
    println!("project_listener_count={observed}");
    Ok(())
}

#[cfg(windows)]
fn query_extended_table(tcp: bool, family: u32, table_class: u32) -> Result<Vec<usize>, String> {
    let mut bytes = 0u32;
    let first = unsafe {
        if tcp {
            GetExtendedTcpTable(null_mut(), &mut bytes, 0, family, table_class as _, 0)
        } else {
            GetExtendedUdpTable(null_mut(), &mut bytes, 0, family, table_class as _, 0)
        }
    };
    if first != ERROR_INSUFFICIENT_BUFFER || bytes == 0 {
        return Err(format!(
            "extended {} table size query failed with Win32 error {first}",
            if tcp { "TCP" } else { "UDP" }
        ));
    }
    let words = (bytes as usize).div_ceil(size_of::<usize>()).max(1);
    let mut buffer = vec![0usize; words];
    let result = unsafe {
        if tcp {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut bytes,
                0,
                family,
                table_class as _,
                0,
            )
        } else {
            GetExtendedUdpTable(
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut bytes,
                0,
                family,
                table_class as _,
                0,
            )
        }
    };
    if result != 0 {
        return Err(format!(
            "GetExtended{}Table failed with Win32 error {result}",
            if tcp { "Tcp" } else { "Udp" }
        ));
    }
    Ok(buffer)
}

#[cfg(windows)]
fn windows_port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

#[cfg(windows)]
fn observe_tcp4_listeners(projects: &BTreeMap<u32, String>) -> Result<usize, String> {
    let buffer = query_extended_table(true, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER as u32)?;
    let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { (*table).table.as_ptr() };
    let mut observed = 0usize;
    for offset in 0..count {
        let row = unsafe { &*rows.add(offset) };
        if let Some(identity) = projects.get(&row.dwOwningPid) {
            observed += 1;
            println!(
                "project_listener=proto:tcp4 local:{}:{} pid:{} process:{}",
                Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()),
                windows_port(row.dwLocalPort),
                row.dwOwningPid,
                identity
            );
        }
    }
    Ok(observed)
}

#[cfg(windows)]
fn observe_tcp6_listeners(projects: &BTreeMap<u32, String>) -> Result<usize, String> {
    let buffer = query_extended_table(true, AF_INET6 as u32, TCP_TABLE_OWNER_PID_LISTENER as u32)?;
    let table = buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { (*table).table.as_ptr() };
    let mut observed = 0usize;
    for offset in 0..count {
        let row = unsafe { &*rows.add(offset) };
        if let Some(identity) = projects.get(&row.dwOwningPid) {
            observed += 1;
            println!(
                "project_listener=proto:tcp6 local:[{}]:{} pid:{} process:{}",
                Ipv6Addr::from(row.ucLocalAddr),
                windows_port(row.dwLocalPort),
                row.dwOwningPid,
                identity
            );
        }
    }
    Ok(observed)
}

#[cfg(windows)]
fn observe_udp4_listeners(projects: &BTreeMap<u32, String>) -> Result<usize, String> {
    let buffer = query_extended_table(false, AF_INET as u32, UDP_TABLE_OWNER_PID as u32)?;
    let table = buffer.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { (*table).table.as_ptr() };
    let mut observed = 0usize;
    for offset in 0..count {
        let row = unsafe { &*rows.add(offset) };
        if let Some(identity) = projects.get(&row.dwOwningPid) {
            observed += 1;
            println!(
                "project_listener=proto:udp4 local:{}:{} pid:{} process:{}",
                Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()),
                windows_port(row.dwLocalPort),
                row.dwOwningPid,
                identity
            );
        }
    }
    Ok(observed)
}

#[cfg(windows)]
fn observe_udp6_listeners(projects: &BTreeMap<u32, String>) -> Result<usize, String> {
    let buffer = query_extended_table(false, AF_INET6 as u32, UDP_TABLE_OWNER_PID as u32)?;
    let table = buffer.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { (*table).table.as_ptr() };
    let mut observed = 0usize;
    for offset in 0..count {
        let row = unsafe { &*rows.add(offset) };
        if let Some(identity) = projects.get(&row.dwOwningPid) {
            observed += 1;
            println!(
                "project_listener=proto:udp6 local:[{}]:{} pid:{} process:{}",
                Ipv6Addr::from(row.ucLocalAddr),
                windows_port(row.dwLocalPort),
                row.dwOwningPid,
                identity
            );
        }
    }
    Ok(observed)
}

fn usage() -> String {
    "usage: edge-diagnostic doctor <current.pb>".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observes_current_process_by_exact_executable_path() {
        let current = std::env::current_exe().unwrap();
        assert!(process_running_at(&current));
    }

    #[cfg(windows)]
    #[test]
    fn service_binary_path_extracts_unquoted_and_quoted_commands() {
        assert_eq!(
            service_binary_path(Path::new(
                r"C:\sing-box\releases\abc\bin\edge-controller.exe windows-service C:\sing-box 127.0.0.1:51051"
            )),
            PathBuf::from(r"C:\sing-box\releases\abc\bin\edge-controller.exe")
        );
        assert_eq!(
            service_binary_path(Path::new(
                r#""C:\Program Files\edge-controller.exe" windows-service C:\sing-box 127.0.0.1:51051"#
            )),
            PathBuf::from(r"C:\Program Files\edge-controller.exe")
        );
    }

    #[cfg(windows)]
    #[test]
    fn singbox_config_argument_is_observed_without_shell_parsing() {
        let args = vec![
            "sing-box.exe".to_owned(),
            "run".to_owned(),
            "-c".to_owned(),
            r"C:\sing-box\runtime\sing-box.json".to_owned(),
        ];
        assert_eq!(
            extract_config_argument(&args).as_deref(),
            Some(r"C:\sing-box\runtime\sing-box.json")
        );
    }

    #[cfg(windows)]
    #[test]
    fn route_mask_prefix_length_is_counted_without_text_parsing() {
        assert_eq!(0u32.count_ones(), 0);
        assert_eq!(0xffff_ffffu32.count_ones(), 32);
        assert_eq!(0x00ff_ffffu32.count_ones(), 24);
    }
}
