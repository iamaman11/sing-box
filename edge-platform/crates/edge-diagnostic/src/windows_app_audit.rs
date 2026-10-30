//! Read-only per-application observations in the existing diagnostic binary.
//! This is not a second app controller and never edits Git, sing-box, routes,
//! DNS, firewall, SCM or foreign Cloudflare One. The existing /host ADMIN
//! transport may invoke it and sign its bounded stdout as a normal receipt.
use super::*;
use edge_shared_types::{
    WindowsActivationState, WindowsApplicationRoute, WindowsApplicationRouting,
    WindowsApplicationScope, WindowsDatapathMode, WindowsDefaultRoute,
    production_windows_route_tag,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::time::Duration;

const MAX_CONNECTION_SNAPSHOT: u64 = 1_048_576;
const MAX_CONNECTIONS: usize = 1024;
const MAX_INVENTORY: usize = 512;
const MAX_INVENTORY_BYTES: usize = 32_768;
const MAX_REGISTRY_SUBKEYS: u32 = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    Pass,
    Fail,
    Unproven,
}
impl Evidence {
    fn text(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Unproven => "UNPROVEN",
        }
    }
}

fn process_connection_path(value: &Value) -> Option<&str> {
    value
        .pointer("/metadata/processPath")
        .and_then(Value::as_str)
}

fn is_managed_tun(value: &Value) -> bool {
    value.pointer("/metadata/type").and_then(Value::as_str) == Some("tun/managed-tun-in")
}

/// A runtime route witness is strictly narrower than an external egress
/// witness. It must be a live tracked native TUN connection from the exact
/// executable path, with the correct first outbound chain. Absence, missing
/// path metadata or incomplete traffic always means UNPROVEN, never PASS.
fn connection_traffic_observed(connection: &Value) -> bool {
    let metadata = &connection["metadata"];
    let destination = metadata
        .get("destinationIP")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
        || metadata
            .get("host")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
    let transport = metadata.get("network").and_then(Value::as_str);
    destination
        && matches!(transport, Some("tcp" | "udp"))
        && connection
            .get("upload")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0)
        && connection
            .get("download")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0)
}

fn assess_application_route(connections: &[Value], app: &WindowsApplicationRoute) -> Evidence {
    let Ok(expected) = production_windows_route_tag(app.route) else {
        return Evidence::Fail;
    };
    let mut observed = false;
    for connection in connections {
        if !process_connection_path(connection)
            .is_some_and(|path| path.eq_ignore_ascii_case(&app.executable_path))
        {
            continue;
        }
        observed = true;
        // A tracked, zero-byte (or one-way) connection is not proof that
        // HTTPS/TCP or UDP traffic actually reached the selected outbound.
        if !is_managed_tun(connection)
            || !connection_traffic_observed(connection)
            || connection
                .get("chains")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
                != Some(expected)
        {
            return Evidence::Fail;
        }
    }
    if observed {
        Evidence::Pass
    } else {
        Evidence::Unproven
    }
}

fn assess_unselected_direct(connections: &[Value], selected: &BTreeSet<String>) -> Evidence {
    let mut observed = false;
    for connection in connections {
        if !is_managed_tun(connection) {
            continue;
        }
        let Some(path) = process_connection_path(connection) else {
            continue;
        };
        if path.is_empty()
            || selected.contains(&path.to_lowercase())
            || path.rsplit('\\').next().is_some_and(|base| {
                base.eq_ignore_ascii_case(
                    edge_shared_types::windows_routing::FOREIGN_WARP_SERVICE_BASENAME,
                )
            })
        {
            continue;
        }
        observed = true;
        if !connection_traffic_observed(connection)
            || connection
                .get("chains")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
                != Some("direct")
        {
            return Evidence::Fail;
        }
    }
    if observed {
        Evidence::Pass
    } else {
        Evidence::Unproven
    }
}

fn validate_snapshot(bytes: &[u8]) -> Result<Vec<Value>, &'static str> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONNECTION_SNAPSHOT {
        return Err("HOST_WINDOWS_APP_CONNECTION_SNAPSHOT_SIZE_INVALID");
    }
    let json: Value = serde_json::from_slice(bytes)
        .map_err(|_| "HOST_WINDOWS_APP_CONNECTION_SNAPSHOT_INVALID")?;
    let connections = json
        .get("connections")
        .and_then(Value::as_array)
        .ok_or("HOST_WINDOWS_APP_CONNECTION_SNAPSHOT_INVALID")?;
    if connections.len() > MAX_CONNECTIONS {
        return Err("HOST_WINDOWS_APP_CONNECTION_SNAPSHOT_TOO_MANY");
    }
    Ok(connections.to_vec())
}

fn running_executables() -> (System, BTreeSet<String>) {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    let paths = sys
        .processes()
        .values()
        .filter_map(|p| p.exe().and_then(|path| path.to_str()))
        .filter(|path| edge_shared_types::host_admin::windows_absolute_path(path))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    (sys, paths)
}

#[derive(Default)]
struct InstalledInventory {
    // Uninstall DisplayName is evidence of a registry registration, not of
    // an executable's installed/current on-disk identity.
    registered_programs: BTreeSet<String>,
    // App Paths gives path candidates to inspect before editing Git desired.
    // Windows does not require applications to register here.
    app_path_candidates: BTreeSet<String>,
}

/// Read-only registry enumeration. A registry display name, App Paths entry,
/// or running process is NOT a verified application identity, and no registry
/// value is ever executed or applied as a route. Both 32/64-bit views and
/// machine/user hives are inspected; missing/inaccessible entries are normal.
fn registry_inventory() -> InstalledInventory {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        REG_SZ, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn read_string(key: HKEY, name: &str) -> Option<String> {
        let wname = wide(name);
        let mut raw = [0u8; 4096];
        let mut size = raw.len() as u32;
        let mut kind = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                if name.is_empty() {
                    std::ptr::null()
                } else {
                    wname.as_ptr()
                },
                std::ptr::null_mut(),
                &mut kind,
                raw.as_mut_ptr(),
                &mut size,
            )
        };
        if status != 0 || kind != REG_SZ || size < 2 || size as usize > raw.len() || size % 2 != 0 {
            return None;
        }
        let units = raw[..size as usize]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let end = units.iter().position(|unit| *unit == 0)?;
        let text = String::from_utf16(&units[..end]).ok()?;
        (!text.is_empty() && text.len() <= 2048 && !text.chars().any(char::is_control))
            .then_some(text)
    }

    fn enumerate(hive: HKEY, view: u32, root: &str, value: &str, target: &mut BTreeSet<String>) {
        let mut key = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(hive, wide(root).as_ptr(), 0, KEY_READ | view, &mut key) } != 0 {
            return;
        }
        for index in 0..MAX_REGISTRY_SUBKEYS {
            let mut name = [0u16; 260];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status != 0 {
                break;
            }
            let Ok(child) = String::from_utf16(&name[..length as usize]) else {
                continue;
            };
            let mut entry = std::ptr::null_mut();
            let subkey = format!("{root}\\{child}");
            if unsafe {
                RegOpenKeyExW(hive, wide(&subkey).as_ptr(), 0, KEY_READ | view, &mut entry)
            } != 0
            {
                continue;
            }
            if let Some(value) = read_string(entry, value) {
                target.insert(value);
            }
            unsafe { RegCloseKey(entry) };
        }
        unsafe { RegCloseKey(key) };
    }
    let mut found = InstalledInventory::default();
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            enumerate(
                hive,
                view,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "DisplayName",
                &mut found.registered_programs,
            );
            enumerate(
                hive,
                view,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
                "",
                &mut found.app_path_candidates,
            );
        }
    }
    // App Paths default strings may be stale or indirect. Expose only
    // currently-existing lexical absolute executable file candidates.
    found.app_path_candidates.retain(|path| {
        edge_shared_types::host_admin::windows_absolute_path(path) && Path::new(path).is_file()
    });
    found
}

fn print_inventory_rows(label: &str, rows: &BTreeSet<String>, budget: &mut usize) -> bool {
    let mut emitted = 0usize;
    for row in rows.iter().take(MAX_INVENTORY) {
        let len = label.len() + 1 + row.len() + 1;
        if len > *budget {
            break;
        }
        println!("{label}={row}");
        *budget -= len;
        emitted += 1;
    }
    emitted < rows.len()
}

fn exact_owned_singbox_pid(
    sys: &System,
    state: &WindowsActivationState,
) -> Result<u32, &'static str> {
    let controllers = sys
        .processes()
        .iter()
        .filter(|(_, process)| {
            process
                .exe()
                .is_some_and(|p| same_path(p, Path::new(&state.controller_path)))
        })
        .map(|(pid, _)| *pid)
        .collect::<Vec<_>>();
    if controllers.len() != 1 {
        return Err("HOST_WINDOWS_APP_SCM_OWNER_UNPROVEN");
    }
    let children = sys
        .processes()
        .iter()
        .filter(|(_, p)| {
            p.exe()
                .is_some_and(|exe| same_path(exe, Path::new(&state.sing_box_path)))
                && p.parent() == Some(controllers[0])
        })
        .map(|(pid, _)| pid.as_u32())
        .collect::<Vec<_>>();
    if children.len() != 1 {
        return Err("HOST_WINDOWS_APP_CHILD_OWNER_UNPROVEN");
    }
    Ok(children[0])
}

/// Only the exact SCM-owned sing-box child may own the loopback Clash API
/// listener. A malicious or stale listener is NOT a trusted route witness.
fn require_exact_api_owner(pid: u32) -> Result<(), &'static str> {
    let buffer = query_extended_table(true, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER as u32)
        .map_err(|_| "HOST_WINDOWS_APP_LISTENER_TABLE_UNAVAILABLE")?;
    let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries as usize };
    if count > 65536 {
        return Err("HOST_WINDOWS_APP_LISTENER_TABLE_UNBOUNDED");
    }
    let rows = unsafe { (*table).table.as_ptr() };
    let mut observed = 0usize;
    for i in 0..count {
        let row = unsafe { &*rows.add(i) };
        if windows_port(row.dwLocalPort) != edge_singbox::STAGE2_CLASH_API_PORT as u16
            || Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()) != Ipv4Addr::LOCALHOST
        {
            continue;
        }
        if row.dwOwningPid != pid {
            return Err("HOST_WINDOWS_APP_LISTENER_FOREIGN_OWNER");
        }
        observed += 1;
    }
    if observed != 1 {
        return Err("HOST_WINDOWS_APP_LISTENER_UNPROVEN");
    }
    Ok(())
}

fn live_connections() -> Result<Vec<Value>, &'static str> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(4))
        .build()
        .map_err(|_| "HOST_WINDOWS_APP_API_CLIENT_UNAVAILABLE")?;
    let mut response = client
        .get(format!(
            "http://127.0.0.1:{}/connections",
            edge_singbox::STAGE2_CLASH_API_PORT
        ))
        .send()
        .map_err(|_| "HOST_WINDOWS_APP_API_UNAVAILABLE")?;
    if !response.status().is_success() {
        return Err("HOST_WINDOWS_APP_API_REJECTED");
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_CONNECTION_SNAPSHOT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_WINDOWS_APP_API_INCOMPLETE")?;
    validate_snapshot(&bytes)
}

fn output_route_rows(
    routing: Option<&WindowsApplicationRouting>,
    connections: Option<&[Value]>,
) -> Result<(), String> {
    let selected =
        routing.filter(|p| p.scope == WindowsApplicationScope::SelectedApplications as i32);
    if let Some(routing) = selected {
        let known = routing
            .applications
            .iter()
            .map(|a| a.executable_path.to_lowercase())
            .collect::<BTreeSet<_>>();
        for app in &routing.applications {
            let expected = production_windows_route_tag(app.route)?;
            let status = connections.map_or(Evidence::Unproven, |rows| {
                assess_application_route(rows, app)
            });
            println!("application_path={}", app.executable_path);
            println!("application_expected_outbound={expected}");
            println!("application_runtime_route={}", status.text());
            // Clash's connection chain is NOT independent public-IP proof.
            println!("application_external_egress=UNPROVEN");
        }
        let other = connections.map_or(Evidence::Unproven, |rows| {
            assess_unselected_direct(rows, &known)
        });
        println!("unselected_application_route={}", other.text());
        println!("unselected_application_external_egress=UNPROVEN");
    } else {
        println!("selected_applications=OFF");
        println!("general_tun_policy=ACTIVE");
        println!("application_runtime_route=UNPROVEN");
        println!("application_external_egress=UNPROVEN");
    }
    Ok(())
}

pub(super) fn run(command: &str, activation: &Path) -> Result<(), String> {
    let root = activation.parent().ok_or("HOST_WINDOWS_APP_ROOT_MISSING")?;
    if !root.to_string_lossy().eq_ignore_ascii_case(r"C:\sing-box") {
        return Err("HOST_WINDOWS_APP_INSTALLED_ROOT_REQUIRED".into());
    }
    edge_shared_types::host_journal::verify_windows_protected_path_acl(activation, true)?;
    let bytes = fs::read(activation).map_err(|_| "HOST_WINDOWS_APP_ACTIVATION_MISSING")?;
    let state = decode_windows_activation_state(&bytes)?;
    verify_windows_activation_files(&state)?;
    let (sys, executables) = running_executables();
    if command == "app-inventory" {
        let installed = registry_inventory();
        println!("source=WINDOWS_REGISTRY_UNINSTALL_APP_PATHS_AND_NATIVE_RUNNING_PROCESSES");
        println!("installed_apps_inventory=PARTIAL_REGISTRY_ONLY");
        println!("registry_names_not_executable_identities=YES");
        println!("registered_app_paths_not_authorized_routes=YES");
        // Reserve a bounded share for each source. A large Uninstall registry
        // must never hide currently-running route candidates.
        let mut program_budget = MAX_INVENTORY_BYTES / 3;
        let mut path_budget = MAX_INVENTORY_BYTES / 3;
        let mut process_budget = MAX_INVENTORY_BYTES / 3;
        let truncated = print_inventory_rows(
            "registered_program_name",
            &installed.registered_programs,
            &mut program_budget,
        ) | print_inventory_rows(
            "registered_app_path_candidate",
            &installed.app_path_candidates,
            &mut path_budget,
        ) | print_inventory_rows("running_executable", &executables, &mut process_budget);
        println!("inventory_truncated={truncated}");
        println!("mutations=0");
        return Ok(());
    }
    let desired = canonical_production_desired_state()?;
    edge_shared_types::windows_routing::validate(desired.windows_application_routing.as_ref())?;
    let mode = WindowsDatapathMode::try_from(desired.windows_datapath_mode)
        .map_err(|_| "HOST_WINDOWS_APP_MODE_INVALID")?;
    if mode != WindowsDatapathMode::ManagedTun {
        println!("managed_tun=OFF");
        println!("selected_applications=INACTIVE_SAVED_IN_GIT");
        println!("application_runtime_route=UNPROVEN");
        println!("application_external_egress=UNPROVEN");
        println!("mutations=0");
        return Ok(());
    }
    let config_path = root.join("runtime/sing-box.json");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&config_path, true)?;
    let config = fs::read(config_path).map_err(|_| "HOST_WINDOWS_APP_CONFIG_UNAVAILABLE")?;
    edge_singbox::verify_managed_application_routes(&config, &desired)?;
    let owned = exact_owned_singbox_pid(&sys, &state).and_then(require_exact_api_owner);
    let connections = match owned.and_then(|_| live_connections()) {
        Ok(rows) => Some(rows),
        Err(reason) => {
            println!("application_api_failure={reason}");
            None
        }
    };
    let (_, tun) = edge_shared_types::windows_native_network::observe_native_managed_tun()?;
    tun.require_native_dual_stack_route_capture()?;
    println!("managed_tun=ON");
    println!("application_config=PASS");
    println!(
        "application_api_owner={}",
        if connections.is_some() {
            "PASS"
        } else {
            "UNPROVEN"
        }
    );
    output_route_rows(
        desired.windows_application_routing.as_ref(),
        connections.as_deref(),
    )?;
    println!("application_external_egress_source=REQUIRES_INDEPENDENT_LIVE_PROBE");
    println!("mutations=0");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn app() -> WindowsApplicationRoute {
        WindowsApplicationRoute {
            executable_path: r"C:\Apps\Browser\firefox.exe".into(),
            route: WindowsDefaultRoute::VlessRealityWarp as i32,
        }
    }
    fn connection(path: &str, out: &str) -> Value {
        json!({
            "metadata": {
                "processPath":path,
                "type":"tun/managed-tun-in",
                "network":"tcp",
                "destinationIP":"203.0.113.20"
            },
            "chains":[out],
            "upload":123,
            "download":456
        })
    }
    #[test]
    fn application_route_evidence_requires_exact_path_and_real_chain() {
        let selected = app();
        assert_eq!(assess_application_route(&[], &selected), Evidence::Unproven);
        assert_eq!(
            assess_application_route(
                &[connection(
                    r"C:\Apps\Other\firefox.exe",
                    "vless-reality-warp"
                )],
                &selected
            ),
            Evidence::Unproven
        );
        assert_eq!(
            assess_application_route(
                &[connection(&selected.executable_path, "vless-reality-warp")],
                &selected
            ),
            Evidence::Pass
        );
        assert_eq!(
            assess_application_route(
                &[connection(&selected.executable_path, "direct")],
                &selected
            ),
            Evidence::Fail
        );
        let mut wrong = connection(&selected.executable_path, "vless-reality-warp");
        wrong["metadata"]["type"] = json!("mixed/mixed-in");
        assert_eq!(
            assess_application_route(&[wrong], &selected),
            Evidence::Fail
        );
        let mut missing = connection(&selected.executable_path, "vless-reality-warp");
        missing["metadata"]["processPath"] = Value::Null;
        assert_eq!(
            assess_application_route(&[missing], &selected),
            Evidence::Unproven
        );
    }
    #[test]
    fn unselected_direct_never_passes_proxy_or_missing_process_identity() {
        let selected = BTreeSet::from([app().executable_path.to_lowercase()]);
        assert_eq!(assess_unselected_direct(&[], &selected), Evidence::Unproven);
        assert_eq!(
            assess_unselected_direct(
                &[connection(r"C:\Apps\Other\example.exe", "direct")],
                &selected
            ),
            Evidence::Pass
        );
        assert_eq!(
            assess_unselected_direct(
                &[connection(
                    r"C:\Apps\Other\example.exe",
                    "vless-reality-warp"
                )],
                &selected
            ),
            Evidence::Fail
        );
        assert_eq!(
            assess_unselected_direct(
                &[connection(&app().executable_path, "vless-reality-warp")],
                &selected
            ),
            Evidence::Unproven
        );
    }
    #[test]
    fn route_evidence_rejects_zero_byte_one_way_or_unattributed_traffic() {
        let chosen = app();
        for field in ["upload", "download"] {
            let mut row = connection(&chosen.executable_path, "vless-reality-warp");
            row[field] = json!(0);
            assert_eq!(assess_application_route(&[row], &chosen), Evidence::Fail);
        }
        for field in ["network", "destinationIP"] {
            let mut row = connection(&chosen.executable_path, "vless-reality-warp");
            row["metadata"][field] = Value::Null;
            assert_eq!(assess_application_route(&[row], &chosen), Evidence::Fail);
        }
        let mut row = connection(r"C:\Apps\Other\example.exe", "direct");
        row["download"] = json!(0);
        assert_eq!(
            assess_unselected_direct(&[row], &BTreeSet::new()),
            Evidence::Fail
        );
    }

    #[test]
    fn snapshot_rejects_wrong_schema_unbounded_and_missing_connections() {
        assert!(validate_snapshot(b"{}").is_err());
        assert!(validate_snapshot(b"[]").is_err());
        assert!(validate_snapshot(b"").is_err());
        assert!(validate_snapshot(&vec![b' '; MAX_CONNECTION_SNAPSHOT as usize + 1]).is_err());
        assert!(
            validate_snapshot(br#"{"connections":[]}"#)
                .unwrap()
                .is_empty()
        );
        let many = json!({"connections":vec![Value::Null;MAX_CONNECTIONS+1]});
        assert!(validate_snapshot(many.to_string().as_bytes()).is_err());
    }
}
