//! One native Task Scheduler observation contract for preflight, handoff and status.
//! No task execution, shell, credentials, or alternative management transport.
use super::*;
use std::time::{Duration, Instant};
use windows::Win32::System::TaskScheduler::*;
use windows::core::Interface;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Security::{IsWellKnownSid, LookupAccountNameW, WinLocalSystemSid},
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

#[derive(Debug, Clone)]
pub(super) struct Task {
    pub system: bool,
    pub highest: bool,
    pub service_account: bool,
    pub enabled: bool,
    pub state: i32,
    pub instances: i32,
    pub actions: i32,
    pub executable: String,
    pub arguments: String,
    pub working_directory: String,
}

impl Task {
    pub fn validate_expected(&self, console: &str, expected_state: &str) -> Result<(), String> {
        let enabled = match expected_state {
            "Ready" | "Running" => true,
            "Disabled" => false,
            _ => return Err("HOST_WINDOWS_TASK_EXPECTED_STATE_INVALID".into()),
        };
        self.validate(console, enabled)?;
        if expected_state == "Running" && (self.state != 4 || self.instances < 1) {
            return Err("HOST_WINDOWS_TASK_SYSTEM_INSTANCE_NOT_RUNNING".into());
        }
        Ok(())
    }
    pub fn validate(&self, console: &str, enabled: bool) -> Result<(), String> {
        let checks = [
            (self.system, "PRINCIPAL"),
            (self.highest, "RUN_LEVEL"),
            (self.service_account, "LOGON_TYPE"),
            (self.actions == 1, "ACTION_COUNT"),
            (
                self.executable == console || self.executable == format!("\"{console}\""),
                "EXECUTABLE",
            ),
            (
                matches!(
                    self.arguments.as_str(),
                    "privileged-dispatch --install-root C:\\sing-box"
                        | "privileged-dispatch --install-root \"C:\\sing-box\""
                ),
                "ARGUMENTS",
            ),
            (self.working_directory.is_empty(), "WORKING_DIRECTORY"),
            (self.enabled == enabled, "ENABLED"),
            // Running and Queued are normal for the existing scheduled owner.
            // Its executable/principal are still checked. Quiescence is a
            // separate bounded process-handle wait, mandatory before activation.
            (
                if enabled {
                    matches!(self.state, 2..=4)
                } else {
                    matches!(self.state, 1 | 4)
                },
                "STATE",
            ),
        ];
        for (ok, predicate) in checks {
            if !ok {
                return Err(format!("HOST_WINDOWS_TASK_{predicate}_MISMATCH"));
            }
        }
        Ok(())
    }
}

fn api(stage: &str, error: windows::core::Error) -> String {
    format!(
        "HOST_WINDOWS_TASK_{stage}_HRESULT_{:08X}",
        error.code().0 as u32
    )
}
fn win32(stage: &str) -> String {
    format!("HOST_WINDOWS_TASK_{stage}_WIN32_{}", unsafe {
        GetLastError()
    })
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn is_system(name: &str) -> Result<bool, String> {
    if name == "S-1-5-18" {
        return Ok(true);
    }
    let name = wide(name);
    let mut sid_len = 0;
    let mut domain_len = 0;
    let mut use_type = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut use_type,
        );
    }
    if sid_len == 0 || sid_len > 65536 || domain_len > 65536 {
        return Err(win32("PRINCIPAL_SIZE"));
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_type,
        )
    } == 0
    {
        return Err(win32("PRINCIPAL_LOOKUP"));
    }
    Ok(unsafe { IsWellKnownSid(sid.as_mut_ptr().cast(), WinLocalSystemSid) } != 0)
}

fn with_task<T>(read: impl FnOnce(IRegisteredTask) -> Result<T, String>) -> Result<T, String> {
    let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    hr.ok().map_err(|e| api("COM_INITIALIZE", e))?;
    let _guard = TaskSchedulerComGuard;
    let service: ITaskService = unsafe {
        CoCreateInstance(
            &GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd),
            None::<&IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|e| api("CREATE", e))?;
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(|e| api("CONNECT", e))?;
    let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(|e| api("FOLDER", e))?;
    let task = unsafe { folder.GetTask(&BSTR::from(PRIVILEGED_TASK_NAME)) }
        .map_err(|e| api("GET_TASK", e))?;
    read(task)
}

pub(super) fn observe() -> Result<Task, String> {
    with_task(|task| {
        let definition = unsafe { task.Definition() }.map_err(|e| api("DEFINITION", e))?;
        let principal = unsafe { definition.Principal() }.map_err(|e| api("PRINCIPAL", e))?;
        let mut name = BSTR::new();
        let mut level = TASK_RUNLEVEL_TYPE::default();
        let mut logon = TASK_LOGON_TYPE::default();
        unsafe { principal.UserId(&mut name) }.map_err(|e| api("USER_ID", e))?;
        unsafe { principal.RunLevel(&mut level) }.map_err(|e| api("RUN_LEVEL", e))?;
        unsafe { principal.LogonType(&mut logon) }.map_err(|e| api("LOGON_TYPE", e))?;
        let actions = unsafe { definition.Actions() }.map_err(|e| api("ACTIONS", e))?;
        let mut count = 0;
        unsafe { actions.Count(&mut count) }.map_err(|e| api("ACTION_COUNT", e))?;
        if count != 1 {
            return Err("HOST_WINDOWS_TASK_ACTION_COUNT_MISMATCH".into());
        }
        let action: IExecAction = unsafe { actions.get_Item(1) }
            .map_err(|e| api("ACTION", e))?
            .cast()
            .map_err(|e| api("EXEC_ACTION", e))?;
        let mut executable = BSTR::new();
        let mut arguments = BSTR::new();
        let mut cwd = BSTR::new();
        unsafe { action.Path(&mut executable) }.map_err(|e| api("EXECUTABLE", e))?;
        unsafe { action.Arguments(&mut arguments) }.map_err(|e| api("ARGUMENTS", e))?;
        unsafe { action.WorkingDirectory(&mut cwd) }.map_err(|e| api("WORKING_DIRECTORY", e))?;
        Ok(Task {
            system: is_system(&name.to_string())?,
            highest: level == TASK_RUNLEVEL_HIGHEST,
            service_account: logon == TASK_LOGON_SERVICE_ACCOUNT,
            enabled: unsafe { task.Enabled() }.map_err(|e| api("ENABLED", e))?.0 != 0,
            state: unsafe { task.State() }.map_err(|e| api("STATE", e))?.0,
            instances: unsafe { task.GetInstances(0).and_then(|i| i.Count()) }
                .map_err(|e| api("INSTANCE_COUNT", e))?,
            actions: count,
            executable: executable.to_string(),
            arguments: arguments.to_string(),
            working_directory: cwd.to_string(),
        })
    })
}

/// Configuration change on the same registered task. No registration or Run API.
pub(super) fn set_enabled(enabled: bool) -> Result<(), String> {
    with_task(|task| {
        unsafe {
            task.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(if enabled {
                -1
            } else {
                0
            }))
        }
        .map_err(|e| api("SET_ENABLED", e))
    })
}

/// Share the existing SYSTEM owner lock while its registered task is disabled.
/// This closes the queued-instance/process-enumeration race without introducing
/// another mutex, scheduler or owner. A surviving lock FILE proves nothing.
pub(super) fn exclusive_handoff(root: &Path, console: &str) -> Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    require_explicit_local_administrator_first_use()?;
    let task = observe()?;
    task.validate(console, false)?;
    let journal = root.join("native-host/journal");
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&journal, false)
        .map_err(str::to_owned)?;
    let lock_path = journal.join("owner.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(1 | 2)
        .open(&lock_path)
        .map_err(|_| "HOST_WINDOWS_HANDOFF_OWNER_LOCK_UNAVAILABLE")?;
    edge_shared_types::host_journal::verify_windows_protected_path_acl(&lock_path, true)
        .map_err(str::to_owned)?;
    lock.try_lock()
        .map_err(|_| "HOST_WINDOWS_HANDOFF_OWNER_BUSY_NO_REPLAY")?;
    Ok(lock)
}

struct Handle(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn wait_handle(handle: &Handle, deadline: Instant) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = remaining.as_millis().min(u32::MAX as u128) as u32;
    match unsafe { WaitForSingleObject(handle.0, millis) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err("HOST_WINDOWS_TASK_QUIESCENCE_TIMEOUT_NO_REPLAY".into()),
        _ => Err(win32("WAIT_PROCESS")),
    }
}

/// Wait on exact, open process handles with ONE deadline; never stop a task,
/// terminate a process, poll indefinitely or interpret a PID disappearing as success.
pub(super) fn await_quiescent(console: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(win32("PROCESS_SNAPSHOT"));
    }
    let snapshot = Handle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut handles = Vec::new();
    while next != 0 {
        let length = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if entry.th32ProcessID != std::process::id()
            && name.eq_ignore_ascii_case("edge-console.exe")
        {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    entry.th32ProcessID,
                )
            };
            if handle.is_null() {
                // It may have exited before OpenProcess. Prove it via one
                // fresh inventory, rather than accepting any access failure.
                if unsafe { GetLastError() } == 87
                    && edge_local_runtime::observe_process(entry.th32ProcessID).is_none()
                {
                    next = unsafe { Process32NextW(snapshot.0, &mut entry) };
                    continue;
                }
                return Err(win32("OPEN_PROCESS"));
            }
            let handle = Handle(handle);
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length) }
                == 0
            {
                return Err(win32("PROCESS_IMAGE"));
            }
            let path = String::from_utf16_lossy(&path[..length as usize]);
            if !path.eq_ignore_ascii_case(console) {
                return Err("HOST_WINDOWS_TASK_COMPETING_CONSOLE".into());
            }
            handles.push(handle);
        }
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
        return Err(win32("PROCESS_ENUMERATION"));
    }
    for handle in &handles {
        wait_handle(handle, deadline)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn exact() -> Task {
        Task {
            system: true,
            highest: true,
            service_account: true,
            enabled: true,
            state: 3,
            instances: 0,
            actions: 1,
            executable: "C:\\release\\edge-console.exe".into(),
            arguments: "privileged-dispatch --install-root \"C:\\sing-box\"".into(),
            working_directory: String::new(),
        }
    }
    #[test]
    fn windows_handoff_task_schedule_is_not_identity() {
        let mut task = exact();
        for state in [2, 3, 4] {
            task.state = state;
            task.instances = i32::from(state == 4);
            task.validate(&task.executable, true).unwrap();
        }
        task.enabled = false;
        task.state = 1;
        task.validate(&task.executable, false).unwrap();
        task.state = 4;
        task.instances = 1;
        task.validate(&task.executable, false).unwrap();
        assert!(
            task.validate(&task.executable, true)
                .unwrap_err()
                .contains("ENABLED")
        );
    }
    #[test]
    fn windows_handoff_system_entry_requires_the_actual_running_instance() {
        let mut task = exact();
        assert_eq!(
            task.validate_expected(&task.executable, "Running")
                .unwrap_err(),
            "HOST_WINDOWS_TASK_SYSTEM_INSTANCE_NOT_RUNNING"
        );
        task.state = 4;
        task.instances = 1;
        task.validate_expected(&task.executable, "Running").unwrap();
        task.enabled = false;
        assert!(
            task.validate_expected(&task.executable, "Running")
                .unwrap_err()
                .contains("ENABLED")
        );
        assert!(
            task.validate_expected(&task.executable, "arbitrary")
                .unwrap_err()
                .contains("EXPECTED_STATE")
        );
    }
    #[test]
    fn windows_handoff_task_rejects_each_authority_drift() {
        let mut cases = Vec::new();
        let mut t = exact();
        t.system = false;
        cases.push((t, "PRINCIPAL"));
        let mut t = exact();
        t.highest = false;
        cases.push((t, "RUN_LEVEL"));
        let mut t = exact();
        t.service_account = false;
        cases.push((t, "LOGON_TYPE"));
        let mut t = exact();
        t.actions = 2;
        cases.push((t, "ACTION_COUNT"));
        let mut t = exact();
        t.executable.push_str(".other");
        cases.push((t, "EXECUTABLE"));
        let mut t = exact();
        t.arguments.push_str(" --other");
        cases.push((t, "ARGUMENTS"));
        let mut t = exact();
        t.working_directory = "C:\\Users".into();
        cases.push((t, "WORKING_DIRECTORY"));
        let mut t = exact();
        t.state = 0;
        cases.push((t, "STATE"));
        for (t, code) in cases {
            assert_eq!(
                t.validate(&exact().executable, true).unwrap_err(),
                format!("HOST_WINDOWS_TASK_{code}_MISMATCH")
            );
        }
    }
    #[test]
    fn windows_handoff_localized_system_is_resolved_by_windows() {
        assert!(is_system("S-1-5-18").unwrap());
        assert!(is_system("NT AUTHORITY\\SYSTEM").unwrap());
        assert!(!is_system(&env::var("USERNAME").unwrap()).unwrap());
    }
    #[test]
    fn windows_handoff_waits_for_real_process_without_killing_it() {
        // A native child stays alive until the parent supplies stdin. No CLR
        // startup or sleep duration can race the timeout assertion on CI.
        let mut child = Command::new("cmd.exe")
            .args(["/D", "/C", "set /p fixture= & exit /b 0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let handle = Handle(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, child.id()) });
        assert!(!handle.0.is_null());
        assert_eq!(
            wait_handle(&handle, Instant::now() + Duration::from_millis(1)).unwrap_err(),
            "HOST_WINDOWS_TASK_QUIESCENCE_TIMEOUT_NO_REPLAY"
        );
        assert!(child.try_wait().unwrap().is_none());
        child.stdin.take().unwrap().write_all(b"\r\n").unwrap();
        wait_handle(&handle, Instant::now() + Duration::from_secs(10)).unwrap();
        assert!(child.wait().unwrap().success());
    }
    #[test]
    fn windows_handoff_native_task_api_readback_does_not_need_a_shell() {
        // Existing task if present; an isolated runner must report a precise
        // missing-task HRESULT. This test NEVER registers, changes or runs it.
        match observe() {
            Ok(task) => assert!(task.actions > 0),
            Err(error) => assert!(
                error.starts_with("HOST_WINDOWS_TASK_") && error.contains("_HRESULT_"),
                "{error}"
            ),
        }
    }
}
