//! A root-owned entry point that only launches a closed read-only toolbox.
//! The actual program is dropped to an unprivileged UID/GID with no extra groups.
//! Runner has no access to shell, docker.sock or generic sudo.
use super::*;
use edge_shared_types::host_diagnostics::{
    MAX_DIAGNOSTIC_OUTPUT_BYTES, MAX_DIAGNOSTIC_REQUEST_BYTES, decode_diagnostic_request,
};
use std::io::Read;
use std::process::{Command, Stdio};

fn diagnostic_binary(tool: &str) -> Result<&'static str, &'static str> {
    match tool {
        "ip" => Ok("/usr/sbin/ip"),
        "ss" => Ok("/usr/bin/ss"),
        "ps" => Ok("/usr/bin/ps"),
        "uname" => Ok("/usr/bin/uname"),
        "uptime" => Ok("/usr/bin/uptime"),
        "resolvectl" => Ok("/usr/bin/resolvectl"),
        "systemctl" => Ok("/usr/bin/systemctl"),
        _ => Err("HOST_DIAG_BINARY_NOT_ALLOWED"),
    }
}

pub(super) fn run_host_probe() -> Result<(), String> {
    // The only request bytes arrive on stdin from a verified same-run GitHub artifact.
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_DIAGNOSTIC_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "HOST_DIAG_STDIN_UNAVAILABLE")?;
    let request = decode_diagnostic_request(&bytes).map_err(str::to_owned)?;
    let host = host_native::registered_vm_host()?;
    if request.machine_id != host.machine_id {
        return Err("HOST_DIAG_NATIVE_MACHINE_MISMATCH".to_owned());
    }
    // Do not require resource-journal admission to inspect a broken system.
    // This function contains NO privileged mutator or resource-repair capability.
    let executable = diagnostic_binary(&request.argv[0]).map_err(str::to_owned)?;
    let mut cmd = Command::new("/usr/bin/timeout");
    cmd.args([
        "--kill-after=1s",
        "7s",
        "/usr/bin/setpriv",
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "--no-new-privs",
    ])
    .arg(executable)
    .args(&request.argv[1..])
    .env_clear()
    .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
    .env("LANG", "C")
    .env("LC_ALL", "C")
    .current_dir("/")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| "HOST_DIAG_LAUNCHER_UNAVAILABLE")?;
    let stdout = child.stdout.take().ok_or("HOST_DIAG_STDOUT_UNAVAILABLE")?;
    let stderr = child.stderr.take().ok_or("HOST_DIAG_STDERR_UNAVAILABLE")?;
    // Do not let an untrusted subprocess allocate arbitrary amounts in the agent.
    let out_thread = std::thread::spawn(move || {
        let mut out = Vec::new();
        stdout
            .take((MAX_DIAGNOSTIC_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut out)
            .map(|_| out)
    });
    let err_thread = std::thread::spawn(move || {
        let mut err = Vec::new();
        stderr
            .take((MAX_DIAGNOSTIC_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut err)
            .map(|_| err)
    });
    let status = child.wait().map_err(|_| "HOST_DIAG_WAIT_UNAVAILABLE")?;
    let stdout = out_thread
        .join()
        .map_err(|_| "HOST_DIAG_STDOUT_THREAD_FAILED")?
        .map_err(|_| "HOST_DIAG_STDOUT_READ_FAILED")?;
    let stderr = err_thread
        .join()
        .map_err(|_| "HOST_DIAG_STDERR_THREAD_FAILED")?
        .map_err(|_| "HOST_DIAG_STDERR_READ_FAILED")?;
    println!("host_diagnostic_source=RUNNER_COPIED_UNAUTHENTICATED");
    println!("host_diagnostic_machine={}", request.machine_id);
    println!("host_diagnostic_comment={}", request.source_comment_id);
    println!("host_diagnostic_tool={}", request.argv[0]);
    println!("host_diagnostic_privilege=UID_65534_GID_65534_CLEAR_GROUPS");
    println!("host_diagnostic_resource_mutations=0");
    println!("host_diagnostic_exit={}", status.code().unwrap_or(-1));
    if stdout.len() > MAX_DIAGNOSTIC_OUTPUT_BYTES || stderr.len() > MAX_DIAGNOSTIC_OUTPUT_BYTES {
        println!("host_diagnostic_result=OUTPUT_LIMIT");
        return Ok(());
    }
    // Only the fixed, read-only toolbox's bounded printable output is public.
    // No environment, proc command-lines, Docker inspect env or raw system logs.
    for (kind, value) in [("stdout", stdout), ("stderr", stderr)] {
        for (index, line) in String::from_utf8_lossy(&value).lines().take(60).enumerate() {
            let printable = line
                .chars()
                .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
                .take(160)
                .collect::<String>();
            println!("host_diagnostic_{kind}_{index}={printable}");
        }
    }
    println!(
        "host_diagnostic_result={}",
        if status.success() {
            "COMMAND_OK"
        } else {
            "COMMAND_FAILED"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_absolute_non_shell_tools_are_addressable() {
        assert_eq!(diagnostic_binary("ip").unwrap(), "/usr/sbin/ip");
        for x in [
            "sh",
            "bash",
            "/bin/bash",
            "docker",
            "sudo",
            "nft",
            "journalctl",
        ] {
            assert!(diagnostic_binary(x).is_err());
        }
    }
}
