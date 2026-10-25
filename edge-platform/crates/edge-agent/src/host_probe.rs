//! An installed root-owned entry point for a closed unprivileged diagnostic
//! toolbox. The GitHub runner has no generic sudo or Docker socket access.
use super::*;
use edge_shared_types::host_diagnostics::{
    MAX_DIAGNOSTIC_OUTPUT_BYTES, MAX_DIAGNOSTIC_REQUEST_BYTES, decode_diagnostic_request,
    diagnostic_commands,
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

fn run_one_diagnostic(index: usize, argv: &[&str]) -> Result<bool, String> {
    let executable = diagnostic_binary(argv[0]).map_err(str::to_owned)?;
    // Root ownership is retained by the existing Agent process; the probed
    // executable is launched with an unprivileged UID and no groups.
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
    .args(&argv[1..])
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

    println!("host_diagnostic_{index}_tool={}", argv[0]);
    println!("host_diagnostic_{index}_exit={}", status.code().unwrap_or(-1));
    if stdout.len() > MAX_DIAGNOSTIC_OUTPUT_BYTES || stderr.len() > MAX_DIAGNOSTIC_OUTPUT_BYTES {
        println!("host_diagnostic_{index}_result=OUTPUT_LIMIT");
        return Ok(false);
    }

    // The fixed readonly grammar excludes raw journals, process args,
    // unbounded file reads, Docker inspect-env and secret-bearing commands.
    for (kind, value) in [("stdout", stdout), ("stderr", stderr)] {
        for (line_index, line) in String::from_utf8_lossy(&value).lines().take(60).enumerate() {
            let printable = line
                .chars()
                .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
                .take(160)
                .collect::<String>();
            println!("host_diagnostic_{index}_{kind}_{line_index}={printable}");
        }
    }
    let success = status.success();
    println!(
        "host_diagnostic_{index}_result={}",
        if success { "COMMAND_OK" } else { "COMMAND_FAILED" }
    );
    Ok(success)
}

pub(super) fn run_host_probe() -> Result<(), String> {
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
    // Validate ALL members first, including the last. Never execute part
    // of an invalid batch. This path does not inspect or mutate the journal.
    let commands = diagnostic_commands(&request).map_err(str::to_owned)?;
    println!("host_diagnostic_source=RUNNER_COPIED_UNAUTHENTICATED");
    println!("host_diagnostic_machine={}", request.machine_id);
    println!("host_diagnostic_comment={}", request.source_comment_id);
    println!("host_diagnostic_privilege=UID_65534_GID_65534_CLEAR_GROUPS");
    println!("host_diagnostic_resource_mutations=0");
    println!("host_diagnostic_commands={}", commands.len());
    let mut failures = 0usize;
    for (index, argv) in commands.iter().enumerate() {
        if !run_one_diagnostic(index, argv)? {
            failures += 1;
        }
    }
    println!("host_diagnostic_command_failures={failures}");
    println!(
        "host_diagnostic_result={}",
        if failures == 0 { "COMMANDS_OK" } else { "PARTIAL_COMMAND_FAILURE" }
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
