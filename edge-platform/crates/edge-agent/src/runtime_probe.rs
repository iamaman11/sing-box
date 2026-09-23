use std::process::{Command, Stdio};

use edge_shared_types::{RuntimeProbeEvidence, RuntimeProbeStatus};

#[derive(Debug, Clone)]
pub(crate) struct BoundedCommandProbe {
    pub(crate) status: RuntimeProbeStatus,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
}

impl BoundedCommandProbe {
    pub(crate) fn evidence(&self) -> RuntimeProbeEvidence {
        RuntimeProbeEvidence {
            status: self.status as i32,
            exit_code: self.exit_code,
        }
    }
}

pub(crate) fn bounded_command_probe(
    program: &str,
    args: &[&str],
    timeout_seconds: u64,
    require_output: bool,
) -> BoundedCommandProbe {
    let timeout = format!("{timeout_seconds}s");
    let output = match Command::new("timeout")
        .arg(timeout)
        .arg(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            return BoundedCommandProbe {
                status: if err.kind() == std::io::ErrorKind::NotFound {
                    RuntimeProbeStatus::CommandNotFound
                } else {
                    RuntimeProbeStatus::NonZero
                },
                exit_code: None,
                stdout: String::new(),
            };
        }
    };

    let exit_code = output.status.code();
    if output.stdout.len() > 16 * 1024 || output.stderr.len() > 16 * 1024 {
        return BoundedCommandProbe {
            status: RuntimeProbeStatus::OutputLimit,
            exit_code,
            stdout: String::new(),
        };
    }

    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(_) => {
            return BoundedCommandProbe {
                status: RuntimeProbeStatus::ParseError,
                exit_code,
                stdout: String::new(),
            };
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        return BoundedCommandProbe {
            status: if require_output && stdout.trim().is_empty() {
                RuntimeProbeStatus::Empty
            } else {
                RuntimeProbeStatus::Ok
            },
            exit_code,
            stdout,
        };
    }

    BoundedCommandProbe {
        status: classify_probe_failure(exit_code, &stderr),
        exit_code,
        stdout: String::new(),
    }
}

pub(crate) fn classify_probe_failure(
    exit_code: Option<i32>,
    stderr: &str,
) -> RuntimeProbeStatus {
    let lowered = stderr.to_ascii_lowercase();
    if exit_code == Some(124) {
        RuntimeProbeStatus::Timeout
    } else if exit_code == Some(126) || lowered.contains("permission denied") {
        RuntimeProbeStatus::PermissionDenied
    } else if lowered.contains("unknown command")
        || lowered.contains("unknown subcommand")
        || lowered.contains("unsupported")
        || lowered.contains("not supported")
        || lowered.contains("unrecognized option")
    {
        RuntimeProbeStatus::Unsupported
    } else if exit_code == Some(127)
        || lowered.contains("executable file not found")
        || lowered.contains("command not found")
        || lowered.contains("no such file or directory")
    {
        RuntimeProbeStatus::CommandNotFound
    } else {
        RuntimeProbeStatus::NonZero
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_runtime_probe_failure_boundaries() {
        assert_eq!(
            classify_probe_failure(Some(124), ""),
            RuntimeProbeStatus::Timeout
        );
        assert_eq!(
            classify_probe_failure(Some(127), "executable file not found"),
            RuntimeProbeStatus::CommandNotFound
        );
        assert_eq!(
            classify_probe_failure(Some(1), "permission denied"),
            RuntimeProbeStatus::PermissionDenied
        );
        assert_eq!(
            classify_probe_failure(Some(2), "unknown subcommand settings"),
            RuntimeProbeStatus::Unsupported
        );
        assert_eq!(
            classify_probe_failure(Some(1), "connection failed"),
            RuntimeProbeStatus::NonZero
        );
    }
}
