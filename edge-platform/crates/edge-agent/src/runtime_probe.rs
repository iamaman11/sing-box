use std::process::{Command, Stdio};

use edge_shared_types::{RuntimeProbeEvidence, RuntimeProbeStatus};

const MAX_PROBE_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 1024;
const MAX_DIAGNOSTIC_LINES: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct BoundedCommandProbe {
    pub(crate) status: RuntimeProbeStatus,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl BoundedCommandProbe {
    pub(crate) fn evidence(&self) -> RuntimeProbeEvidence {
        RuntimeProbeEvidence {
            status: self.status as i32,
            exit_code: self.exit_code,
            diagnostic_stdout: None,
            diagnostic_stderr: None,
        }
    }

    pub(crate) fn diagnostic_evidence(&self) -> RuntimeProbeEvidence {
        let mut evidence = self.evidence();
        if self.status != RuntimeProbeStatus::Ok {
            evidence.diagnostic_stdout = redacted_diagnostic_output(&self.stdout);
            evidence.diagnostic_stderr = redacted_diagnostic_output(&self.stderr);
        }
        evidence
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
                stderr: err.to_string(),
            };
        }
    };

    bounded_probe_from_parts(
        output.status.code(),
        output.status.success(),
        output.stdout,
        output.stderr,
        require_output,
    )
}

fn bounded_probe_from_parts(
    exit_code: Option<i32>,
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    require_output: bool,
) -> BoundedCommandProbe {
    if stdout.len() > MAX_PROBE_OUTPUT_BYTES || stderr.len() > MAX_PROBE_OUTPUT_BYTES {
        return BoundedCommandProbe {
            status: RuntimeProbeStatus::OutputLimit,
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    let stdout = match String::from_utf8(stdout) {
        Ok(stdout) => stdout,
        Err(_) => {
            return BoundedCommandProbe {
                status: RuntimeProbeStatus::ParseError,
                exit_code,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
    };
    let stderr = String::from_utf8_lossy(&stderr).into_owned();

    if success {
        return BoundedCommandProbe {
            status: if require_output && stdout.trim().is_empty() {
                RuntimeProbeStatus::Empty
            } else {
                RuntimeProbeStatus::Ok
            },
            exit_code,
            stdout,
            stderr,
        };
    }

    let classification_input = format!("{stdout}\n{stderr}");
    BoundedCommandProbe {
        status: classify_probe_failure(exit_code, &classification_input),
        exit_code,
        stdout,
        stderr,
    }
}

pub(crate) fn classify_probe_failure(exit_code: Option<i32>, output: &str) -> RuntimeProbeStatus {
    let lowered = output.to_ascii_lowercase();
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

fn redacted_diagnostic_output(value: &str) -> Option<String> {
    let mut rendered = String::new();
    for raw_line in value.lines().filter(|line| !line.trim().is_empty()).take(MAX_DIAGNOSTIC_LINES) {
        let line = redact_diagnostic_line(raw_line);
        if line.is_empty() {
            continue;
        }
        if !rendered.is_empty() {
            if rendered.len() + 1 >= MAX_DIAGNOSTIC_BYTES {
                break;
            }
            rendered.push('\n');
        }
        let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(rendered.len());
        rendered.extend(line.chars().take(remaining));
        if rendered.len() >= MAX_DIAGNOSTIC_BYTES {
            break;
        }
    }
    if rendered.is_empty() {
        None
    } else {
        Some(rendered)
    }
}

fn redact_diagnostic_line(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_graphic() || ch == ' ' || ch == '\t' {
                ch
            } else {
                '?'
            }
        })
        .collect::<String>();
    let lowered = normalized.to_ascii_lowercase();
    const SENSITIVE_MARKERS: &[&str] = &[
        "authorization:",
        "bearer ",
        "token=",
        "token:",
        "\"token\"",
        "secret=",
        "secret:",
        "\"secret\"",
        "password=",
        "password:",
        "passwd=",
        "private key",
        "private_key",
        "credential=",
        "credential:",
        "\"credential\"",
        "client_secret",
        "api_key",
        "access_key",
    ];
    if SENSITIVE_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return "[REDACTED_SENSITIVE_LINE]".to_owned();
    }

    normalized
        .split_whitespace()
        .map(|token| {
            if looks_secret_like(token) {
                "[REDACTED]".to_owned()
            } else {
                token.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_secret_like(value: &str) -> bool {
    let candidate = value.trim_matches(|ch: char| {
        !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '_' | '-' | '/' | '+' | '=')
    });
    if candidate.len() < 24 {
        return false;
    }

    let alpha = candidate.chars().filter(|ch| ch.is_ascii_alphabetic()).count();
    let digits = candidate.chars().filter(|ch| ch.is_ascii_digit()).count();
    let alnum = alpha + digits;
    candidate.len() >= 40
        || (candidate.matches('.').count() >= 2 && alnum >= 20)
        || (alnum >= 24 && alpha > 0 && digits > 0)
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

    #[test]
    fn non_zero_probe_preserves_stdout_and_stderr_for_local_parsing() {
        let probe = bounded_probe_from_parts(
            Some(1),
            false,
            b"Status update: Connected\n".to_vec(),
            b"daemon returned a non-zero status\n".to_vec(),
            true,
        );
        assert_eq!(probe.status, RuntimeProbeStatus::NonZero);
        assert_eq!(probe.stdout, "Status update: Connected\n");
        assert_eq!(probe.stderr, "daemon returned a non-zero status\n");
    }

    #[test]
    fn diagnostic_evidence_redacts_secret_material() {
        let probe = BoundedCommandProbe {
            status: RuntimeProbeStatus::NonZero,
            exit_code: Some(1),
            stdout: "Status update: Connected\n".to_owned(),
            stderr: "token=mesh-super-secret-value\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz012345\n"
                .to_owned(),
        };
        let evidence = probe.diagnostic_evidence();
        let rendered = format!(
            "{} {}",
            evidence.diagnostic_stdout.unwrap_or_default(),
            evidence.diagnostic_stderr.unwrap_or_default()
        );
        assert!(rendered.contains("Status update: Connected"));
        assert!(!rendered.contains("mesh-super-secret-value"));
        assert!(!rendered.contains("abcdefghijklmnopqrstuvwxyz012345"));
        assert!(rendered.contains("[REDACTED_SENSITIVE_LINE]"));
    }

    #[test]
    fn diagnostic_evidence_is_bounded() {
        let long_line = "safe ".repeat(1000);
        let probe = BoundedCommandProbe {
            status: RuntimeProbeStatus::NonZero,
            exit_code: Some(1),
            stdout: long_line,
            stderr: String::new(),
        };
        let evidence = probe.diagnostic_evidence();
        assert!(
            evidence
                .diagnostic_stdout
                .as_deref()
                .is_some_and(|value| value.len() <= MAX_DIAGNOSTIC_BYTES)
        );
    }

    #[test]
    fn output_limit_never_serializes_raw_output() {
        let probe = bounded_probe_from_parts(
            Some(1),
            false,
            vec![b'x'; MAX_PROBE_OUTPUT_BYTES + 1],
            Vec::new(),
            true,
        );
        assert_eq!(probe.status, RuntimeProbeStatus::OutputLimit);
        let evidence = probe.diagnostic_evidence();
        assert!(evidence.diagnostic_stdout.is_none());
        assert!(evidence.diagnostic_stderr.is_none());
    }
}
