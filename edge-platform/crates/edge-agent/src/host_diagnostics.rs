use std::fs;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use edge_shared_types::{
    HostIdentityDiagnostics, HostResourceDiagnostics, HostRuntimeDiagnostics, HostTimeDiagnostics,
    RuntimeProbeEvidence, RuntimeProbeStatus,
};

const MAX_DIAGNOSTIC_DETAIL: usize = 256;

pub(crate) fn collect_host_runtime_diagnostics() -> HostRuntimeDiagnostics {
    HostRuntimeDiagnostics {
        identity: Some(collect_identity()),
        time: Some(collect_time()),
        resources: Some(collect_resources()),
    }
}

fn collect_identity() -> HostIdentityDiagnostics {
    let hostname = fs::read_to_string("/etc/hostname");
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease");

    let failure = hostname
        .as_ref()
        .err()
        .map(|err| ("hostname", err))
        .or_else(|| kernel.as_ref().err().map(|err| ("kernel_release", err)));

    HostIdentityDiagnostics {
        probe: Some(match failure {
            Some((label, err)) => io_failure_evidence(label, err),
            None => ok_evidence(),
        }),
        hostname: hostname
            .ok()
            .and_then(|value| bounded_nonempty(&value, 128)),
        kernel_release: kernel.ok().and_then(|value| bounded_nonempty(&value, 128)),
        architecture: Some(std::env::consts::ARCH.to_owned()),
    }
}

fn collect_time() -> HostTimeDiagnostics {
    let unix_time_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs());
    let uptime_raw = fs::read_to_string("/proc/uptime");
    let uptime_seconds = uptime_raw.as_deref().ok().and_then(parse_uptime_seconds);

    let probe = match (&uptime_raw, unix_time_seconds, uptime_seconds) {
        (Err(err), _, _) => io_failure_evidence("uptime", err),
        (Ok(_), None, _) => parse_failure_evidence("system clock before unix epoch"),
        (Ok(_), Some(_), None) => parse_failure_evidence("failed to parse /proc/uptime"),
        _ => ok_evidence(),
    };

    HostTimeDiagnostics {
        probe: Some(probe),
        unix_time_seconds,
        uptime_seconds,
    }
}

fn collect_resources() -> HostResourceDiagnostics {
    let logical_cpus = std::thread::available_parallelism()
        .ok()
        .and_then(|value| u32::try_from(value.get()).ok());
    let load_raw = fs::read_to_string("/proc/loadavg");
    let memory_raw = fs::read_to_string("/proc/meminfo");

    let loads = load_raw.as_deref().ok().and_then(parse_loadavg);
    let memory = memory_raw.as_deref().ok().and_then(parse_meminfo);

    let probe = if let Err(err) = &load_raw {
        io_failure_evidence("loadavg", err)
    } else if let Err(err) = &memory_raw {
        io_failure_evidence("meminfo", err)
    } else if logical_cpus.is_none() {
        parse_failure_evidence("logical CPU count unavailable")
    } else if loads.is_none() {
        parse_failure_evidence("failed to parse /proc/loadavg")
    } else if memory.is_none() {
        parse_failure_evidence("failed to parse /proc/meminfo")
    } else {
        ok_evidence()
    };

    let (load_1, load_5, load_15) = loads
        .map(|(one, five, fifteen)| (Some(one), Some(five), Some(fifteen)))
        .unwrap_or((None, None, None));
    let (memory_total_bytes, memory_available_bytes) = memory
        .map(|(total, available)| (Some(total), Some(available)))
        .unwrap_or((None, None));

    HostResourceDiagnostics {
        probe: Some(probe),
        logical_cpus,
        load_1,
        load_5,
        load_15,
        memory_total_bytes,
        memory_available_bytes,
    }
}

fn ok_evidence() -> RuntimeProbeEvidence {
    RuntimeProbeEvidence {
        status: RuntimeProbeStatus::Ok as i32,
        exit_code: None,
        diagnostic_stdout: None,
        diagnostic_stderr: None,
    }
}

fn io_failure_evidence(label: &str, err: &io::Error) -> RuntimeProbeEvidence {
    let status = if err.kind() == io::ErrorKind::PermissionDenied {
        RuntimeProbeStatus::PermissionDenied
    } else if err.kind() == io::ErrorKind::NotFound {
        RuntimeProbeStatus::Unsupported
    } else {
        RuntimeProbeStatus::NonZero
    };
    RuntimeProbeEvidence {
        status: status as i32,
        exit_code: None,
        diagnostic_stdout: None,
        diagnostic_stderr: Some(bounded_detail(&format!("{label}: {err}"))),
    }
}

fn parse_failure_evidence(detail: &str) -> RuntimeProbeEvidence {
    RuntimeProbeEvidence {
        status: RuntimeProbeStatus::ParseError as i32,
        exit_code: None,
        diagnostic_stdout: None,
        diagnostic_stderr: Some(bounded_detail(detail)),
    }
}

fn bounded_detail(value: &str) -> String {
    value.chars().take(MAX_DIAGNOSTIC_DETAIL).collect()
}

fn bounded_nonempty(value: &str, max_len: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.chars().take(max_len).collect())
    }
}

fn parse_uptime_seconds(value: &str) -> Option<u64> {
    let seconds = value.split_whitespace().next()?.parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds.is_sign_negative() {
        return None;
    }
    Some(seconds.floor() as u64)
}

fn parse_loadavg(value: &str) -> Option<(f64, f64, f64)> {
    let mut fields = value.split_whitespace();
    let one = fields.next()?.parse::<f64>().ok()?;
    let five = fields.next()?.parse::<f64>().ok()?;
    let fifteen = fields.next()?.parse::<f64>().ok()?;
    if [one, five, fifteen]
        .iter()
        .any(|value| !value.is_finite() || value.is_sign_negative())
    {
        return None;
    }
    Some((one, five, fifteen))
}

fn parse_meminfo(value: &str) -> Option<(u64, u64)> {
    let mut total_kib = None;
    let mut available_kib = None;
    for line in value.lines() {
        let mut fields = line.split_whitespace();
        match fields.next()? {
            "MemTotal:" => total_kib = fields.next()?.parse::<u64>().ok(),
            "MemAvailable:" => available_kib = fields.next()?.parse::<u64>().ok(),
            _ => {}
        }
    }
    Some((
        total_kib?.checked_mul(1024)?,
        available_kib?.checked_mul(1024)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uptime_load_and_memory_without_shell_text_contracts() {
        assert_eq!(parse_uptime_seconds("123.99 45.0\n"), Some(123));
        assert_eq!(
            parse_loadavg("0.10 0.20 0.30 1/100 123\n"),
            Some((0.10, 0.20, 0.30))
        );
        assert_eq!(
            parse_meminfo(
                "MemTotal:       1024 kB\nMemFree:         128 kB\nMemAvailable:    512 kB\n"
            ),
            Some((1024 * 1024, 512 * 1024))
        );
    }

    #[test]
    fn parser_rejects_incomplete_or_invalid_resource_evidence() {
        assert_eq!(parse_uptime_seconds("not-a-number"), None);
        assert_eq!(parse_loadavg("0.1 0.2"), None);
        assert_eq!(parse_meminfo("MemTotal: 1024 kB\n"), None);
    }

    #[test]
    fn diagnostic_detail_is_bounded() {
        assert_eq!(
            bounded_detail(&"x".repeat(1024)).len(),
            MAX_DIAGNOSTIC_DETAIL
        );
    }
}
