//! Closed, read-only diagnostic grammar shared by the Git coordinator and native owner.
//! It is a safety boundary: accepting argv is not accepting an arbitrary executable.
use crate::FleetHostDiagnosticRequest;
use prost::Message;

pub const MAX_DIAGNOSTIC_REQUEST_BYTES: usize = 4096;
pub const MAX_DIAGNOSTIC_OUTPUT_BYTES: usize = 8192;

pub fn validate_diagnostic_request(request: &FleetHostDiagnosticRequest) -> Result<(), &'static str> {
    if request.schema_version != 1 || request.source_comment_id == 0 {
        return Err("HOST_DIAG_REQUEST_IDENTITY_INVALID");
    }
    if request.machine_id.is_empty()
        || request.machine_id.len() > 64
        || !request.machine_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("HOST_DIAG_MACHINE_INVALID");
    }
    if request.argv.is_empty() || request.argv.len() > 8
        || request.argv.iter().any(|arg| arg.is_empty() || arg.len() > 80
            || !arg.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b',' | b'/' | b':' )))
    {
        return Err("HOST_DIAG_ARGV_INVALID");
    }
    let a = request.argv.iter().map(String::as_str).collect::<Vec<_>>();
    let allowed = match a.as_slice() {
        ["ip", "-4" | "-6", "address" | "addr" | "link", "show"]
        | ["ip", "link", "show"]
        | ["ip", "-4" | "-6", "rule", "show"]
        | ["ip", "-4" | "-6", "route", "show", "table", "all"]
        | ["ss", "-tuna"] | ["ss", "-tln"]
        | ["ps", "-eo", "pid,ppid,stat,comm"]
        | ["uname", "-r"]
        | ["uptime"]
        | ["resolvectl", "status"]
        | ["systemctl", "--failed", "--no-pager"] => true,
        ["ip", "-4" | "-6", "route", "show", "table", id] =>
            id.parse::<u32>().is_ok_and(|value| value > 0),
        _ => false,
    };
    if !allowed {
        return Err("HOST_DIAG_COMMAND_NOT_READONLY_ALLOWED");
    }
    if request.encoded_len() > MAX_DIAGNOSTIC_REQUEST_BYTES {
        return Err("HOST_DIAG_REQUEST_TOO_LARGE");
    }
    Ok(())
}

pub fn decode_diagnostic_request(data: &[u8]) -> Result<FleetHostDiagnosticRequest, &'static str> {
    if data.is_empty() || data.len() > MAX_DIAGNOSTIC_REQUEST_BYTES {
        return Err("HOST_DIAG_REQUEST_SIZE_INVALID");
    }
    let request = FleetHostDiagnosticRequest::decode(data)
        .map_err(|_| "HOST_DIAG_REQUEST_PROTOBUF_INVALID")?;
    validate_diagnostic_request(&request)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(args: &[&str]) -> FleetHostDiagnosticRequest {
        FleetHostDiagnosticRequest {
            schema_version: 1,
            machine_id: "application-acceptance-4".into(),
            source_comment_id: 123,
            argv: args.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn allow_readonly_variations_without_new_handler() {
        for args in [
            vec!["ip", "-6", "route", "show", "table", "all"],
            vec!["ip", "-4", "route", "show", "table", "100"],
            vec!["ip", "-6", "rule", "show"],
            vec!["ip", "-4", "addr", "show"],
            vec!["ip", "link", "show"],
            vec!["ss", "-tuna"],
            vec!["ps", "-eo", "pid,ppid,stat,comm"],
            vec!["resolvectl", "status"],
            vec!["systemctl", "--failed", "--no-pager"],
            vec!["uname", "-r"],
            vec!["uptime"],
        ] {
            let r = request(&args);
            validate_diagnostic_request(&r).unwrap();
            assert_eq!(decode_diagnostic_request(&r.encode_to_vec()).unwrap(), r);
        }
    }

    #[test]
    fn reject_shell_writes_secrets_and_unbounded_args() {
        for args in [
            vec!["ip", "-6", "route", "add", "default"],
            vec!["ip", "netns", "exec", "test", "bash"],
            vec!["systemctl", "restart", "docker"],
            vec!["sh", "-c", "id"],
            vec!["ip", "-6", "route", "show", "table", "0"],
            vec!["ip", "-6", "route", "show", "table", "all;id"],
            vec!["docker", "inspect", "secret"],
            vec!["journalctl", "-u", "root"],
        ] {
            assert!(validate_diagnostic_request(&request(&args)).is_err(), "{args:?}");
        }
    }
}
