//! Closed, read-only diagnostic grammar shared by Git and the installed owner.
//! "--next" batches safe independent probes without another workflow, shell,
//! root capability, or a new operator route.
use crate::FleetHostDiagnosticRequest;
use prost::Message;

pub const MAX_DIAGNOSTIC_REQUEST_BYTES: usize = 4096;
pub const MAX_DIAGNOSTIC_OUTPUT_BYTES: usize = 8192;
pub const MAX_DIAGNOSTIC_BATCH_COMMANDS: usize = 6;

fn approved_readonly_command(args: &[&str]) -> bool {
    match args {
        ["ip", "-4" | "-6", "address" | "addr" | "link", "show"]
        | ["ip", "link", "show"]
        | ["ip", "-4" | "-6", "rule", "show"]
        | ["ip", "-4" | "-6", "route", "show", "table", "all"]
        | ["ss", "-tuna"]
        | ["ss", "-tln"]
        | ["ps", "-eo", "pid,ppid,stat,comm"]
        | ["uname", "-r"]
        | ["uptime"]
        | ["resolvectl", "status"]
        | ["systemctl", "--failed", "--no-pager"] => true,
        ["ip", "-4" | "-6", "route", "show", "table", id] => {
            id.parse::<u32>().is_ok_and(|value| value > 0)
        }
        _ => false,
    }
}

fn parse_commands(argv: &[String]) -> Result<Vec<Vec<&str>>, &'static str> {
    let mut commands = Vec::new();
    let mut command = Vec::new();
    for arg in argv {
        if arg == "--next" {
            if command.is_empty() || !approved_readonly_command(&command) {
                return Err("HOST_DIAG_BATCH_SEGMENT_NOT_READONLY_ALLOWED");
            }
            commands.push(std::mem::take(&mut command));
            if commands.len() >= MAX_DIAGNOSTIC_BATCH_COMMANDS {
                return Err("HOST_DIAG_BATCH_TOO_MANY_COMMANDS");
            }
        } else {
            command.push(arg.as_str());
            if command.len() > 8 {
                return Err("HOST_DIAG_BATCH_ARGV_TOO_LARGE");
            }
        }
    }
    if command.is_empty() || !approved_readonly_command(&command) {
        return Err("HOST_DIAG_BATCH_SEGMENT_NOT_READONLY_ALLOWED");
    }
    commands.push(command);
    if commands.len() > MAX_DIAGNOSTIC_BATCH_COMMANDS {
        return Err("HOST_DIAG_BATCH_TOO_MANY_COMMANDS");
    }
    Ok(commands)
}

/// Decode/validate the WHOLE batch before executing the FIRST native probe.
/// A dangerous later segment rejects the whole request, rather than running
/// earlier commands and then discovering the invalid one.
pub fn diagnostic_commands(
    request: &FleetHostDiagnosticRequest,
) -> Result<Vec<Vec<&str>>, &'static str> {
    validate_diagnostic_request(request)?;
    parse_commands(&request.argv)
}

pub fn validate_diagnostic_request(
    request: &FleetHostDiagnosticRequest,
) -> Result<(), &'static str> {
    if request.schema_version != 1 || request.source_comment_id == 0 {
        return Err("HOST_DIAG_REQUEST_IDENTITY_INVALID");
    }
    if request.machine_id.is_empty()
        || request.machine_id.len() > 64
        || !request
            .machine_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("HOST_DIAG_MACHINE_INVALID");
    }
    if request.argv.is_empty()
        || request.argv.len() > MAX_DIAGNOSTIC_BATCH_COMMANDS * 9
        || request.argv.iter().any(|arg| {
            arg.is_empty()
                || arg.len() > 80
                || !arg.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'_' | b'.' | b',' | b'/' | b':')
                })
        })
    {
        return Err("HOST_DIAG_ARGV_INVALID");
    }
    if request.encoded_len() > MAX_DIAGNOSTIC_REQUEST_BYTES {
        return Err("HOST_DIAG_REQUEST_TOO_LARGE");
    }
    parse_commands(&request.argv)?;
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
            assert_eq!(diagnostic_commands(&r).unwrap().len(), 1);
        }
    }

    #[test]
    fn one_request_contains_several_independent_native_probes() {
        let r = request(&[
            "ip", "-4", "route", "show", "table", "all",
            "--next", "ip", "-6", "rule", "show",
            "--next", "ss", "-tln",
            "--next", "systemctl", "--failed", "--no-pager",
            "--next", "ps", "-eo", "pid,ppid,stat,comm",
            "--next", "uptime",
        ]);
        let commands = diagnostic_commands(&r).unwrap();
        assert_eq!(commands.len(), MAX_DIAGNOSTIC_BATCH_COMMANDS);
        assert_eq!(commands[0], ["ip", "-4", "route", "show", "table", "all"]);
        assert_eq!(commands[5], ["uptime"]);
        assert_eq!(decode_diagnostic_request(&r.encode_to_vec()).unwrap(), r);
    }

    #[test]
    fn deny_entire_batch_if_any_segment_is_unsafe_or_incomplete() {
        for args in [
            vec!["uptime", "--next", "systemctl", "restart", "docker"],
            vec!["uptime", "--next", "docker", "exec", "root"],
            vec!["uptime", "--next", "sh", "-c", "id"],
            vec!["--next", "uptime"],
            vec!["uptime", "--next"],
            vec!["uptime", "--next", "--next", "uptime"],
            vec!["ip", "-4", "route", "add", "default"],
            vec!["ip", "netns", "exec", "test", "bash"],
            vec!["ip", "-6", "route", "show", "table", "0"],
            vec!["ip", "-6", "route", "show", "table", "all;id"],
            vec!["journalctl", "-u", "root"],
        ] {
            assert!(validate_diagnostic_request(&request(&args)).is_err(), "{args:?}");
        }
        let r = request(&[
            "uptime", "--next", "uptime", "--next", "uptime",
            "--next", "uptime", "--next", "uptime", "--next", "uptime",
            "--next", "uptime",
        ]);
        assert!(validate_diagnostic_request(&r).is_err());
    }
}
