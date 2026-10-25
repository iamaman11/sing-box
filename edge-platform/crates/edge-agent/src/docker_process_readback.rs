//! Read-only, secret-free /proc process evidence from the existing root Agent.
//! No process command line, name, environment, credentials or raw error output.
use std::{fs, os::unix::fs::MetadataExt};
use edge_shared_types::{FleetVmProcessEvidence, FleetVmProcessSnapshot};

const MAX_PROCESSES: usize = 4096;
const MAX_STAT_BYTES: usize = 8192;

fn parse_process_stat(text: &str) -> Option<(String, u32, &'static str)> {
    let open = text.find('(')?;
    let close = text.rfind(") ")?;
    if close <= open {
        return None;
    }
    let name = text.get(open + 1..close)?;
    let mut fields = text.get(close + 2..)?.split_ascii_whitespace();
    let raw_state = fields.next()?;
    let state = match raw_state {
        "R" => "R", "S" => "S", "D" => "D", "Z" => "Z",
        "T" | "t" => "T", "I" => "I", "X" | "x" => "X",
        "W" => "W", "K" => "K", "P" => "P",
        _ => return None,
    };
    let ppid = fields.next()?.parse::<u32>().ok()?;
    Some((name.to_owned(), ppid, state))
}

pub(super) fn collect_native_process_snapshot() -> FleetVmProcessSnapshot {
    let mut result = FleetVmProcessSnapshot {
        procfs_readable: false,
        ..Default::default()
    };
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return result,
    };
    result.procfs_readable = true;
    let mut ids = Vec::new();
    for item in entries {
        // Do not suppress partial directory errors as evidence of a
        // complete snapshot. Even a successful read_dir can fail mid-iteration.
        let Ok(item) = item else {
            result.procfs_readable = false;
            return FleetVmProcessSnapshot::default();
        };
        if let Ok(pid) = item.file_name().to_string_lossy().parse::<u32>() {
            if pid != 0 { ids.push(pid); }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    result.observed_count = ids.len().min(u32::MAX as usize) as u32;
    result.truncated = ids.len() > MAX_PROCESSES;
    for pid in ids.into_iter().take(MAX_PROCESSES) {
        let path = std::path::PathBuf::from(format!("/proc/{pid}"));
        let mut process = FleetVmProcessEvidence {
            pid, state_code: "?".to_owned(), ..Default::default()
        };
        match fs::symlink_metadata(&path) {
            Err(_) => process.read_error_code = "METADATA_UNAVAILABLE".to_owned(),
            Ok(metadata) => {
                process.real_uid = metadata.uid();
                let bytes = fs::read(path.join("stat"));
                match bytes {
                    Err(_) => process.read_error_code = "STAT_UNAVAILABLE".to_owned(),
                    Ok(bytes) if bytes.len() > MAX_STAT_BYTES => {
                        process.read_error_code = "STAT_INVALID".to_owned()
                    }
                    Ok(bytes) => match std::str::from_utf8(&bytes)
                        .ok().and_then(parse_process_stat)
                    {
                        None => process.read_error_code = "STAT_INVALID".to_owned(),
                        Some((name, parent_pid, state)) => {
                            process.parent_pid = parent_pid;
                            process.state_code = state.to_owned();
                            process.command_name_sha256 = ring::digest::digest(
                                &ring::digest::SHA256, name.as_bytes()
                            ).as_ref().to_vec();
                        }
                    }
                }
            }
        }
        if !process.read_error_code.is_empty() {
            result.read_error_count += 1;
        }
        result.processes.push(process);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stat_with_brackets_and_spaces_is_unambiguous_and_never_copies_name() {
        let (name, ppid, state) = parse_process_stat("123 (custom ) worker) Z 2 3 4").unwrap();
        assert_eq!(name, "custom ) worker");
        assert_eq!(ppid, 2);
        assert_eq!(state, "Z");
        assert!(parse_process_stat("123 (broken").is_none());
    }
    #[test]
    fn root_local_process_snapshot_is_bounded_and_well_formed() {
        let result = collect_native_process_snapshot();
        assert!(result.procfs_readable);
        assert!(!result.processes.is_empty());
        edge_shared_types::host_resources::validate_vm_process_snapshot(&result).unwrap();
        assert!(!result.processes.iter().any(|p| {
            p.command_name_sha256.windows(5).any(|w| w == b"token")
        }));
    }
}
