use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use edge_controller_core::collect_controller_status;
use edge_shared_types::PlatformError;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = io::stderr().write_all(&err.encode_proto());
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), PlatformError> {
    let repo_root = repo_root_from_args()?;
    let report = collect_controller_status(&repo_root)?;
    io::stdout()
        .write_all(&report.encode_proto())
        .map_err(|err| {
            PlatformError::new(
                "stdout_write_failed",
                "controller.output",
                format!("failed to write protobuf response: {err}"),
                true,
                edge_shared_types::ErrorSubsystem::State,
            )
        })?;
    Ok(())
}

fn repo_root_from_args() -> Result<PathBuf, PlatformError> {
    let mut args = env::args().skip(1);

    match (args.next(), args.next(), args.next()) {
        (None, None, None) => env::current_dir().map_err(|err| {
            PlatformError::new(
                "current_dir_unavailable",
                "controller.startup",
                format!("failed to resolve current directory: {err}"),
                false,
                edge_shared_types::ErrorSubsystem::State,
            )
        }),
        (Some(path), None, None) => Ok(PathBuf::from(path)),
        _ => Err(PlatformError::new(
            "invalid_arguments",
            "controller.startup",
            "usage: edge-controller [repo-root]",
            false,
            edge_shared_types::ErrorSubsystem::State,
        )),
    }
}

#[cfg(test)]
mod tests {
    use edge_controller_core::collect_controller_status;

    #[test]
    fn encodes_controller_status_proto() {
        let report =
            collect_controller_status(std::path::Path::new("/home/bose/projects/sing-box"))
                .unwrap();
        let bytes = report.encode_proto();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x0a);
    }
}
