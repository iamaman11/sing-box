use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use edge_controller_core::collect_repo_inventory;
use edge_shared_types::{FilePresence, InventoryReport, PlatformError};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{}", render_error_json(&err));
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), PlatformError> {
    let repo_root = repo_root_from_args()?;
    let report = collect_repo_inventory(&repo_root)?;
    println!("{}", render_inventory_json(&report));
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

fn render_inventory_json(report: &InventoryReport) -> String {
    let required_repo_files = render_files(&report.required_repo_files);
    let local_only_files = render_files(&report.local_only_files);
    let blockers = render_string_array(&report.blockers);
    let warnings = render_string_array(&report.warnings);

    format!(
        "{{\"repo_root\":\"{}\",\"rust_workspace_present\":{},\"required_repo_files\":[{}],\"local_only_files\":[{}],\"blockers\":[{}],\"warnings\":[{}]}}",
        escape_json(&report.repo_root),
        report.rust_workspace_present,
        required_repo_files,
        local_only_files,
        blockers,
        warnings
    )
}

fn render_files(files: &[FilePresence]) -> String {
    files
        .iter()
        .map(|file| {
            format!(
                "{{\"path\":\"{}\",\"present\":{},\"category\":\"{}\"}}",
                escape_json(&file.path),
                file.present,
                file.category.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn render_string_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_error_json(err: &PlatformError) -> String {
    format!(
        "{{\"error\":{{\"code\":\"{}\",\"stage\":\"{}\",\"message\":\"{}\",\"retryable\":{},\"subsystem\":\"{}\"}}}}",
        err.code,
        err.stage,
        escape_json(&err.message),
        err.retryable,
        err.subsystem.as_str()
    )
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_json_strings() {
        assert_eq!(escape_json("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }
}
