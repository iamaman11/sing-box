use edge_shared_types::{decode_windows_activation_state, verify_windows_activation_files};
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    if command != "doctor" {
        return Err(usage());
    }
    let state_path = PathBuf::from(args.next().ok_or_else(usage)?);
    if args.next().is_some() {
        return Err(usage());
    }

    let bytes = std::fs::read(&state_path).map_err(|err| {
        format!(
            "failed to read activation state {}: {err}",
            state_path.display()
        )
    })?;
    let state = decode_windows_activation_state(&bytes)?;
    verify_windows_activation_files(&state)?;

    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let controller_running = system.processes().values().any(|process| {
        process
            .name()
            .to_string_lossy()
            .eq_ignore_ascii_case("edge-controller.exe")
    });

    println!("status=PASS");
    println!("release_set_sha256={}", state.release_set_sha256);
    println!("source_revision={}", state.source_revision);
    println!("release_dir={}", state.release_dir);
    println!("controller_path={}", state.controller_path);
    println!("console_path={}", state.console_path);
    println!("sing_box_path={}", state.sing_box_path);
    println!("diagnostic_path={}", state.diagnostic_path);
    println!("controller_running={controller_running}");
    println!("controller_required_for_diagnostics=false");
    println!("exact_release_files=PASS");
    Ok(())
}

fn usage() -> String {
    "usage: edge-diagnostic doctor <current.pb>".to_owned()
}

