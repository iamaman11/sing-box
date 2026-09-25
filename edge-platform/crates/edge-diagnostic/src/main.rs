use edge_shared_types::{
    WindowsActivationState, decode_windows_activation_state, digest_to_lower_hex,
};
use ring::digest::{Context, SHA256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
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
    verify_state_files(&state)?;

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

fn verify_state_files(state: &WindowsActivationState) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err(format!(
            "unsupported Windows activation schema {}",
            state.schema_version
        ));
    }
    verify_file(
        "controller",
        &state.controller_path,
        &state.controller_sha256,
    )?;
    verify_file("console", &state.console_path, &state.console_sha256)?;
    verify_file("sing-box", &state.sing_box_path, &state.sing_box_sha256)?;
    verify_file(
        "diagnostic",
        &state.diagnostic_path,
        &state.diagnostic_sha256,
    )?;
    Ok(())
}

fn verify_file(label: &str, path: &str, expected: &[u8]) -> Result<(), String> {
    if expected.len() != 32 {
        return Err(format!("{label} digest must contain 32 bytes"));
    }
    let actual = sha256_file(Path::new(path))?;
    if actual != expected {
        return Err(format!(
            "{label} SHA-256 mismatch: expected {}, got {}",
            digest_to_lower_hex(expected),
            digest_to_lower_hex(&actual)
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context.finish().as_ref().to_vec())
}
