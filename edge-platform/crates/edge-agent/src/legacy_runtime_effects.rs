// Cohesive native Rust module; no new runtime owner or workflow.
use super::*;

pub(super) fn start_warp_egress(
    stack_dir: &Path,
    images: &BTreeMap<String,
    String>,
) -> Result<(), String> {
    run_compose(stack_dir, images, &["pull", "warp-egress"])?;
    run_compose(
        stack_dir,
        images,
        &["up", "-d", "--force-recreate", "warp-egress"],
    )
}

pub(super) fn start_line1_gateway(
    stack_dir: &Path,
    images: &BTreeMap<String,
    String>,
) -> Result<(), String> {
    run_compose(
        stack_dir,
        images,
        &["--profile", "tunnel", "pull", "line1-gateway"],
    )?;
    run_compose(
        stack_dir,
        images,
        &[
            "--profile",
            "tunnel",
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            "line1-gateway",
        ],
    )
}

pub(super) fn start_line2_proxy(
    stack_dir: &Path,
    images: &BTreeMap<String,
    String>,
) -> Result<(), String> {
    run_compose(stack_dir, images, &["pull", "line2-proxy"])?;
    run_compose(
        stack_dir,
        images,
        &["up", "-d", "--force-recreate", "--no-deps", "line2-proxy"],
    )
}

pub(super) fn run_compose(
    stack_dir: &Path,
    images: &BTreeMap<String, String>,
    args: &[&str],
) -> Result<(), String> {
    let mut command = Command::new("docker");
    command
        .arg("compose")
        .arg("-f")
        .arg("docker-compose.yml")
        .args(args)
        .current_dir(stack_dir)
        .env(
            EDGE_GATEWAY_IMAGE_KEY,
            images.get(EDGE_GATEWAY_IMAGE_KEY).unwrap(),
        )
        .env(
            EDGE_WARP_EGRESS_IMAGE_KEY,
            images.get(EDGE_WARP_EGRESS_IMAGE_KEY).unwrap(),
        )
        .env(
            EDGE_MESH_IMAGE_KEY,
            images.get(EDGE_MESH_IMAGE_KEY).unwrap(),
        )
        .env_remove("COMPOSE_FILE")
        .env_remove("COMPOSE_PROFILES")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = command
        .status()
        .map_err(|err| format!("fixed docker compose operation could not start: {err}"))?;
    if !status.success() {
        return Err(format!(
            "fixed docker compose operation failed with exit_code={}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

pub(super) fn run_fixed_command(
    stack_dir: &Path,
    program: &str,
    args: &[String],
    environment: &BTreeMap<String, String>,
    operation: &str,
) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(stack_dir)
        .envs(environment)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("{operation} could not start: {err}"))?;
    if !status.success() {
        return Err(format!(
            "{operation} failed with exit_code={}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}
