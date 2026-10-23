use super::*;

impl Drop for SshTunnelGuard {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(super) async fn resolve_deploy_target(
    _state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
) -> Result<ResolvedDeployTarget, String> {
    if !request.mock_provider {
        return Err(
            "legacy deploy target resolution is test-only; real server deployment is owned by the canonical GitHub VM Application Lifecycle"
                .to_owned(),
        );
    }

    let label = request
        .label_prefix
        .clone()
        .unwrap_or_else(|| "mock-edge".to_owned());
    let target_ip = request
        .target_ip
        .clone()
        .unwrap_or_else(|| "203.0.113.10".to_owned());
    let instance = mock_instance(&label, DEFAULT_REGION, DEFAULT_PLAN, &target_ip);
    Ok(ResolvedDeployTarget {
        instance_id: instance.id,
        target_ip: instance.main_ip,
    })
}

pub(super) fn status_for_target_resolution_error(message: String) -> Status {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("transport")
        || normalized.contains("timeout")
        || normalized.contains("http 429")
        || normalized.contains("http 5")
    {
        Status::unavailable(message)
    } else {
        Status::invalid_argument(message)
    }
}

pub(super) fn select_unique_vultr_instance_by_label(
    instances: &[edge_provider_vultr::VultrInstance],
    deployment_label: &str,
) -> Result<Option<edge_provider_vultr::VultrInstance>, String> {
    let mut matches = instances
        .iter()
        .filter(|instance| instance.label == deployment_label);
    let first = matches.next();
    if let Some(second) = matches.next() {
        let first_id = first
            .map(|instance| instance.id.as_str())
            .unwrap_or("<missing>");
        return Err(format!(
            "ambiguous Vultr instance identity for label {deployment_label}: at least {first_id} and {}",
            second.id
        ));
    }
    Ok(first.cloned())
}

pub(super) struct PrepareAgentTransportContext<'a> {
    pub(super) repo_root: &'a Path,
    pub(super) direct_endpoint: &'a str,
    pub(super) request: &'a DeployRequest,
    pub(super) target: &'a ResolvedDeployTarget,
    pub(super) preexisting_agent_target: Option<AgentConnectionTarget>,
    pub(super) preexisting_agent_trust: bool,
    pub(super) operation_id: i64,
    pub(super) state: &'a Arc<Mutex<EdgeState>>,
}

pub(super) async fn prepare_agent_transport(
    context: PrepareAgentTransportContext<'_>,
) -> Result<AgentTransport, String> {
    if !should_bootstrap_via_ssh(
        context.state,
        context.request,
        context.preexisting_agent_trust,
    ) {
        let connection_target = context.preexisting_agent_target.clone().unwrap_or(
            resolve_operation_agent_connection_target(
                context.state,
                context.target,
                context.direct_endpoint,
            )?,
        );
        if should_fallback_to_ssh_bootstrap(context.direct_endpoint, context.state)
            && connect_to_agent_target(&connection_target).await.is_err()
        {
            append_operation_event(
                context.state,
                context.operation_id,
                "direct edge-agent transport is unavailable; falling back to SSH bootstrap",
            )
            .map_err(|status| status.message().to_owned())?;
        } else {
            return Ok(AgentTransport {
                endpoint: connection_target.endpoint,
                tls_paths: connection_target.tls_paths,
                _tunnel: None,
            });
        }
    }

    let config = resolve_bootstrap_access_config(context.repo_root, context.state)?;
    append_operation_event(
        context.state,
        context.operation_id,
        "waiting for SSH reachability",
    )
    .map_err(|status| status.message().to_owned())?;
    accept_ssh_host_key(context.target, &config).await?;
    append_operation_event(
        context.state,
        context.operation_id,
        "strict pre-existing SSH host trust verified",
    )
    .map_err(|status| status.message().to_owned())?;
    wait_for_docker_runtime(context.target, &config).await?;
    append_operation_event(
        context.state,
        context.operation_id,
        "cloud-init and docker are ready",
    )
    .map_err(|status| status.message().to_owned())?;
    ensure_edge_agent_service(context.target, &config).await?;
    append_operation_event(
        context.state,
        context.operation_id,
        "edge-agent service is running",
    )
    .map_err(|status| status.message().to_owned())?;

    let local_port = reserve_local_port()?;
    let tunnel = start_ssh_tunnel(context.target, &config, local_port)?;
    let tunnel_endpoint = format!("http://127.0.0.1:{local_port}");
    if let Some(connection_target) = context
        .preexisting_agent_target
        .as_ref()
        .map(|value| retarget_agent_connection_target(value, tunnel_endpoint.clone()))
        && connect_to_agent_target(&connection_target).await.is_ok()
    {
        return Ok(AgentTransport {
            endpoint: connection_target.endpoint,
            tls_paths: connection_target.tls_paths,
            _tunnel: Some(tunnel),
        });
    }

    Ok(AgentTransport {
        endpoint: tunnel_endpoint,
        tls_paths: None,
        _tunnel: Some(tunnel),
    })
}

pub(super) fn should_fallback_to_ssh_bootstrap(
    direct_endpoint: &str,
    state: &Arc<Mutex<EdgeState>>,
) -> bool {
    env::var_os("EDGE_AGENT_ENDPOINT").is_none()
        && direct_endpoint == DEFAULT_AGENT_ENDPOINT
        && has_configured_secret_ref(state, SECRET_SSH_PRIVATE_KEY_PATH)
}

pub(super) fn resolve_operation_agent_connection_target(
    state: &Arc<Mutex<EdgeState>>,
    target: &ResolvedDeployTarget,
    default_endpoint: &str,
) -> Result<AgentConnectionTarget, String> {
    if env::var_os("EDGE_AGENT_ENDPOINT").is_some() || default_endpoint != DEFAULT_AGENT_ENDPOINT {
        return Ok(AgentConnectionTarget {
            endpoint: default_endpoint.to_owned(),
            tls_paths: None,
        });
    }

    if let Some(connection_target) =
        resolve_targeted_agent_connection_target(state, &target.instance_id, &target.target_ip)?
    {
        return Ok(connection_target);
    }

    Err(format!(
        "no persisted agent trust was found for instance {} at {}; set EDGE_AGENT_ENDPOINT explicitly or bootstrap via SSH",
        target.instance_id, target.target_ip
    ))
}

pub(super) fn should_bootstrap_via_ssh(
    state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    preexisting_agent_trust: bool,
) -> bool {
    let ssh_available = has_configured_secret_ref(state, SECRET_SSH_PRIVATE_KEY_PATH);
    let missing_persisted_trust = !preexisting_agent_trust;

    env::var("EDGE_BOOTSTRAP_VIA_SSH")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        || (request
            .target_ip
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            && ssh_available)
        || (missing_persisted_trust && ssh_available)
}

pub(super) fn resolve_bootstrap_access_config(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
) -> Result<BootstrapAccessConfig, String> {
    let source_private_key_path = resolve_path_secret(
        state,
        SECRET_SSH_PRIVATE_KEY_PATH,
        &default_env_ref("EDGE_SSH_PRIVATE_KEY_PATH"),
    )
    .map_err(|_| {
        "a configured SSH private key path secret is required for SSH bootstrap".to_owned()
    })?;
    if !source_private_key_path.is_file() {
        return Err(format!(
            "SSH private key was not found: {}",
            source_private_key_path.display()
        ));
    }
    let private_key_path = stage_ssh_private_key(repo_root, &source_private_key_path)?;

    let agent_binary_path = env::var("EDGE_AGENT_BINARY_PATH")
        .map(PathBuf::from)
        .ok()
        .or_else(|| default_edge_agent_binary_path(repo_root))
        .ok_or_else(|| {
            "EDGE_AGENT_BINARY_PATH is required or a Linux edge-agent binary must exist under edge-platform/target"
                .to_owned()
        })?;
    if !agent_binary_path.is_file() {
        return Err(format!(
            "edge-agent binary was not found: {}",
            agent_binary_path.display()
        ));
    }
    if cfg!(windows)
        && agent_binary_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err(format!(
            "Windows deploy requires a Linux edge-agent binary, but resolved {}",
            agent_binary_path.display()
        ));
    }

    let known_hosts_path = ensure_known_hosts_file(repo_root)?;
    let ssh_user = env::var("EDGE_SSH_USER").unwrap_or_else(|_| DEFAULT_SSH_USER.to_owned());
    let remote_port = env::var("EDGE_AGENT_REMOTE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_AGENT_REMOTE_PORT);

    Ok(BootstrapAccessConfig {
        private_key_path,
        agent_binary_path,
        ssh_user,
        remote_port,
        known_hosts_path,
    })
}

pub(super) fn backend_ready_for_local_runtime(repo_root: &Path) -> bool {
    if !live_state_artifact_present(repo_root) {
        return false;
    }
    if is_installed_windows_root(repo_root) {
        let Ok(bytes) = fs::read(windows_runtime_state_path(repo_root)) else {
            return false;
        };
        return decode_windows_runtime_state(&bytes).is_ok()
            && default_local_config_path(repo_root).is_file();
    }
    let db_path = controller_state_db_path(repo_root);
    let Ok(state) = EdgeState::open_or_create(&db_path) else {
        return false;
    };
    state
        .get_controller_state()
        .ok()
        .flatten()
        .is_some_and(|value| value.active_instance_id.is_some() || value.active_server_ip.is_some())
}

pub(super) fn live_state_artifact_present(repo_root: &Path) -> bool {
    default_live_state_path(repo_root).is_file()
}

pub(super) fn default_edge_agent_binary_path(repo_root: &Path) -> Option<PathBuf> {
    let target_dir = repo_root.join("edge-platform").join("target");
    let candidates = if cfg!(windows) {
        vec![
            target_dir
                .join("x86_64-unknown-linux-gnu")
                .join("debug")
                .join("edge-agent"),
            target_dir
                .join("x86_64-unknown-linux-musl")
                .join("debug")
                .join("edge-agent"),
            target_dir
                .join("x86_64-unknown-linux-gnu")
                .join("release")
                .join("edge-agent"),
            target_dir
                .join("x86_64-unknown-linux-musl")
                .join("release")
                .join("edge-agent"),
            repo_root
                .join("recovered")
                .join("vm")
                .join("vultr-edge-stack")
                .join("bin")
                .join("edge-agent"),
        ]
    } else {
        vec![
            target_dir.join("debug").join("edge-agent"),
            target_dir.join("release").join("edge-agent"),
        ]
    };
    candidates.into_iter().find(|candidate| candidate.is_file())
}

pub(super) fn stage_ssh_private_key(
    repo_root: &Path,
    source_path: &Path,
) -> Result<PathBuf, String> {
    let runtime_dir = repo_root.join("edge-platform").join(".runtime");
    fs::create_dir_all(&runtime_dir)
        .map_err(|err| format!("failed to create {}: {err}", runtime_dir.display()))?;
    let staged_path = runtime_dir.join(format!("bootstrap-staged-key-{}", unix_timestamp()));
    fs::copy(source_path, &staged_path).map_err(|err| {
        format!(
            "failed to stage SSH private key from {} to {}: {err}",
            source_path.display(),
            staged_path.display()
        )
    })?;

    if cfg!(windows) {
        let username = env::var("USERNAME")
            .map_err(|_| "USERNAME is required to secure staged SSH private key".to_owned())?;
        let staged_str = staged_path.display().to_string();

        let status = Command::new("icacls")
            .args([&staged_str, "/inheritance:r"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| {
                format!(
                    "failed to start icacls for {}: {err}",
                    staged_path.display()
                )
            })?;
        if !status.success() {
            return Err(format!(
                "icacls failed to disable inheritance for staged SSH key {} with status {status}",
                staged_path.display()
            ));
        }

        let grant_target = format!("{username}:R");
        let status = Command::new("icacls")
            .args([&staged_str, "/grant:r", &grant_target])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| {
                format!(
                    "failed to start icacls grant for {}: {err}",
                    staged_path.display()
                )
            })?;
        if !status.success() {
            return Err(format!(
                "icacls failed to grant access to staged SSH key {} with status {status}",
                staged_path.display()
            ));
        }
    }

    Ok(staged_path)
}

pub(super) fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or_default()
}

pub(super) fn ensure_known_hosts_file(repo_root: &Path) -> Result<PathBuf, String> {
    let path = repo_root.join(DEFAULT_SSH_KNOWN_HOSTS_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    if !path.exists() {
        fs::write(&path, b"")
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }
    Ok(path)
}

pub(super) async fn accept_ssh_host_key(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    for _ in 0..60 {
        let result = run_command_capture(
            "ssh",
            &[
                "-i".to_owned(),
                config.private_key_path.display().to_string(),
                "-o".to_owned(),
                "BatchMode=yes".to_owned(),
                "-o".to_owned(),
                "StrictHostKeyChecking=yes".to_owned(),
                "-o".to_owned(),
                format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
                "-o".to_owned(),
                "IdentitiesOnly=yes".to_owned(),
                "-o".to_owned(),
                "ConnectTimeout=5".to_owned(),
                format!("{}@{}", config.ssh_user, target.target_ip),
                "exit".to_owned(),
            ],
        );
        if result.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(5)).await;
    }
    Err(format!(
        "timed out waiting for strictly trusted SSH on {}; legacy bootstrap never enrolls or refreshes host keys",
        target.target_ip
    ))
}

pub(super) async fn wait_for_docker_runtime(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    for _ in 0..90 {
        let result = run_command(
            "ssh",
            &ssh_args(
                config,
                &target.target_ip,
                "if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait >/dev/null 2>&1; fi; command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1",
            ),
        );
        if result.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(5)).await;
    }
    Err(format!(
        "docker runtime was not ready on {} after waiting for cloud-init",
        target.target_ip
    ))
}

pub(super) async fn ensure_edge_agent_service(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    if config
        .agent_binary_path
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err(format!(
            "refusing to upload non-Linux edge-agent binary: {}",
            config.agent_binary_path.display()
        ));
    }

    run_command(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "mkdir -p /opt/vultr-edge-stack/bin",
        ),
    )?;
    run_command(
        "scp",
        &scp_args(
            config,
            &target.target_ip,
            &config.agent_binary_path,
            "/opt/vultr-edge-stack/bin/edge-agent.tmp",
        ),
    )?;
    run_command(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "install -m 0755 /opt/vultr-edge-stack/bin/edge-agent.tmp /opt/vultr-edge-stack/bin/edge-agent && rm -f /opt/vultr-edge-stack/bin/edge-agent.tmp && systemctl daemon-reload && systemctl enable edge-agent.service && systemctl restart edge-agent.service && systemctl is-active --quiet edge-agent.service",
        ),
    )?;
    Ok(())
}

pub(super) fn restart_edge_agent_service(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<(), String> {
    run_command(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "systemctl daemon-reload && systemctl restart edge-agent.service && systemctl is-active --quiet edge-agent.service",
        ),
    )
}

pub(super) fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|err| format!("failed to reserve local agent tunnel port: {err}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| format!("failed to read local tunnel port: {err}"))
}

pub(super) fn start_ssh_tunnel(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
    local_port: u16,
) -> Result<SshTunnelGuard, String> {
    let mut child = Command::new("ssh")
        .args([
            "-i",
            &config.private_key_path.display().to_string(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            &format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-N",
            "-L",
            &format!("{local_port}:127.0.0.1:{}", config.remote_port),
            &format!("{}@{}", config.ssh_user, target.target_ip),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("failed to start SSH tunnel: {err}"))?;

    let probe_addr = SocketAddr::from(([127, 0, 0, 1], local_port));
    for _ in 0..40 {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to read SSH tunnel status: {err}"))?
        {
            return Err(format!("SSH tunnel exited early with status {status}"));
        }
        if TcpStream::connect_timeout(&probe_addr, Duration::from_millis(250)).is_ok() {
            return Ok(SshTunnelGuard { child });
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "timed out waiting for local SSH tunnel on 127.0.0.1:{local_port}"
    ))
}

pub(super) fn ssh_args(
    config: &BootstrapAccessConfig,
    target_ip: &str,
    command: &str,
) -> Vec<String> {
    vec![
        "-i".to_owned(),
        config.private_key_path.display().to_string(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        format!("{}@{}", config.ssh_user, target_ip),
        command.to_owned(),
    ]
}

pub(super) fn scp_args(
    config: &BootstrapAccessConfig,
    target_ip: &str,
    source_path: &Path,
    remote_path: &str,
) -> Vec<String> {
    vec![
        "-i".to_owned(),
        config.private_key_path.display().to_string(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", config.known_hosts_path.display()),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        source_path.display().to_string(),
        format!("{}@{}:{remote_path}", config.ssh_user, target_ip),
    ]
}

pub(super) fn run_command(program: &str, args: &[String]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to start {program}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} exited with status {status} ({})",
            args.join(" ")
        ))
    }
}

pub(super) fn run_command_capture(program: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("failed to start {program}: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if output.status.success() {
        if stdout.is_empty() {
            Ok(stderr)
        } else if stderr.is_empty() {
            Ok(stdout)
        } else {
            Ok(format!("{stdout} | {stderr}"))
        }
    } else {
        Err(format!(
            "{program} exited with status {}: {} {}",
            output.status, stdout, stderr
        ))
    }
}

pub(super) fn collect_edge_agent_diagnostics(
    target: &ResolvedDeployTarget,
    config: &BootstrapAccessConfig,
) -> Result<String, String> {
    let status = run_command_capture(
        "ssh",
        &ssh_args(
            config,
            &target.target_ip,
            "systemctl is-active edge-agent.service && journalctl -u edge-agent.service -n 20 --no-pager",
        ),
    )?;
    Ok(status.replace('\n', " | "))
}

pub(super) async fn apply_bundle_to_agent_target(
    target: &AgentConnectionTarget,
    bundle: &PreparedDeploymentBundle,
) -> Result<edge_shared_types::ApplyBundleResponse, String> {
    let channel = connect_to_agent_target(target)
        .await
        .map_err(|err| format!("failed to connect to edge-agent: {err}"))?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let response = client
        .apply_bundle(Request::new(ApplyBundleRequest {
            stack_files: bundle
                .stack_files
                .iter()
                .map(bundle_file_payload_to_proto)
                .collect(),
            host_files: bundle
                .host_files
                .iter()
                .map(bundle_file_payload_to_proto)
                .collect(),
            deployment_summary: Some(BundleFile {
                relative_path: "deployment-summary.json".to_owned(),
                content: bundle.deployment_summary_json.as_bytes().to_vec(),
                executable: false,
                sensitive: true,
            }),
            agent_env_file: Some(BundleFile {
                relative_path: "edge-agent.env".to_owned(),
                content: bundle.agent_env_content.as_bytes().to_vec(),
                executable: false,
                sensitive: false,
            }),
            prune_existing: true,
            bundle_id: None,
            bundle_digest: None,
        }))
        .await
        .map_err(|err| format!("edge-agent apply bundle RPC failed: {err}"))?;
    Ok(response.into_inner())
}

pub(super) async fn verify_agent_runtime_target(
    target: &AgentConnectionTarget,
    require_readiness: bool,
) -> Result<AgentState, String> {
    let channel = connect_to_agent_target(target)
        .await
        .map_err(|err| format!("failed to connect to edge-agent: {err}"))?;
    let mut client = AgentServiceClient::<Channel>::new(channel);
    let response = client
        .verify_runtime(Request::new(VerifyRuntimeRequest {
            require_readiness,
            mode: BootstrapMode::Unspecified as i32,
        }))
        .await
        .map_err(|err| format!("edge-agent verify runtime RPC failed: {err}"))?;
    Ok(response.into_inner())
}

pub(super) async fn wait_for_agent_runtime_target(
    target: &AgentConnectionTarget,
    require_readiness: bool,
) -> Result<AgentState, String> {
    let mut last_error = None;
    for _ in 0..20 {
        match verify_agent_runtime_target(target, require_readiness).await {
            Ok(state) if !require_readiness || state.ready => return Ok(state),
            Ok(state) => {
                last_error = Some(format!(
                    "edge-agent responded but readiness is false: {}",
                    state.degraded_reasons.join("; ")
                ));
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
    Err(last_error.unwrap_or_else(|| {
        "edge-agent did not become reachable before readiness timeout".to_owned()
    }))
}

pub(super) fn bundle_file_payload_to_proto(file: &edge_bundle::BundleFilePayload) -> BundleFile {
    BundleFile {
        relative_path: file.relative_path.clone(),
        content: file.content.clone(),
        executable: file.executable,
        sensitive: file.sensitive,
    }
}

pub(super) fn bundle_to_proto_summary(
    bundle: &PreparedDeploymentBundle,
    target: &ResolvedDeployTarget,
) -> edge_shared_types::DeploymentSummary {
    edge_shared_types::DeploymentSummary {
        live_state_present: true,
        source_state_path: None,
        deployment_label: Some(bundle.label.clone()),
        instance_id: Some(target.instance_id.clone()),
        server_ip: Some(target.target_ip.clone()),
        tunnel_domain: if bundle.deployment.tunnel.enabled {
            Some(bundle.deployment.tunnel.domain.clone())
        } else {
            None
        },
    }
}

pub(super) fn provider_observation_from_request(
    request: &DeployRequest,
    target_ip: &str,
) -> ProviderObservation {
    let mut warnings = Vec::new();
    if request.mock_provider {
        warnings.push("provider operations were executed in mock mode".to_owned());
    }
    if request.skip_dns {
        warnings.push("DNS cutover was skipped for this deployment".to_owned());
    }
    if target_ip.trim().is_empty() {
        warnings.push("target IP is empty".to_owned());
    }
    ProviderObservation {
        configured: !request.mock_provider,
        compute_provider: "vultr".to_owned(),
        dns_provider: "cloudflare".to_owned(),
        warnings,
    }
}

pub(super) fn should_update_dns(request: &DeployRequest) -> bool {
    !request.skip_dns
        && request
            .dns_record_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

pub(super) async fn apply_dns_update(
    _state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    target_ip: &str,
) -> Result<String, String> {
    if !request.mock_provider {
        return Err("legacy controller DNS mutation is retired; use canonical GitHub-owned application control".to_owned());
    }
    let zone_name = request
        .cloudflare_zone_name
        .clone()
        .unwrap_or_else(|| DEFAULT_CLOUDFLARE_ZONE.to_owned());
    let record_name = request
        .dns_record_name
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_RECORD.to_owned());
    let record = mock_upsert_a_record(&zone_name, &record_name, target_ip);
    Ok(format!(
        "mock DNS updated: {} -> {} ({})",
        record.record_name, record.ip, record.zone_id
    ))
}

pub(super) async fn delete_dns_record(
    _state: &Arc<Mutex<EdgeState>>,
    request: &DestroyRequest,
) -> Result<String, String> {
    if !request.mock_provider {
        return Err("legacy controller DNS deletion is retired; use canonical GitHub-owned application control".to_owned());
    }
    let record_name = request
        .dns_record_name
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_RECORD.to_owned());
    Ok(format!("mock DNS delete requested for {}", record_name))
}

pub(super) fn write_private_state_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set {} mode 600: {err}", path.display()))?;
    }
    Ok(())
}

pub(super) fn persist_bundle_locally(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    bundle: &PreparedDeploymentBundle,
    target: &ResolvedDeployTarget,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    write_private_state_file(&live_state_path, bundle.current_state_json.as_bytes())?;

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    guard
        .clear_destroy_tombstones(Some(&bundle.label), Some(&target.instance_id))
        .map_err(|err| format!("failed to clear destroy tombstones: {err}"))?;
    guard
        .record_deployment(&bundle.label, &target.instance_id, &target.target_ip)
        .map_err(|err| format!("failed to record deployment: {err}"))?;
    let live_state: Value = serde_json::from_str(&bundle.current_state_json)
        .map_err(|err| format!("failed to parse rendered current state JSON: {err}"))?;
    let tunnel_domain = live_state
        .get("tunnel")
        .and_then(Value::as_object)
        .and_then(|tunnel| tunnel.get("domain"))
        .and_then(Value::as_str);
    guard
        .upsert_controller_state(NewControllerState {
            active_deployment_label: Some(&bundle.label),
            active_instance_id: Some(&target.instance_id),
            active_server_ip: Some(&target.target_ip),
            active_tunnel_domain: tunnel_domain,
            active_deployment_state_json: Some(&bundle.current_state_json),
            deploy_phase: DeployPhase::DeploymentPublished,
            app_readiness_phase: AppReadinessPhase::ServerRuntimeReady,
            last_error_code: None,
            last_error_message: None,
        })
        .map_err(|err| format!("failed to update controller state: {err}"))?;
    guard
        .upsert_trust_entry(NewTrustEntry {
            deployment_id: &bundle.label,
            instance_id: &target.instance_id,
            ip: &target.target_ip,
            known_host_line: "",
            domain_name: Some("edge-agent"),
            ca_cert_path: Some(
                bundle
                    .local_trust_material
                    .ca_cert_path
                    .to_string_lossy()
                    .as_ref(),
            ),
            server_cert_path: Some(
                bundle
                    .local_trust_material
                    .server_cert_path
                    .to_string_lossy()
                    .as_ref(),
            ),
            client_cert_path: Some(
                bundle
                    .local_trust_material
                    .client_cert_path
                    .to_string_lossy()
                    .as_ref(),
            ),
            client_key_path: Some(
                bundle
                    .local_trust_material
                    .client_key_path
                    .to_string_lossy()
                    .as_ref(),
            ),
        })
        .map_err(|err| format!("failed to record trust entry: {err}"))?;
    Ok(())
}

pub(super) fn read_live_deployment_summary(
    repo_root: &Path,
) -> Result<edge_shared_types::DeploymentSummary, String> {
    let db_path = repo_root.join(DEFAULT_STATE_DB);
    if db_path.is_file() {
        let state = EdgeState::open_or_create(&db_path)
            .map_err(|err| format!("failed to open {}: {err}", db_path.display()))?;
        if let Some(controller) = state
            .get_controller_state()
            .map_err(|err| format!("failed to read controller state: {err}"))?
        {
            if let Some(raw) = controller.active_deployment_state_json.as_deref() {
                let value: Value = serde_json::from_str(raw).map_err(|err| {
                    format!("failed to parse controller deployment state JSON: {err}")
                })?;
                let live_state_present = controller.active_deployment_label.is_some()
                    || controller.active_instance_id.is_some()
                    || controller.active_server_ip.is_some()
                    || value.get("label").is_some()
                    || value.get("instance_id").is_some()
                    || value.get("ip").is_some();
                if live_state_present {
                    return Ok(edge_shared_types::DeploymentSummary {
                        live_state_present: true,
                        source_state_path: Some(db_path.display().to_string()),
                        deployment_label: controller.active_deployment_label.or_else(|| {
                            value
                                .get("label")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                        instance_id: controller.active_instance_id.or_else(|| {
                            value
                                .get("instance_id")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                        server_ip: controller.active_server_ip.or_else(|| {
                            value
                                .get("ip")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                        tunnel_domain: controller.active_tunnel_domain.or_else(|| {
                            value
                                .get("tunnel")
                                .and_then(Value::as_object)
                                .and_then(|tunnel| tunnel.get("domain"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                    });
                }
            }
            let live_state_present = controller.active_deployment_label.is_some()
                || controller.active_instance_id.is_some()
                || controller.active_server_ip.is_some();
            if live_state_present {
                return Ok(edge_shared_types::DeploymentSummary {
                    live_state_present: true,
                    source_state_path: Some(db_path.display().to_string()),
                    deployment_label: controller.active_deployment_label,
                    instance_id: controller.active_instance_id,
                    server_ip: controller.active_server_ip,
                    tunnel_domain: controller.active_tunnel_domain,
                });
            }
            return Ok(edge_shared_types::DeploymentSummary::missing());
        }
    }

    let path = default_live_state_path(repo_root);
    if !path.is_file() {
        return Ok(edge_shared_types::DeploymentSummary::missing());
    }
    let raw = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(edge_shared_types::DeploymentSummary {
        live_state_present: true,
        source_state_path: Some(path.display().to_string()),
        deployment_label: value
            .get("label")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        instance_id: value
            .get("instance_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        server_ip: value
            .get("ip")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        tunnel_domain: value
            .get("tunnel")
            .and_then(Value::as_object)
            .and_then(|tunnel| tunnel.get("domain"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

pub(super) fn read_live_state_raw(repo_root: &Path) -> Result<Option<String>, String> {
    let path = default_live_state_path(repo_root);
    if !path.is_file() {
        return Ok(None);
    }
    fs::read_to_string(&path)
        .map(Some)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))
}

pub(super) fn parse_tunnel_domain_from_state_json(raw: &str) -> Result<Option<String>, String> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|err| format!("failed to parse deployment state JSON: {err}"))?;
    Ok(value
        .get("tunnel")
        .and_then(Value::as_object)
        .and_then(|tunnel| tunnel.get("domain"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
}

pub(super) fn restore_controller_state_snapshot(
    state: &Arc<Mutex<EdgeState>>,
    snapshot: Option<&edge_state::StoredControllerState>,
) -> Result<(), String> {
    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    match snapshot {
        Some(value) => guard
            .upsert_controller_state(NewControllerState {
                active_deployment_label: value.active_deployment_label.as_deref(),
                active_instance_id: value.active_instance_id.as_deref(),
                active_server_ip: value.active_server_ip.as_deref(),
                active_tunnel_domain: value.active_tunnel_domain.as_deref(),
                active_deployment_state_json: value.active_deployment_state_json.as_deref(),
                deploy_phase: value.deploy_phase,
                app_readiness_phase: value.app_readiness_phase,
                last_error_code: value.last_error_code.as_deref(),
                last_error_message: value.last_error_message.as_deref(),
            })
            .map(|_| ())
            .map_err(|err| format!("failed to restore controller state snapshot: {err}")),
        None => guard
            .clear_controller_state()
            .map_err(|err| format!("failed to clear controller state: {err}")),
    }
}

pub(super) fn clear_live_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    deployment_label: Option<&str>,
    instance_id: &str,
    target_ip: &str,
    operation_id: i64,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    if live_state_path.is_file() {
        fs::remove_file(&live_state_path)
            .map_err(|err| format!("failed to remove {}: {err}", live_state_path.display()))?;
    }

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    let event_message = format!("cleared deployment state for {instance_id}");
    guard
        .mark_authoritative_absent_for_destroy(DestroyAuthorityTransition {
            deployment_label,
            instance_id: Some(instance_id),
            server_ip: Some(target_ip),
            operation_id,
            operation_status: Some("SUCCEEDED"),
            event_message: Some(&event_message),
        })
        .map_err(|err| format!("failed to mark deployment absent: {err}"))?;
    Ok(())
}

pub(super) fn stop_local_runtime_for_destroy(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    operation_id: i64,
    warnings: &mut Vec<String>,
) -> Result<(), Status> {
    let config_path = default_local_config_path(repo_root);
    match stop_runtime_process(&config_path, true) {
        Ok(result) => {
            append_operation_event(
                state,
                operation_id,
                &format!("destroy local runtime stop: {}", result.note),
            )?;
            warnings.extend(
                result
                    .warnings
                    .into_iter()
                    .filter(|warning| warning != "sing-box process is not running"),
            );
            Ok(())
        }
        Err(err) => {
            let warning = format!("destroy local runtime stop failed: {err}");
            append_operation_event(state, operation_id, &warning)?;
            warnings.push(warning);
            Ok(())
        }
    }
}

pub(super) fn is_tombstoned_candidate(
    state: &EdgeState,
    deployment_label: &str,
    instance_id: &str,
) -> Result<bool, String> {
    state
        .find_destroy_tombstone(Some(deployment_label), Some(instance_id))
        .map(|value| value.is_some())
        .map_err(|err| format!("failed to query destroy tombstones: {err}"))
}

pub(super) fn blank_option(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

pub(super) fn rollback_live_deployment_state(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    deployment_label: &str,
    instance_id: &str,
    target_ip: &str,
    previous_live_state: Option<&str>,
    previous_controller_state: Option<&edge_state::StoredControllerState>,
) -> Result<(), String> {
    let live_state_path = default_live_state_path(repo_root);
    let previous_state_json = previous_live_state.or_else(|| {
        previous_controller_state.and_then(|value| value.active_deployment_state_json.as_deref())
    });
    match previous_state_json {
        Some(raw) => write_private_state_file(&live_state_path, raw.as_bytes())?,
        None if live_state_path.is_file() => fs::remove_file(&live_state_path)
            .map_err(|err| format!("failed to remove {}: {err}", live_state_path.display()))?,
        None => {}
    }

    let guard = state
        .lock()
        .map_err(|_| "controller state mutex poisoned".to_owned())?;
    guard
        .clear_deployment_by_label(deployment_label)
        .map_err(|err| format!("failed to clear deployment row: {err}"))?;
    guard
        .clear_trust_entry(deployment_label, instance_id, target_ip)
        .map_err(|err| format!("failed to clear trust row: {err}"))?;
    match previous_controller_state {
        Some(snapshot) => {
            let snapshot_state_json = snapshot
                .active_deployment_state_json
                .as_deref()
                .or(previous_state_json);
            let snapshot_tunnel_domain = snapshot.active_tunnel_domain.clone().or_else(|| {
                snapshot_state_json
                    .and_then(|raw| parse_tunnel_domain_from_state_json(raw).ok())
                    .flatten()
            });
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: snapshot.active_deployment_label.as_deref(),
                    active_instance_id: snapshot.active_instance_id.as_deref(),
                    active_server_ip: snapshot.active_server_ip.as_deref(),
                    active_tunnel_domain: snapshot_tunnel_domain.as_deref(),
                    active_deployment_state_json: snapshot_state_json,
                    deploy_phase: snapshot.deploy_phase,
                    app_readiness_phase: snapshot.app_readiness_phase,
                    last_error_code: snapshot.last_error_code.as_deref(),
                    last_error_message: snapshot.last_error_message.as_deref(),
                })
                .map_err(|err| format!("failed to restore controller state: {err}"))?;
        }
        None => {
            let parsed_value = previous_state_json
                .map(|raw| {
                    serde_json::from_str::<Value>(raw).map_err(|err| {
                        format!("failed to parse rollback current state JSON: {err}")
                    })
                })
                .transpose()?;
            let has_previous_state = previous_state_json.is_some();
            let deployment_label = parsed_value.as_ref().and_then(|value| {
                value
                    .get("label")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let active_instance_id = parsed_value.as_ref().and_then(|value| {
                value
                    .get("instance_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let active_server_ip = parsed_value.as_ref().and_then(|value| {
                value
                    .get("ip")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
            let tunnel_domain = previous_state_json
                .map(parse_tunnel_domain_from_state_json)
                .transpose()?
                .flatten();
            guard
                .upsert_controller_state(NewControllerState {
                    active_deployment_label: deployment_label.as_deref(),
                    active_instance_id: active_instance_id.as_deref(),
                    active_server_ip: active_server_ip.as_deref(),
                    active_tunnel_domain: tunnel_domain.as_deref(),
                    active_deployment_state_json: previous_state_json,
                    deploy_phase: if has_previous_state {
                        DeployPhase::DeploymentPublished
                    } else {
                        DeployPhase::Unspecified
                    },
                    app_readiness_phase: if has_previous_state {
                        AppReadinessPhase::ServerRuntimeReady
                    } else {
                        AppReadinessPhase::DeploymentAbsent
                    },
                    last_error_code: None,
                    last_error_message: None,
                })
                .map_err(|err| format!("failed to restore controller state: {err}"))?;
        }
    }
    Ok(())
}

pub(super) async fn rollback_failed_deploy(
    repo_root: &Path,
    state: &Arc<Mutex<EdgeState>>,
    request: &DeployRequest,
    target: &ResolvedDeployTarget,
    rollback: &DeployRollbackContext,
    operation_id: i64,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let _ = append_operation_event(state, operation_id, "rollback started");

    if rollback.dns_updated {
        let destroy_request = DestroyRequest {
            instance_id: Some(target.instance_id.clone()),
            target_ip: Some(target.target_ip.clone()),
            dns_record_name: request.dns_record_name.clone(),
            cloudflare_zone_name: request.cloudflare_zone_name.clone(),
            mock_provider: request.mock_provider,
            delete_dns: true,
            delete_instance: false,
            lifecycle_reason: Some("deploy_rollback".to_owned()),
        };
        match delete_dns_record(state, &destroy_request).await {
            Ok(note) => {
                let _ = append_operation_event(state, operation_id, &note);
            }
            Err(err) => {
                warnings.push(format!("rollback DNS cleanup failed: {err}"));
            }
        }
    }

    if let Err(err) = rollback_live_deployment_state(
        repo_root,
        state,
        &rollback.deployment_label,
        &target.instance_id,
        &target.target_ip,
        rollback.previous_live_state.as_deref(),
        rollback.previous_controller_state.as_ref(),
    ) {
        warnings.push(format!("rollback state restore failed: {err}"));
    } else {
        let _ = append_operation_event(
            state,
            operation_id,
            "rollback restored local deployment state",
        );
    }

    if warnings.is_empty() {
        let _ = append_operation_event(state, operation_id, "rollback completed");
    } else {
        let _ = append_operation_event(
            state,
            operation_id,
            &format!("rollback completed with warnings: {}", warnings.join("; ")),
        );
    }

    warnings
}

pub(super) fn merge_warnings(mut primary: Vec<String>, mut secondary: Vec<String>) -> Vec<String> {
    primary.append(&mut secondary);
    primary
}
