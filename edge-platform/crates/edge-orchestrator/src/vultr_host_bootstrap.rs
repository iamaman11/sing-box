use edge_provider_vultr::{
    VultrError, VultrInstance, get_instance_typed, get_user_data_typed, halt_instance_typed,
    reboot_instance_typed, start_instance_typed, update_user_data_typed,
};
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

pub const DEFAULT_OPS_USER: &str = "singbox-ops";
pub const CONTROL_TRANSPORT_USER: &str = "edge-control";
const EDGE_AGENT_LOOPBACK: &str = "127.0.0.1:50061";
pub const SCRUBBED_USER_DATA: &str =
    "#cloud-config\n# sing-box bootstrap material scrubbed after strict SSH acceptance\n";

pub struct StrictBootstrapBundle {
    pub cloud_init: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestrictedControlNegativeProof {
    pub shell_rejected: bool,
    pub exec_rejected: bool,
    pub scp_rejected: bool,
    pub sftp_rejected: bool,
    pub pty_rejected: bool,
    pub remote_forward_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSubstrateVersions {
    pub docker_engine_version: String,
    pub containerd_version: String,
    pub compose_version: String,
}

impl HostSubstrateVersions {
    pub fn new(
        docker_engine_version: String,
        containerd_version: String,
        compose_version: String,
    ) -> Result<Self, String> {
        let value = Self {
            docker_engine_version,
            containerd_version,
            compose_version,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        validate_package_version("Docker Engine", &self.docker_engine_version)?;
        validate_package_version("containerd", &self.containerd_version)?;
        validate_package_version("Compose", &self.compose_version)?;
        Ok(())
    }
}

fn validate_package_version(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b':' | b'~' | b'_' | b'-')
        })
    {
        return Err(format!(
            "{label} package version is not a safe exact Debian version"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceAction {
    Start,
    Halt,
    Reboot,
}

impl InstanceAction {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "start" => Ok(Self::Start),
            "halt" => Ok(Self::Halt),
            "reboot" => Ok(Self::Reboot),
            _ => Err(format!(
                "unsupported instance action {value}; expected start, halt, or reboot"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Halt => "halt",
            Self::Reboot => "reboot",
        }
    }

    fn desired_power_status(self) -> Option<&'static str> {
        match self {
            Self::Start => Some("running"),
            Self::Halt => Some("stopped"),
            Self::Reboot => None,
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait OperationalProvider {
    async fn get_instance(&mut self, instance_id: &str) -> Result<VultrInstance, VultrError>;
    async fn start_instance(&mut self, instance_id: &str) -> Result<(), VultrError>;
    async fn halt_instance(&mut self, instance_id: &str) -> Result<(), VultrError>;
    async fn reboot_instance(&mut self, instance_id: &str) -> Result<(), VultrError>;
    async fn get_user_data(&mut self, instance_id: &str) -> Result<String, VultrError>;
    async fn update_user_data(
        &mut self,
        instance_id: &str,
        user_data: &str,
    ) -> Result<(), VultrError>;
}

pub struct VultrOperationalApiProvider {
    api_key: String,
}

impl VultrOperationalApiProvider {
    pub fn new(api_key: String) -> Result<Self, String> {
        if api_key.trim().is_empty() {
            return Err("VULTR_API_KEY must be non-empty".to_owned());
        }
        Ok(Self { api_key })
    }
}

impl OperationalProvider for VultrOperationalApiProvider {
    async fn get_instance(&mut self, instance_id: &str) -> Result<VultrInstance, VultrError> {
        get_instance_typed(&self.api_key, instance_id).await
    }

    async fn start_instance(&mut self, instance_id: &str) -> Result<(), VultrError> {
        start_instance_typed(&self.api_key, instance_id).await
    }

    async fn halt_instance(&mut self, instance_id: &str) -> Result<(), VultrError> {
        halt_instance_typed(&self.api_key, instance_id).await
    }

    async fn reboot_instance(&mut self, instance_id: &str) -> Result<(), VultrError> {
        reboot_instance_typed(&self.api_key, instance_id).await
    }

    async fn get_user_data(&mut self, instance_id: &str) -> Result<String, VultrError> {
        get_user_data_typed(&self.api_key, instance_id)
            .await
            .map(|value| value.data)
    }

    async fn update_user_data(
        &mut self,
        instance_id: &str,
        user_data: &str,
    ) -> Result<(), VultrError> {
        update_user_data_typed(&self.api_key, instance_id, user_data).await
    }
}

pub async fn wait_provider_ready<P: OperationalProvider>(
    provider: &mut P,
    instance_id: &str,
    attempts: usize,
    delay: Duration,
) -> Result<VultrInstance, String> {
    if attempts == 0 {
        return Err("provider readiness attempts must be greater than zero".to_owned());
    }
    let mut last = None;
    for attempt in 0..attempts {
        let current = provider
            .get_instance(instance_id)
            .await
            .map_err(|err| err.to_string())?;
        if current.status == "active"
            && current.power_status == "running"
            && current.server_status == "ok"
            && !current.main_ip.trim().is_empty()
        {
            return Ok(current);
        }
        last = Some(current);
        if attempt + 1 < attempts {
            sleep(delay).await;
        }
    }
    let last = last.ok_or_else(|| "provider returned no instance observation".to_owned())?;
    Err(format!(
        "instance {} did not become provider-ready: status={} power_status={} server_status={} main_ip_present={}",
        last.id,
        last.status,
        last.power_status,
        last.server_status,
        !last.main_ip.trim().is_empty()
    ))
}

pub async fn apply_instance_action<P: OperationalProvider>(
    provider: &mut P,
    instance_id: &str,
    action: InstanceAction,
    attempts: usize,
    delay: Duration,
) -> Result<VultrInstance, String> {
    if attempts == 0 {
        return Err("instance action re-observation attempts must be greater than zero".to_owned());
    }

    let mutation = match action {
        InstanceAction::Start => provider.start_instance(instance_id).await,
        InstanceAction::Halt => provider.halt_instance(instance_id).await,
        InstanceAction::Reboot => provider.reboot_instance(instance_id).await,
    };

    match &mutation {
        Ok(()) => {}
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }

    let desired = action.desired_power_status();
    let mut last = None;
    for attempt in 0..attempts {
        let current = provider
            .get_instance(instance_id)
            .await
            .map_err(|err| err.to_string())?;
        let converged = match (action, desired) {
            (InstanceAction::Reboot, None) => {
                mutation.is_ok()
                    && current.power_status == "running"
                    && current.status == "active"
                    && current.server_status == "ok"
            }
            (_, Some(expected)) => current.power_status == expected,
            _ => false,
        };
        if converged {
            return Ok(current);
        }
        last = Some(current);
        if attempt + 1 < attempts {
            sleep(delay).await;
        }
    }

    if action == InstanceAction::Reboot && mutation.is_err() {
        return Err(format!(
            "reboot outcome for instance {instance_id} is uncertain; running state alone cannot prove that reboot occurred, so mutation was not replayed"
        ));
    }

    let last = last.ok_or_else(|| "provider returned no post-action observation".to_owned())?;
    Err(format!(
        "{} for instance {} did not converge after bounded re-observation: power_status={} status={} server_status={}; mutation was not replayed",
        action.as_str(),
        instance_id,
        last.power_status,
        last.status,
        last.server_status
    ))
}

pub async fn observe_user_data_scrubbed<P: OperationalProvider>(
    provider: &mut P,
    instance_id: &str,
) -> Result<bool, String> {
    let observed = provider
        .get_user_data(instance_id)
        .await
        .map_err(|err| err.to_string())?;
    Ok(observed == SCRUBBED_USER_DATA)
}

pub async fn verify_user_data_scrubbed<P: OperationalProvider>(
    provider: &mut P,
    instance_id: &str,
) -> Result<(), String> {
    let observed = provider
        .get_user_data(instance_id)
        .await
        .map_err(|err| err.to_string())?;
    if observed != SCRUBBED_USER_DATA {
        return Err(format!(
            "instance {instance_id} user-data is not in the canonical scrubbed state"
        ));
    }
    Ok(())
}

pub async fn scrub_user_data<P: OperationalProvider>(
    provider: &mut P,
    instance_id: &str,
    attempts: usize,
    delay: Duration,
) -> Result<bool, String> {
    if attempts == 0 {
        return Err("user-data re-observation attempts must be greater than zero".to_owned());
    }

    let current = provider
        .get_user_data(instance_id)
        .await
        .map_err(|err| err.to_string())?;
    if current == SCRUBBED_USER_DATA {
        return Ok(false);
    }

    let mutation = provider
        .update_user_data(instance_id, SCRUBBED_USER_DATA)
        .await;
    match &mutation {
        Ok(()) => {}
        Err(err) if err.requires_mutation_reobservation() => {}
        Err(err) => return Err(err.to_string()),
    }

    for attempt in 0..attempts {
        let observed = provider
            .get_user_data(instance_id)
            .await
            .map_err(|err| err.to_string())?;
        if observed == SCRUBBED_USER_DATA {
            return Ok(true);
        }
        if attempt + 1 < attempts {
            sleep(delay).await;
        }
    }

    match mutation {
        Ok(()) => Err(format!(
            "user-data PATCH for instance {instance_id} was accepted but scrub state was not observed; PATCH was not replayed"
        )),
        Err(err) => Err(format!(
            "{err}; user-data scrub was not observed for instance {instance_id} and PATCH was not replayed"
        )),
    }
}

pub fn prepare_strict_bootstrap(
    base_cloud_init: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    substrate: &HostSubstrateVersions,
) -> Result<StrictBootstrapBundle, String> {
    validate_hostname(logical_hostname)?;
    if !operator_private_key_path.is_file() {
        return Err(format!(
            "SSH operator private key was not found at {}",
            operator_private_key_path.display()
        ));
    }
    let temp = unique_temp_dir("singbox-host-cert")?;
    let result = (|| {
        let host_key = temp.join("ssh_host_ed25519_key");
        run_checked(
            "ssh-keygen",
            &[
                "-q".to_owned(),
                "-t".to_owned(),
                "ed25519".to_owned(),
                "-N".to_owned(),
                String::new(),
                "-f".to_owned(),
                host_key.display().to_string(),
            ],
            None,
        )?;
        let host_pub = PathBuf::from(format!("{}.pub", host_key.display()));
        run_checked(
            "ssh-keygen",
            &[
                "-q".to_owned(),
                "-s".to_owned(),
                operator_private_key_path.display().to_string(),
                "-I".to_owned(),
                logical_hostname.to_owned(),
                "-z".to_owned(),
                "1".to_owned(),
                "-h".to_owned(),
                "-n".to_owned(),
                logical_hostname.to_owned(),
                "-V".to_owned(),
                "-5m:+8760h".to_owned(),
                host_pub.display().to_string(),
            ],
            None,
        )?;

        let host_cert = PathBuf::from(format!("{}-cert.pub", host_key.display()));
        let private_key = fs::read_to_string(&host_key)
            .map_err(|err| format!("failed to read generated host private key: {err}"))?;
        let public_key = fs::read_to_string(&host_pub)
            .map_err(|err| format!("failed to read generated host public key: {err}"))?;
        let certificate = fs::read_to_string(&host_cert)
            .map_err(|err| format!("failed to read generated host certificate: {err}"))?;

        let cloud_init = render_strict_cloud_init(
            base_cloud_init,
            logical_hostname,
            canonical_operator_public_key,
            &private_key,
            &public_key,
            &certificate,
            substrate,
        )?;
        Ok(StrictBootstrapBundle { cloud_init })
    })();
    let _ = fs::remove_dir_all(&temp);
    result
}

fn render_strict_cloud_init(
    base_cloud_init: &str,
    logical_hostname: &str,
    canonical_operator_public_key: &str,
    host_private_key: &str,
    host_public_key: &str,
    host_certificate: &str,
    substrate: &HostSubstrateVersions,
) -> Result<String, String> {
    let base_cloud_init = render_host_substrate_versions(base_cloud_init, substrate)?;
    if !base_cloud_init.starts_with("#cloud-config\n") {
        return Err("bootstrap template must start with #cloud-config".to_owned());
    }
    let write_anchor = "write_files:\n";
    let run_anchor = "runcmd:\n";
    if !base_cloud_init.contains(write_anchor) || !base_cloud_init.contains(run_anchor) {
        return Err("bootstrap template must contain write_files and runcmd sections".to_owned());
    }

    let canonical_key = canonical_operator_public_key.trim();
    if canonical_key.contains('\n') || canonical_key.contains('\r') {
        return Err("canonical SSH public key must be a single line".to_owned());
    }
    let control_key = restricted_control_authorized_key(canonical_key)?;

    let header = format!(
        "#cloud-config\nhostname: {logical_hostname}\nmanage_etc_hosts: true\nusers:\n  - name: {DEFAULT_OPS_USER}\n    groups: [sudo]\n    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]\n    shell: /bin/bash\n    lock_passwd: true\n    ssh_authorized_keys:\n      - {canonical_key}\n  - name: {CONTROL_TRANSPORT_USER}\n    shell: /usr/sbin/nologin\n    lock_passwd: true\n    ssh_authorized_keys:\n      - '{control_key}'\nssh_pwauth: false\ndisable_root: true\nssh_deletekeys: false\nssh_genkeytypes: []\n"
    );
    let mut rendered = base_cloud_init.replacen("#cloud-config\n", &header, 1);

    let files = format!(
        "write_files:\n{}{}{}{}{}",
        cloud_init_file("/etc/ssh/ssh_host_ed25519_key", "0600", host_private_key),
        cloud_init_file("/etc/ssh/ssh_host_ed25519_key.pub", "0644", host_public_key),
        cloud_init_file(
            "/etc/ssh/ssh_host_ed25519_key-cert.pub",
            "0644",
            host_certificate
        ),
        cloud_init_file(
            "/etc/ssh/sshd_config.d/99-singbox-host-cert.conf",
            "0644",
            "HostKey /etc/ssh/ssh_host_ed25519_key\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\nPasswordAuthentication no\nPermitRootLogin no\n"
        ),
        cloud_init_file(
            "/etc/ssh/sshd_config.d/99-z-singbox-control.conf",
            "0644",
            restricted_control_sshd_config()
        )
    );
    rendered = rendered.replacen(write_anchor, &files, 1);
    rendered = rendered.replacen(
        run_anchor,
        "runcmd:\n  - [bash, -lc, \"sshd -t && systemctl restart ssh\"]\n",
        1,
    );
    Ok(rendered)
}

fn render_host_substrate_versions(
    template: &str,
    substrate: &HostSubstrateVersions,
) -> Result<String, String> {
    substrate.validate()?;
    let replacements = [
        (
            "@@DOCKER_ENGINE_VERSION@@",
            substrate.docker_engine_version.as_str(),
        ),
        (
            "@@CONTAINERD_VERSION@@",
            substrate.containerd_version.as_str(),
        ),
        ("@@COMPOSE_VERSION@@", substrate.compose_version.as_str()),
    ];
    let mut rendered = template.to_owned();
    for (marker, value) in replacements {
        if rendered.matches(marker).count() != 1 {
            return Err(format!(
                "bootstrap template must contain exactly one {marker} marker"
            ));
        }
        rendered = rendered.replacen(marker, value, 1);
    }
    Ok(rendered)
}

fn substrate_acceptance_command(substrate: &HostSubstrateVersions) -> Result<String, String> {
    substrate.validate()?;
    Ok(format!(
        "failures=''; \
         record_failure() {{ if test -n \"$failures\"; then failures=\"$failures,$1\"; else failures=\"$1\"; fi; }}; \
         test \"$(cat /var/lib/singbox-lifecycle/host-bootstrap 2>/dev/null)\" = exact-substrate-ready || record_failure host-bootstrap-marker; \
         test \"$(dpkg-query -W -f='${{Version}}' docker-ce 2>/dev/null)\" = '{}' || record_failure docker-ce-version; \
         test \"$(dpkg-query -W -f='${{Version}}' docker-ce-cli 2>/dev/null)\" = '{}' || record_failure docker-cli-version; \
         test \"$(dpkg-query -W -f='${{Version}}' containerd.io 2>/dev/null)\" = '{}' || record_failure containerd-version; \
         test \"$(dpkg-query -W -f='${{Version}}' docker-compose-plugin 2>/dev/null)\" = '{}' || record_failure compose-version; \
         sudo systemctl is-active --quiet docker || record_failure docker-service; \
         sudo docker version >/dev/null 2>&1 || record_failure docker-api; \
         sudo docker compose version >/dev/null 2>&1 || record_failure compose-cli; \
         sudo sshd -t >/dev/null 2>&1 || record_failure sshd-config; \
         if test -n \"$failures\"; then printf '%s\\n' \"EDGE_SUBSTRATE_FAIL:$failures\" >&2; exit 42; fi",
        substrate.docker_engine_version,
        substrate.docker_engine_version,
        substrate.containerd_version,
        substrate.compose_version,
    ))
}

fn substrate_forensic_command() -> &'static str {
    "marker=$(cat /var/lib/singbox-lifecycle/host-bootstrap 2>/dev/null || printf missing); \
     marker_stat=$(stat -c '%U:%G:%a:%s:%Y' /var/lib/singbox-lifecycle/host-bootstrap 2>/dev/null || printf missing); \
     env_stat=$(stat -c '%U:%G:%a:%s:%Y' /var/lib/singbox-lifecycle/host-substrate.env 2>/dev/null || printf missing); \
     docker_ce=$(dpkg-query -W -f='${Version}' docker-ce 2>/dev/null || printf missing); \
     docker_cli=$(dpkg-query -W -f='${Version}' docker-ce-cli 2>/dev/null || printf missing); \
     containerd=$(dpkg-query -W -f='${Version}' containerd.io 2>/dev/null || printf missing); \
     compose=$(dpkg-query -W -f='${Version}' docker-compose-plugin 2>/dev/null || printf missing); \
     docker_active=$(sudo systemctl is-active docker 2>/dev/null || printf unavailable); \
     docker_enabled=$(sudo systemctl is-enabled docker 2>/dev/null || printf unavailable); \
     root_mount=$(findmnt -n -o SOURCE,FSTYPE --target / 2>/dev/null | tr ' ' ':' || printf unavailable); \
     var_mount=$(findmnt -n -o SOURCE,FSTYPE --target /var 2>/dev/null | tr ' ' ':' || printf unavailable); \
     boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unavailable); \
     uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || printf unavailable); \
     cloud_instance_id=$(cat /var/lib/cloud/data/instance-id 2>/dev/null || printf unavailable); \
     cloud_status=$(cloud-init status 2>/dev/null | tr ' ' '_' || printf unavailable); \
     opt_stat=$(stat -c '%U:%G:%a:%s:%Y' /opt/vultr-edge-stack 2>/dev/null || printf missing); \
     printf '%s\\n' \"EDGE_SUBSTRATE_FORENSIC:boot_id=$boot_id;uptime=$uptime;marker=$marker;marker_stat=$marker_stat;env_stat=$env_stat;docker_ce=$docker_ce;docker_cli=$docker_cli;containerd=$containerd;compose=$compose;docker_active=$docker_active;docker_enabled=$docker_enabled;root_mount=$root_mount;var_mount=$var_mount;cloud_instance_id=$cloud_instance_id;cloud_status=$cloud_status;opt_stat=$opt_stat\""
}

fn bounded_forensic_evidence(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("EDGE_SUBSTRATE_FORENSIC:"))
        .unwrap_or("unavailable")
        .chars()
        .take(1200)
        .collect()
}

fn capture_substrate_forensics(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    known_hosts_path: &Path,
) -> String {
    let args = strict_ssh_args(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        known_hosts_path,
        substrate_forensic_command(),
    );
    match Command::new("ssh")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => bounded_forensic_evidence(&output.stdout),
        _ => "unavailable".to_owned(),
    }
}

fn cloud_init_file(path: &str, mode: &str, content: &str) -> String {
    let indented = content
        .trim_end_matches('\n')
        .lines()
        .map(|line| format!("      {line}\n"))
        .collect::<String>();
    format!(
        "  - path: {path}\n    owner: root:root\n    permissions: '{mode}'\n    content: |\n{indented}"
    )
}

pub fn verify_operator_key_matches(
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<(), String> {
    if !operator_private_key_path.is_file() {
        return Err(format!(
            "SSH operator private key was not found at {}",
            operator_private_key_path.display()
        ));
    }
    let derived = run_capture(
        "ssh-keygen",
        &[
            "-y".to_owned(),
            "-f".to_owned(),
            operator_private_key_path.display().to_string(),
        ],
    )?;
    let derived = String::from_utf8(derived)
        .map_err(|_| "derived SSH public key was not UTF-8".to_owned())?;
    let expected = public_key_material(canonical_operator_public_key)?;
    let actual = public_key_material(&derived)?;
    if actual != expected {
        return Err("SSH operator private key does not match canonical public key".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrictSshFailureClass {
    Transport,
    HostTrust,
    Authentication,
    RemoteAcceptance,
    OtherSsh,
}

impl StrictSshFailureClass {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Transport => "TRANSPORT",
            Self::HostTrust => "HOST_TRUST",
            Self::Authentication => "AUTHENTICATION",
            Self::RemoteAcceptance => "REMOTE_ACCEPTANCE",
            Self::OtherSsh => "OTHER_SSH",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StrictSshAttemptEvidence {
    class: StrictSshFailureClass,
    exit_code: Option<i32>,
    detail: String,
}

#[derive(Debug, Default)]
struct StrictSshFailureCounts {
    transport: usize,
    host_trust: usize,
    authentication: usize,
    remote_acceptance: usize,
    other_ssh: usize,
}

impl StrictSshFailureCounts {
    fn record(&mut self, class: StrictSshFailureClass) {
        match class {
            StrictSshFailureClass::Transport => self.transport += 1,
            StrictSshFailureClass::HostTrust => self.host_trust += 1,
            StrictSshFailureClass::Authentication => self.authentication += 1,
            StrictSshFailureClass::RemoteAcceptance => self.remote_acceptance += 1,
            StrictSshFailureClass::OtherSsh => self.other_ssh += 1,
        }
    }

    fn summary(&self) -> String {
        format!(
            "transport={} host_trust={} authentication={} remote_acceptance={} other_ssh={}",
            self.transport,
            self.host_trust,
            self.authentication,
            self.remote_acceptance,
            self.other_ssh
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrictSshAcceptanceObservation {
    pub passed: bool,
    pub attempts: usize,
    pub counts: String,
    pub last_class: Option<StrictSshFailureClass>,
    pub last_exit_code: Option<i32>,
    pub last_detail: String,
    pub forensic: String,
    pub transport_stage: String,
}

impl StrictSshAcceptanceObservation {
    pub(crate) fn evidence(&self) -> String {
        if self.passed {
            return "PASS".to_owned();
        }
        format!(
            "attempts={} counts=[{}] last_class={} last_exit_code={} last_detail={} forensic={} transport_stage={}",
            self.attempts,
            self.counts,
            self.last_class
                .map(StrictSshFailureClass::label)
                .unwrap_or("NONE"),
            self.last_exit_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            self.last_detail,
            self.forensic,
            self.transport_stage,
        )
    }
}

fn bounded_ssh_evidence(stderr: &[u8]) -> String {
    let mut parts = String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let lowered = line.to_ascii_lowercase();
            if [
                "password",
                "private_key",
                "private key",
                "authorization",
                "token=",
            ]
            .iter()
            .any(|marker| lowered.contains(marker))
            {
                "[redacted sensitive SSH evidence]".to_owned()
            } else {
                line.chars().take(240).collect::<String>()
            }
        })
        .take(4)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "no-stderr".to_owned()
    } else {
        parts.truncate(4);
        parts.join(" | ")
    }
}

fn classify_strict_ssh_failure(exit_code: Option<i32>, stderr: &[u8]) -> StrictSshAttemptEvidence {
    let detail = bounded_ssh_evidence(stderr);
    let lowered = detail.to_ascii_lowercase();
    let class = if lowered.contains("edge_substrate_fail:") {
        StrictSshFailureClass::RemoteAcceptance
    } else if [
        "host key verification failed",
        "remote host identification has changed",
        "certificate invalid",
        "host certificate",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        StrictSshFailureClass::HostTrust
    } else if [
        "permission denied",
        "authentication failed",
        "too many authentication failures",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        StrictSshFailureClass::Authentication
    } else if [
        "connection refused",
        "connection timed out",
        "operation timed out",
        "no route to host",
        "network is unreachable",
        "connection reset",
        "connection closed",
        "kex_exchange_identification",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        StrictSshFailureClass::Transport
    } else if exit_code.is_some_and(|code| code != 255) {
        StrictSshFailureClass::RemoteAcceptance
    } else {
        StrictSshFailureClass::OtherSsh
    };
    StrictSshAttemptEvidence {
        class,
        exit_code,
        detail,
    }
}

fn run_strict_ssh_attempt(args: &[String]) -> Result<(), StrictSshAttemptEvidence> {
    let output = Command::new("ssh")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| StrictSshAttemptEvidence {
            class: StrictSshFailureClass::OtherSsh,
            exit_code: None,
            detail: format!("failed-to-start-ssh:{err}"),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(classify_strict_ssh_failure(
            output.status.code(),
            &output.stderr,
        ))
    }
}

fn transport_stage_evidence(stderr: &[u8], success: bool) -> String {
    let lowered = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let tcp_connected =
        lowered.contains("connection established") || lowered.contains("connected to ") || success;
    let remote_banner = lowered.contains("remote protocol version") || success;
    let kex_reached = lowered.contains("ssh2_msg_kexinit")
        || lowered.contains("kex: algorithm:")
        || lowered.contains("server host key:")
        || success;
    let host_trust_reached = lowered.contains("host '")
        || lowered.contains("host key verification")
        || lowered.contains("server host key:")
        || success;
    let authentication_reached = lowered.contains("authentications that can continue")
        || lowered.contains("authenticated to ")
        || success;
    let remote_command_reached = lowered.contains("sending command") || success;
    format!(
        "tcp_connected={tcp_connected};remote_banner={remote_banner};kex_reached={kex_reached};host_trust_reached={host_trust_reached};authentication_reached={authentication_reached};remote_command_reached={remote_command_reached}"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransportStageObservation {
    evidence: String,
    passed: bool,
}

fn capture_transport_stage(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    known_hosts_path: &Path,
) -> TransportStageObservation {
    let mut args = strict_ssh_args(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        known_hosts_path,
        "true",
    );
    args.insert(0, "-vvv".to_owned());
    match Command::new("ssh")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => TransportStageObservation {
            evidence: transport_stage_evidence(&output.stderr, output.status.success()),
            passed: output.status.success(),
        },
        Err(_) => TransportStageObservation {
            evidence: "diagnostic_unavailable=true".to_owned(),
            passed: false,
        },
    }
}

fn should_retry_acceptance_after_transport_probe(
    last_class: StrictSshFailureClass,
    transport_probe_passed: bool,
) -> bool {
    last_class == StrictSshFailureClass::Transport && transport_probe_passed
}

pub(crate) async fn observe_strict_ssh_acceptance(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    substrate: &HostSubstrateVersions,
    attempts: usize,
    delay: Duration,
) -> Result<StrictSshAcceptanceObservation, String> {
    if attempts == 0 {
        return Err("strict SSH attempts must be greater than zero".to_owned());
    }
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let substrate_check = substrate_acceptance_command(substrate)?;
    let args = strict_ssh_args(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        &trust,
        &substrate_check,
    );
    let mut counts = StrictSshFailureCounts::default();
    let mut last = None;
    let mut forensic = None;
    for attempt in 0..attempts {
        match run_strict_ssh_attempt(&args) {
            Ok(()) => {
                let _ = fs::remove_file(&trust);
                return Ok(StrictSshAcceptanceObservation {
                    passed: true,
                    attempts: attempt + 1,
                    counts: counts.summary(),
                    last_class: None,
                    last_exit_code: Some(0),
                    last_detail: "PASS".to_owned(),
                    forensic: "not-required".to_owned(),
                    transport_stage: "not-required".to_owned(),
                });
            }
            Err(evidence) => {
                if evidence.class == StrictSshFailureClass::RemoteAcceptance
                    && (forensic.is_none() || attempt + 1 == attempts)
                {
                    forensic = Some(capture_substrate_forensics(
                        target_ip,
                        logical_hostname,
                        operator_private_key_path,
                        &trust,
                    ));
                }
                counts.record(evidence.class);
                last = Some(evidence);
            }
        }
        if attempt + 1 < attempts {
            sleep(delay).await;
        }
    }
    let mut last = last.unwrap_or(StrictSshAttemptEvidence {
        class: StrictSshFailureClass::OtherSsh,
        exit_code: None,
        detail: "no SSH attempt was made".to_owned(),
    });
    let mut total_attempts = attempts;
    let mut transport_stage = "not-required".to_owned();

    if last.class == StrictSshFailureClass::Transport {
        let stage = capture_transport_stage(
            target_ip,
            logical_hostname,
            operator_private_key_path,
            &trust,
        );
        transport_stage = stage.evidence;

        if should_retry_acceptance_after_transport_probe(last.class, stage.passed) {
            total_attempts += 1;
            match run_strict_ssh_attempt(&args) {
                Ok(()) => {
                    let _ = fs::remove_file(&trust);
                    return Ok(StrictSshAcceptanceObservation {
                        passed: true,
                        attempts: total_attempts,
                        counts: counts.summary(),
                        last_class: None,
                        last_exit_code: Some(0),
                        last_detail: "PASS_AFTER_TRANSPORT_READINESS".to_owned(),
                        forensic: forensic.unwrap_or_else(|| "not-collected".to_owned()),
                        transport_stage,
                    });
                }
                Err(evidence) => {
                    if evidence.class == StrictSshFailureClass::RemoteAcceptance {
                        forensic = Some(capture_substrate_forensics(
                            target_ip,
                            logical_hostname,
                            operator_private_key_path,
                            &trust,
                        ));
                    }
                    counts.record(evidence.class);
                    last = evidence;
                }
            }
        }
    }

    let observation = StrictSshAcceptanceObservation {
        passed: false,
        attempts: total_attempts,
        counts: counts.summary(),
        last_class: Some(last.class),
        last_exit_code: last.exit_code,
        last_detail: last.detail,
        forensic: forensic.unwrap_or_else(|| "not-collected".to_owned()),
        transport_stage,
    };
    let _ = fs::remove_file(&trust);
    Ok(observation)
}

pub async fn strict_ssh_accept(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    substrate: &HostSubstrateVersions,
    attempts: usize,
    delay: Duration,
) -> Result<(), String> {
    let observed = observe_strict_ssh_acceptance(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
        substrate,
        attempts,
        delay,
    )
    .await?;
    if observed.passed {
        Ok(())
    } else {
        Err(format!(
            "strict SSH acceptance failed for {logical_hostname} at {target_ip}: {}",
            observed.evidence()
        ))
    }
}

pub fn ensure_host_certificate_rotated(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    minimum_serial: u64,
) -> Result<bool, String> {
    if minimum_serial == 0 {
        return Err("minimum host certificate serial must be greater than zero".to_owned());
    }
    let current = read_host_certificate_serial(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
    )?;
    if current >= minimum_serial {
        return Ok(false);
    }

    let mutation = rotate_host_certificate(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
        minimum_serial,
    );
    let reobserved = read_host_certificate_serial(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
    );
    resolve_host_certificate_rotation_outcome(minimum_serial, mutation, reobserved)
}

fn resolve_host_certificate_rotation_outcome(
    minimum_serial: u64,
    mutation: Result<(), String>,
    reobserved: Result<u64, String>,
) -> Result<bool, String> {
    match (mutation, reobserved) {
        (_, Ok(serial)) if serial >= minimum_serial => Ok(true),
        (Ok(()), Ok(serial)) => Err(format!(
            "host certificate rotation was accepted but serial remained below required minimum {minimum_serial}: observed {serial}; mutation was not replayed"
        )),
        (Err(mutation_error), Ok(serial)) => Err(format!(
            "{mutation_error}; host certificate serial re-observed at {serial}, below required minimum {minimum_serial}; mutation was not replayed"
        )),
        (Ok(()), Err(observe_error)) => Err(format!(
            "host certificate rotation was accepted but outcome is uncertain because re-observation failed: {observe_error}; mutation was not replayed"
        )),
        (Err(mutation_error), Err(observe_error)) => Err(format!(
            "{mutation_error}; host certificate rotation outcome is uncertain because re-observation failed: {observe_error}; mutation was not replayed"
        )),
    }
}

fn parse_served_host_certificate_serial(stderr: &[u8]) -> Result<u64, String> {
    let text = String::from_utf8_lossy(stderr);
    for line in text.lines().map(str::trim) {
        if !line.contains("Server host certificate:") {
            continue;
        }
        let (_, suffix) = line
            .split_once(", serial ")
            .ok_or_else(|| "served host certificate evidence did not contain serial".to_owned())?;
        let serial = suffix
            .split_whitespace()
            .next()
            .ok_or_else(|| "served host certificate serial was empty".to_owned())?;
        return serial
            .parse::<u64>()
            .map_err(|err| format!("invalid served host certificate serial: {err}"));
    }
    Err("strict SSH evidence did not contain served host certificate metadata".to_owned())
}

pub(crate) fn read_host_certificate_serial(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<u64, String> {
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let mut args = strict_ssh_args(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        &trust,
        "true",
    );
    args.insert(0, "-v".to_owned());
    let result = (|| {
        let output = Command::new("ssh")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("failed to start strict SSH certificate observation: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "strict SSH certificate observation failed: {}",
                bounded_ssh_evidence(&output.stderr)
            ));
        }
        parse_served_host_certificate_serial(&output.stderr)
    })();
    let _ = fs::remove_file(&trust);
    result
}

pub fn rotate_host_certificate(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    serial: u64,
) -> Result<(), String> {
    if serial == 0 {
        return Err("host certificate serial must be greater than zero".to_owned());
    }
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let temp = unique_temp_dir("singbox-host-rotation")?;
    let result = (|| {
        let remote_pub = temp.join("remote-host.pub");
        let output = run_capture(
            "ssh",
            &strict_ssh_args(
                target_ip,
                logical_hostname,
                operator_private_key_path,
                &trust,
                "sudo cat /etc/ssh/ssh_host_ed25519_key.pub",
            ),
        )?;
        fs::write(&remote_pub, output)
            .map_err(|err| format!("failed to stage remote host public key: {err}"))?;

        run_checked(
            "ssh-keygen",
            &[
                "-q".to_owned(),
                "-s".to_owned(),
                operator_private_key_path.display().to_string(),
                "-I".to_owned(),
                format!("{logical_hostname}-rotated"),
                "-z".to_owned(),
                serial.to_string(),
                "-h".to_owned(),
                "-n".to_owned(),
                logical_hostname.to_owned(),
                "-V".to_owned(),
                "-5m:+8760h".to_owned(),
                remote_pub.display().to_string(),
            ],
            None,
        )?;
        let certificate_path = remote_pub.with_file_name("remote-host-cert.pub");
        let certificate = fs::read(&certificate_path)
            .map_err(|err| format!("failed to read rotated host certificate: {err}"))?;

        run_checked(
            "ssh",
            &strict_ssh_args(
                target_ip,
                logical_hostname,
                operator_private_key_path,
                &trust,
                "sudo tee /etc/ssh/ssh_host_ed25519_key-cert.pub >/dev/null && sudo chmod 0644 /etc/ssh/ssh_host_ed25519_key-cert.pub && sudo sshd -t && sudo systemctl reload ssh",
            ),
            Some(&certificate),
        )?;

        run_checked(
            "ssh",
            &strict_ssh_args(
                target_ip,
                logical_hostname,
                operator_private_key_path,
                &trust,
                "sudo ssh-keygen -L -f /etc/ssh/ssh_host_ed25519_key-cert.pub >/dev/null",
            ),
            None,
        )
    })();
    let _ = fs::remove_file(&trust);
    let _ = fs::remove_dir_all(&temp);
    result
}

pub(crate) struct StrictSshTunnelGuard {
    child: Child,
    known_hosts_path: PathBuf,
}

impl Drop for StrictSshTunnelGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.known_hosts_path);
    }
}

pub(crate) fn strict_ssh_run(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    remote_command: &str,
) -> Result<(), String> {
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let result = run_checked(
        "ssh",
        &strict_ssh_args(
            target_ip,
            logical_hostname,
            operator_private_key_path,
            &trust,
            remote_command,
        ),
        None,
    );
    let _ = fs::remove_file(&trust);
    result
}

pub(crate) fn strict_ssh_capture(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    remote_command: &str,
) -> Result<String, String> {
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let result = (|| {
        let output = run_capture(
            "ssh",
            &strict_ssh_args(
                target_ip,
                logical_hostname,
                operator_private_key_path,
                &trust,
                remote_command,
            ),
        )?;
        String::from_utf8(output).map_err(|_| "strict SSH output was not UTF-8".to_owned())
    })();
    let _ = fs::remove_file(&trust);
    result.map(|value| value.trim().to_owned())
}

pub(crate) fn strict_scp_upload(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    source_path: &Path,
    remote_path: &str,
) -> Result<(), String> {
    if !source_path.is_file() {
        return Err(format!(
            "strict SCP source file was not found: {}",
            source_path.display()
        ));
    }
    if !remote_path.starts_with("/tmp/singbox-")
        || remote_path.contains(char::is_whitespace)
        || remote_path.contains("..")
    {
        return Err(format!(
            "strict SCP target must be a fixed /tmp/singbox-* staging path: {remote_path}"
        ));
    }

    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let args = vec![
        "-i".to_owned(),
        operator_private_key_path.display().to_string(),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", trust.display()),
        "-o".to_owned(),
        format!("HostKeyAlias={logical_hostname}"),
        source_path.display().to_string(),
        format!("{DEFAULT_OPS_USER}@{target_ip}:{remote_path}"),
    ];
    let result = run_checked("scp", &args, None);
    let _ = fs::remove_file(&trust);
    result
}

pub(crate) fn start_strict_agent_tunnel(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<(u16, StrictSshTunnelGuard), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|err| format!("failed to reserve local edge-agent tunnel port: {err}"))?;
    let local_port = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect local edge-agent tunnel port: {err}"))?
        .port();
    drop(listener);

    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let tunnel_args = restricted_agent_tunnel_args(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        &trust,
        local_port,
    );
    let mut child = Command::new("ssh")
        .args(&tunnel_args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            let _ = fs::remove_file(&trust);
            format!("failed to start strict edge-agent SSH tunnel: {err}")
        })?;

    let probe = SocketAddr::from(([127, 0, 0, 1], local_port));
    for _ in 0..40 {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to read strict SSH tunnel status: {err}"))?
        {
            let _ = fs::remove_file(&trust);
            return Err(format!(
                "strict edge-agent SSH tunnel exited early with status {status}"
            ));
        }
        if TcpStream::connect_timeout(&probe, Duration::from_millis(250)).is_ok() {
            return Ok((
                local_port,
                StrictSshTunnelGuard {
                    child,
                    known_hosts_path: trust,
                },
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&trust);
    Err(format!(
        "timed out waiting for strict edge-agent SSH tunnel on 127.0.0.1:{local_port}"
    ))
}

fn restricted_control_authorized_key(
    canonical_operator_public_key: &str,
) -> Result<String, String> {
    let material = public_key_material(canonical_operator_public_key)?;
    Ok(format!(
        "restrict,port-forwarding,permitopen=\"{EDGE_AGENT_LOOPBACK}\" {material}"
    ))
}

fn restricted_control_sshd_config() -> &'static str {
    "Match User edge-control\n\
    AuthenticationMethods publickey\n\
    PubkeyAuthentication yes\n\
    PasswordAuthentication no\n\
    KbdInteractiveAuthentication no\n\
    AllowTcpForwarding local\n\
    AllowStreamLocalForwarding no\n\
    PermitOpen 127.0.0.1:50061\n\
    PermitListen none\n\
    AllowAgentForwarding no\n\
    X11Forwarding no\n\
    PermitTTY no\n\
    PermitTunnel no\n\
    PermitUserRC no\n\
    MaxSessions 0\n\
Match all\n"
}

fn restricted_control_base_args(
    logical_hostname: &str,
    operator_private_key_path: &Path,
    known_hosts_path: &Path,
) -> Vec<String> {
    vec![
        "-i".to_owned(),
        operator_private_key_path.display().to_string(),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=5".to_owned(),
        "-o".to_owned(),
        "ConnectionAttempts=1".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts_path.display()),
        "-o".to_owned(),
        format!("HostKeyAlias={logical_hostname}"),
    ]
}

fn restricted_agent_tunnel_args(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    known_hosts_path: &Path,
    local_port: u16,
) -> Vec<String> {
    let mut args = restricted_control_base_args(
        logical_hostname,
        operator_private_key_path,
        known_hosts_path,
    );
    args.extend([
        "-o".to_owned(),
        "ExitOnForwardFailure=yes".to_owned(),
        "-N".to_owned(),
        "-L".to_owned(),
        format!("127.0.0.1:{local_port}:{EDGE_AGENT_LOOPBACK}"),
        format!("{CONTROL_TRANSPORT_USER}@{target_ip}"),
    ]);
    args
}

fn run_expected_restricted_failure(
    program: &str,
    args: &[String],
    stdin: Option<&[u8]>,
    label: &str,
) -> Result<(), String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to start restricted {label} probe: {err}"))?;
    if let Some(input) = stdin
        && let Some(mut handle) = child.stdin.take()
    {
        handle
            .write_all(input)
            .map_err(|err| format!("failed to write restricted {label} probe input: {err}"))?;
    }

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("failed to inspect restricted {label} probe: {err}"))?
        {
            if status.success() {
                return Err(format!(
                    "restricted edge-control {label} capability unexpectedly succeeded"
                ));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "restricted edge-control {label} probe remained active; capability was not proven rejected"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn prove_restricted_control_negative_capabilities(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<RestrictedControlNegativeProof, String> {
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let result = (|| {
        let target = format!("{CONTROL_TRANSPORT_USER}@{target_ip}");
        let base = restricted_control_base_args(
            logical_hostname,
            operator_private_key_path,
            &trust,
        );

        let mut shell_args = base.clone();
        shell_args.extend(["-T".to_owned(), target.clone()]);
        run_expected_restricted_failure("ssh", &shell_args, None, "shell")?;

        let mut exec_args = base.clone();
        exec_args.extend([target.clone(), "true".to_owned()]);
        run_expected_restricted_failure("ssh", &exec_args, None, "exec")?;

        let mut pty_args = base.clone();
        pty_args.extend(["-tt".to_owned(), target.clone(), "true".to_owned()]);
        run_expected_restricted_failure("ssh", &pty_args, None, "pty")?;

        let mut remote_forward_args = base.clone();
        remote_forward_args.extend([
            "-o".to_owned(),
            "ExitOnForwardFailure=yes".to_owned(),
            "-N".to_owned(),
            "-R".to_owned(),
            "127.0.0.1:45991:127.0.0.1:50061".to_owned(),
            target.clone(),
        ]);
        run_expected_restricted_failure(
            "ssh",
            &remote_forward_args,
            None,
            "remote-forward",
        )?;

        let source = unique_temp_file("edge-control-scp-negative");
        fs::write(&source, b"restricted transport negative proof\n")
            .map_err(|err| format!("failed to write restricted SCP probe source: {err}"))?;
        let scp_result = (|| {
            let mut scp_args = base.clone();
            scp_args.extend([
                "-O".to_owned(),
                source.display().to_string(),
                format!("{target}:/tmp/edge-control-forbidden"),
            ]);
            run_expected_restricted_failure("scp", &scp_args, None, "scp")
        })();
        let _ = fs::remove_file(&source);
        scp_result?;

        let mut sftp_args = base;
        sftp_args.extend(["-b".to_owned(), "-".to_owned(), target]);
        run_expected_restricted_failure(
            "sftp",
            &sftp_args,
            Some(b"pwd\nquit\n"),
            "sftp",
        )?;

        Ok(RestrictedControlNegativeProof {
            shell_rejected: true,
            exec_rejected: true,
            scp_rejected: true,
            sftp_rejected: true,
            pty_rejected: true,
            remote_forward_rejected: true,
        })
    })();
    let _ = fs::remove_file(&trust);
    result
}

fn strict_ssh_args(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    known_hosts_path: &Path,
    remote_command: &str,
) -> Vec<String> {
    vec![
        "-i".to_owned(),
        operator_private_key_path.display().to_string(),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=5".to_owned(),
        "-o".to_owned(),
        "ConnectionAttempts=1".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts_path.display()),
        "-o".to_owned(),
        format!("HostKeyAlias={logical_hostname}"),
        format!("{DEFAULT_OPS_USER}@{target_ip}"),
        remote_command.to_owned(),
    ]
}

fn write_ca_known_hosts(
    logical_hostname: &str,
    canonical_operator_public_key: &str,
) -> Result<PathBuf, String> {
    validate_hostname(logical_hostname)?;
    let material = public_key_material(canonical_operator_public_key)?;
    let path = unique_temp_file("singbox-known-hosts");
    fs::write(
        &path,
        format!("@cert-authority {logical_hostname} {material}\n"),
    )
    .map_err(|err| format!("failed to write strict SSH CA trust file: {err}"))?;
    Ok(path)
}

fn public_key_material(public_key: &str) -> Result<String, String> {
    let mut fields = public_key.split_whitespace();
    let algorithm = fields
        .next()
        .ok_or_else(|| "canonical SSH public key is empty".to_owned())?;
    let material = fields
        .next()
        .ok_or_else(|| "canonical SSH public key has no key material".to_owned())?;
    if algorithm != "ssh-ed25519" {
        return Err(format!(
            "canonical SSH public key must be ssh-ed25519, got {algorithm}"
        ));
    }
    if material.is_empty() {
        return Err("canonical SSH public key material is empty".to_owned());
    }
    Ok(format!("{algorithm} {material}"))
}

fn validate_hostname(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.'))
    {
        return Err(format!("invalid strict SSH logical hostname {value}"));
    }
    Ok(())
}

fn unique_temp_dir(prefix: &str) -> Result<PathBuf, String> {
    let path = unique_temp_file(prefix);
    fs::create_dir(&path).map_err(|err| {
        format!(
            "failed to create temporary directory {}: {err}",
            path.display()
        )
    })?;
    Ok(path)
}

fn unique_temp_file(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn run_checked(program: &str, args: &[String], stdin: Option<&[u8]>) -> Result<(), String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to start {program}: {err}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .ok_or_else(|| format!("failed to open stdin for {program}"))?
            .write_all(input)
            .map_err(|err| format!("failed to write stdin for {program}: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed to wait for {program}: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{program} exited with status {}: {}",
            output.status,
            stderr.trim()
        ))
    }
}

fn run_capture(program: &str, args: &[String]) -> Result<Vec<u8>, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("failed to start {program}: {err}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "{program} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_provider_vultr::VultrErrorKind;

    #[derive(Default)]
    struct FakeOperationalProvider {
        instance: Option<VultrInstance>,
        user_data: String,
        update_error: Option<VultrError>,
        update_commits: bool,
        update_calls: usize,
        start_calls: usize,
        halt_calls: usize,
        reboot_calls: usize,
    }

    impl OperationalProvider for FakeOperationalProvider {
        async fn get_instance(&mut self, _instance_id: &str) -> Result<VultrInstance, VultrError> {
            self.instance.clone().ok_or_else(|| VultrError {
                operation: "read Vultr instance",
                kind: VultrErrorKind::Http,
                status: Some(404),
                retry_after_secs: None,
                detail: "not found".to_owned(),
            })
        }

        async fn start_instance(&mut self, _instance_id: &str) -> Result<(), VultrError> {
            self.start_calls += 1;
            if let Some(instance) = self.instance.as_mut() {
                instance.power_status = "running".to_owned();
            }
            Ok(())
        }

        async fn halt_instance(&mut self, _instance_id: &str) -> Result<(), VultrError> {
            self.halt_calls += 1;
            if let Some(instance) = self.instance.as_mut() {
                instance.power_status = "stopped".to_owned();
            }
            Ok(())
        }

        async fn reboot_instance(&mut self, _instance_id: &str) -> Result<(), VultrError> {
            self.reboot_calls += 1;
            Ok(())
        }

        async fn get_user_data(&mut self, _instance_id: &str) -> Result<String, VultrError> {
            Ok(self.user_data.clone())
        }

        async fn update_user_data(
            &mut self,
            _instance_id: &str,
            user_data: &str,
        ) -> Result<(), VultrError> {
            self.update_calls += 1;
            if self.update_error.is_none() || self.update_commits {
                self.user_data = user_data.to_owned();
            }
            match self.update_error.clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
    }

    fn instance(power_status: &str) -> VultrInstance {
        VultrInstance {
            id: "instance-1".to_owned(),
            label: "edge-1".to_owned(),
            region: "waw".to_owned(),
            plan: "vc2-1c-1gb".to_owned(),
            status: "active".to_owned(),
            server_status: "ok".to_owned(),
            power_status: power_status.to_owned(),
            main_ip: "203.0.113.10".to_owned(),
            v6_main_ip: String::new(),
            firewall_group_id: String::new(),
            date_created: String::new(),
            tags: Vec::new(),
            os_id: 2625,
            snapshot_id: None,
            enable_ipv6: false,
        }
    }

    fn uncertain(operation: &'static str) -> VultrError {
        VultrError {
            operation,
            kind: VultrErrorKind::MutationUncertain,
            status: None,
            retry_after_secs: None,
            detail: "simulated response loss".to_owned(),
        }
    }

    #[tokio::test]
    async fn user_data_scrub_is_idempotent() {
        let mut provider = FakeOperationalProvider {
            user_data: SCRUBBED_USER_DATA.to_owned(),
            ..FakeOperationalProvider::default()
        };
        let changed = scrub_user_data(&mut provider, "instance-1", 2, Duration::ZERO)
            .await
            .unwrap();
        assert!(!changed);
        assert_eq!(provider.update_calls, 0);
    }

    #[tokio::test]
    async fn read_only_user_data_verification_never_mutates() {
        let mut provider = FakeOperationalProvider {
            user_data: SCRUBBED_USER_DATA.to_owned(),
            ..FakeOperationalProvider::default()
        };
        verify_user_data_scrubbed(&mut provider, "instance-1")
            .await
            .unwrap();
        assert_eq!(provider.update_calls, 0);

        provider.user_data = "unexpected bootstrap material".to_owned();
        assert!(
            verify_user_data_scrubbed(&mut provider, "instance-1")
                .await
                .is_err()
        );
        assert_eq!(provider.update_calls, 0);
    }

    #[tokio::test]
    async fn uncertain_user_data_patch_reobserves_without_replay() {
        let mut provider = FakeOperationalProvider {
            user_data: "sensitive bootstrap".to_owned(),
            update_error: Some(uncertain("update Vultr instance user-data")),
            update_commits: true,
            ..FakeOperationalProvider::default()
        };
        let changed = scrub_user_data(&mut provider, "instance-1", 2, Duration::ZERO)
            .await
            .unwrap();
        assert!(changed);
        assert_eq!(provider.update_calls, 1);
        assert_eq!(provider.user_data, SCRUBBED_USER_DATA);
    }

    #[tokio::test]
    async fn unresolved_user_data_patch_never_replays() {
        let mut provider = FakeOperationalProvider {
            user_data: "sensitive bootstrap".to_owned(),
            update_error: Some(uncertain("update Vultr instance user-data")),
            update_commits: false,
            ..FakeOperationalProvider::default()
        };
        let error = scrub_user_data(&mut provider, "instance-1", 2, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(error.contains("PATCH was not replayed"));
        assert_eq!(provider.update_calls, 1);
    }

    #[tokio::test]
    async fn start_and_halt_are_one_shot_and_observed() {
        let mut provider = FakeOperationalProvider {
            instance: Some(instance("stopped")),
            ..FakeOperationalProvider::default()
        };
        let started = apply_instance_action(
            &mut provider,
            "instance-1",
            InstanceAction::Start,
            2,
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(started.power_status, "running");
        assert_eq!(provider.start_calls, 1);

        let halted = apply_instance_action(
            &mut provider,
            "instance-1",
            InstanceAction::Halt,
            2,
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(halted.power_status, "stopped");
        assert_eq!(provider.halt_calls, 1);
    }

    #[test]
    fn strict_cloud_init_contains_host_cert_and_locked_root() {
        let base = "#cloud-config\nwrite_files:\n  - path: /tmp/base\n    content: base\nruncmd:\n  - [true]\n";
        let base = format!(
            "{base}# @@DOCKER_ENGINE_VERSION@@ @@CONTAINERD_VERSION@@ @@COMPOSE_VERSION@@\n"
        );
        let substrate = HostSubstrateVersions::new(
            "5:29.8.1-1~debian.13~trixie".to_owned(),
            "2.3.5-1~debian.13~trixie".to_owned(),
            "5.5.1-1~debian.13~trixie".to_owned(),
        )
        .unwrap();
        let rendered = render_strict_cloud_init(
            &base,
            "edge-1",
            "ssh-ed25519 AAAACanonical comment",
            "PRIVATE\n",
            "ssh-ed25519 AAAAHost host\n",
            "ssh-ed25519-cert-v01@openssh.com AAAACert host\n",
            &substrate,
        )
        .unwrap();

        assert!(rendered.contains("HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"));
        assert!(rendered.contains("5:29.8.1-1~debian.13~trixie"));
        assert!(rendered.contains("2.3.5-1~debian.13~trixie"));
        assert!(!rendered.contains("@@DOCKER_ENGINE_VERSION@@"));
        assert!(rendered.contains("PermitRootLogin no"));
        assert!(rendered.contains("name: singbox-ops"));
        assert!(rendered.contains("name: edge-control"));
        assert!(rendered.contains("shell: /usr/sbin/nologin"));
        assert!(rendered.contains(
            "restrict,port-forwarding,permitopen=\"127.0.0.1:50061\" ssh-ed25519 AAAACanonical"
        ));
        assert!(rendered.contains("Match User edge-control"));
        assert!(rendered.contains("AuthenticationMethods publickey"));
        assert!(rendered.contains("AllowTcpForwarding local"));
        assert!(rendered.contains("AllowStreamLocalForwarding no"));
        assert!(rendered.contains("PermitOpen 127.0.0.1:50061"));
        assert!(rendered.contains("PermitListen none"));
        assert!(rendered.contains("AllowAgentForwarding no"));
        assert!(rendered.contains("X11Forwarding no"));
        assert!(rendered.contains("PermitTTY no"));
        assert!(rendered.contains("PermitTunnel no"));
        assert!(rendered.contains("PermitUserRC no"));
        assert!(rendered.contains("MaxSessions 0"));
        assert!(!rendered.contains("ForceCommand"));
        assert!(rendered.contains("Match all"));
        assert!(rendered.contains("hostname: edge-1"));
        assert!(!rendered.contains("StrictHostKeyChecking=accept-new"));
    }

    #[test]
    fn restricted_control_key_and_tunnel_are_agent_only() {
        let key =
            restricted_control_authorized_key("ssh-ed25519 AAAACanonical ignored-comment").unwrap();
        assert_eq!(
            key,
            "restrict,port-forwarding,permitopen=\"127.0.0.1:50061\" ssh-ed25519 AAAACanonical"
        );
        assert!(!key.contains("ignored-comment"));

        let args = restricted_agent_tunnel_args(
            "203.0.113.10",
            "edge-1",
            Path::new("/tmp/operator-key"),
            Path::new("/tmp/known-hosts"),
            43123,
        );
        assert!(args.iter().any(|value| value == "-N"));
        assert!(
            args.iter()
                .any(|value| value == "127.0.0.1:43123:127.0.0.1:50061")
        );
        assert!(
            args.iter()
                .any(|value| value == "edge-control@203.0.113.10")
        );
        assert!(!args.iter().any(|value| value == "singbox-ops@203.0.113.10"));
        assert!(!args.iter().any(|value| value == "accept-new"));

        let base = restricted_control_base_args(
            "edge-1",
            Path::new("/tmp/operator-key"),
            Path::new("/tmp/known-hosts"),
        );
        assert!(base.iter().any(|value| value == "BatchMode=yes"));
        assert!(base.iter().any(|value| value == "StrictHostKeyChecking=yes"));
        assert!(base.iter().any(|value| value == "HostKeyAlias=edge-1"));
        assert!(!base.iter().any(|value| value.contains("singbox-ops")));
    }

    #[test]
    fn substrate_acceptance_command_emits_typed_failure_markers() {
        let substrate = HostSubstrateVersions::new(
            "5:29.8.1-1~debian.13~trixie".to_owned(),
            "2.3.5-1~debian.13~trixie".to_owned(),
            "5.5.1-1~debian.13~trixie".to_owned(),
        )
        .unwrap();
        let command = substrate_acceptance_command(&substrate).unwrap();

        for marker in [
            "host-bootstrap-marker",
            "docker-ce-version",
            "docker-cli-version",
            "containerd-version",
            "compose-version",
            "docker-service",
            "docker-api",
            "compose-cli",
            "sshd-config",
        ] {
            assert!(command.contains(marker), "missing marker {marker}");
        }
        assert!(command.contains("record_failure"));
        assert!(command.contains("EDGE_SUBSTRATE_FAIL:$failures"));
        assert_eq!(command.matches("exit 42").count(), 1);
    }

    #[test]
    fn substrate_forensics_are_bounded_and_exclude_sensitive_payloads() {
        let command = substrate_forensic_command();
        assert!(command.contains("EDGE_SUBSTRATE_FORENSIC:"));
        assert!(command.contains("/proc/sys/kernel/random/boot_id"));
        assert!(command.contains("/var/lib/cloud/data/instance-id"));
        assert!(!command.contains("/var/lib/cloud/instance/user-data"));
        assert!(!command.contains("private_key"));
        assert!(!command.contains("token="));

        let oversized = format!("noise\nEDGE_SUBSTRATE_FORENSIC:{}\n", "x".repeat(1500));
        let bounded = bounded_forensic_evidence(oversized.as_bytes());
        assert_eq!(bounded.chars().count(), 1200);
    }

    #[test]
    fn strict_ssh_failure_classification_is_typed_and_bounded() {
        assert_eq!(
            classify_strict_ssh_failure(
                Some(255),
                b"ssh: connect to host x port 22: Connection refused"
            )
            .class,
            StrictSshFailureClass::Transport
        );
        assert_eq!(
            classify_strict_ssh_failure(Some(255), b"Host key verification failed.").class,
            StrictSshFailureClass::HostTrust
        );
        assert_eq!(
            classify_strict_ssh_failure(Some(255), b"Permission denied (publickey).").class,
            StrictSshFailureClass::Authentication
        );

        let remote = classify_strict_ssh_failure(Some(42), b"EDGE_SUBSTRATE_FAIL:docker-service");
        assert_eq!(remote.class, StrictSshFailureClass::RemoteAcceptance);
        assert!(remote.detail.contains("docker-service"));

        let unmarked_remote = classify_strict_ssh_failure(Some(1), b"");
        assert_eq!(
            unmarked_remote.class,
            StrictSshFailureClass::RemoteAcceptance
        );
        assert_eq!(unmarked_remote.detail, "no-stderr");

        let sensitive = bounded_ssh_evidence(b"password=secret\nline-2\nline-3\nline-4\nline-5\n");
        assert!(sensitive.contains("[redacted sensitive SSH evidence]"));
        assert!(!sensitive.contains("secret"));
        assert!(!sensitive.contains("line-5"));
    }

    #[test]
    fn substrate_versions_reject_shell_metacharacters() {
        let error = HostSubstrateVersions::new(
            "29.0.0;touch-/tmp/bad".to_owned(),
            "2.3.5".to_owned(),
            "5.5.1".to_owned(),
        )
        .unwrap_err();
        assert!(error.contains("Docker Engine"));
    }

    #[test]
    fn ca_trust_is_exact_hostname_and_ed25519_material() {
        let material =
            public_key_material("ssh-ed25519 AAAACanonical comment that is intentionally ignored")
                .unwrap();
        assert_eq!(material, "ssh-ed25519 AAAACanonical");
        assert_eq!(
            format!("@cert-authority {} {}\n", "edge-1", material),
            "@cert-authority edge-1 ssh-ed25519 AAAACanonical\n"
        );
    }
    #[test]
    fn served_host_certificate_serial_is_read_from_strict_handshake() {
        let stderr = b"debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com SHA256:redacted, serial 2 ID \"edge-1-rotated\" CA ssh-ed25519 SHA256:redacted valid forever\n";
        assert_eq!(parse_served_host_certificate_serial(stderr).unwrap(), 2);
        assert!(
            parse_served_host_certificate_serial(
                b"debug1: Server host key: ssh-ed25519 SHA256:redacted\n"
            )
            .is_err()
        );
        assert!(parse_served_host_certificate_serial(
            b"debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com SHA256:redacted, serial nope ID \"bad\"\n"
        )
        .is_err());
    }

    #[test]
    fn transport_stage_evidence_is_structured_and_bounded() {
        let stderr = b"debug1: Connection established.\ndebug1: Remote protocol version 2.0\ndebug1: SSH2_MSG_KEXINIT sent\ndebug1: Server host key: ssh-ed25519 SHA256:redacted\ndebug1: Authentications that can continue: publickey\n";
        let evidence = transport_stage_evidence(stderr, false);
        assert!(evidence.contains("tcp_connected=true"));
        assert!(evidence.contains("remote_banner=true"));
        assert!(evidence.contains("kex_reached=true"));
        assert!(evidence.contains("authentication_reached=true"));
        assert!(!evidence.contains("SHA256:redacted"));
    }

    #[test]
    fn successful_late_transport_probe_allows_one_final_acceptance_observation() {
        assert!(should_retry_acceptance_after_transport_probe(
            StrictSshFailureClass::Transport,
            true,
        ));
        assert!(!should_retry_acceptance_after_transport_probe(
            StrictSshFailureClass::Transport,
            false,
        ));
        assert!(!should_retry_acceptance_after_transport_probe(
            StrictSshFailureClass::RemoteAcceptance,
            true,
        ));
    }

    #[test]
    fn committed_certificate_rotation_is_accepted_after_uncertain_mutation() {
        let result = resolve_host_certificate_rotation_outcome(
            2,
            Err("simulated response loss".to_owned()),
            Ok(2),
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn uncertain_certificate_rotation_never_replays() {
        let error = resolve_host_certificate_rotation_outcome(
            2,
            Err("simulated response loss".to_owned()),
            Err("re-observation unavailable".to_owned()),
        )
        .unwrap_err();
        assert!(error.contains("outcome is uncertain"));
        assert!(error.contains("mutation was not replayed"));
    }
}
