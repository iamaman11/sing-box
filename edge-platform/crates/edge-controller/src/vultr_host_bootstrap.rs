use edge_provider_vultr::{
    VultrError, VultrInstance, get_instance_typed, get_user_data_typed, halt_instance_typed,
    reboot_instance_typed, start_instance_typed, update_user_data_typed,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

pub const DEFAULT_OPS_USER: &str = "singbox-ops";
pub const SCRUBBED_USER_DATA: &str =
    "#cloud-config\n# sing-box bootstrap material scrubbed after strict SSH acceptance\n";

pub struct StrictBootstrapBundle {
    pub cloud_init: String,
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
) -> Result<String, String> {
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

    let header = format!(
        "#cloud-config\nhostname: {logical_hostname}\nmanage_etc_hosts: true\nusers:\n  - name: {DEFAULT_OPS_USER}\n    groups: [sudo]\n    sudo: [\"ALL=(ALL) NOPASSWD:ALL\"]\n    shell: /bin/bash\n    lock_passwd: true\n    ssh_authorized_keys:\n      - {canonical_key}\nssh_pwauth: false\ndisable_root: true\nssh_deletekeys: false\nssh_genkeytypes: []\n"
    );
    let mut rendered = base_cloud_init.replacen("#cloud-config\n", &header, 1);

    let files = format!(
        "write_files:\n{}{}{}{}",
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
        )
    );
    rendered = rendered.replacen(write_anchor, &files, 1);
    rendered = rendered.replacen(
        run_anchor,
        "runcmd:\n  - [bash, -lc, \"sshd -t && systemctl restart ssh\"]\n  - [bash, -lc, \"install -d -m 0755 /var/lib/singbox-lifecycle && printf '%s\\n' strict-host-cert-ready > /var/lib/singbox-lifecycle/host-bootstrap\"]\n",
        1,
    );
    Ok(rendered)
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

pub async fn strict_ssh_accept(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
    attempts: usize,
    delay: Duration,
) -> Result<(), String> {
    if attempts == 0 {
        return Err("strict SSH attempts must be greater than zero".to_owned());
    }
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let args = strict_ssh_args(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        &trust,
        "test -f /var/lib/singbox-lifecycle/host-bootstrap && sudo sshd -t",
    );
    let mut last = None;
    for attempt in 0..attempts {
        match run_checked("ssh", &args, None) {
            Ok(()) => {
                let _ = fs::remove_file(&trust);
                return Ok(());
            }
            Err(err) => last = Some(err),
        }
        if attempt + 1 < attempts {
            sleep(delay).await;
        }
    }
    let _ = fs::remove_file(&trust);
    Err(format!(
        "strict SSH acceptance failed for {logical_hostname} at {target_ip}: {}",
        last.unwrap_or_else(|| "no SSH attempt was made".to_owned())
    ))
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
    rotate_host_certificate(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
        minimum_serial,
    )?;
    let observed = read_host_certificate_serial(
        target_ip,
        logical_hostname,
        operator_private_key_path,
        canonical_operator_public_key,
    )?;
    if observed < minimum_serial {
        return Err(format!(
            "host certificate rotation did not reach required serial {minimum_serial}: observed {observed}"
        ));
    }
    Ok(true)
}

fn read_host_certificate_serial(
    target_ip: &str,
    logical_hostname: &str,
    operator_private_key_path: &Path,
    canonical_operator_public_key: &str,
) -> Result<u64, String> {
    let trust = write_ca_known_hosts(logical_hostname, canonical_operator_public_key)?;
    let result = (|| {
        let output = run_capture(
            "ssh",
            &strict_ssh_args(
                target_ip,
                logical_hostname,
                operator_private_key_path,
                &trust,
                "sudo ssh-keygen -L -f /etc/ssh/ssh_host_ed25519_key-cert.pub",
            ),
        )?;
        let text = String::from_utf8(output)
            .map_err(|_| "host certificate metadata was not UTF-8".to_owned())?;
        text.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix("Serial:"))
            .map(str::trim)
            .ok_or_else(|| "host certificate metadata did not contain Serial".to_owned())?
            .parse::<u64>()
            .map_err(|err| format!("invalid host certificate serial: {err}"))
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
        let rendered = render_strict_cloud_init(
            base,
            "edge-1",
            "ssh-ed25519 AAAACanonical comment",
            "PRIVATE\n",
            "ssh-ed25519 AAAAHost host\n",
            "ssh-ed25519-cert-v01@openssh.com AAAACert host\n",
        )
        .unwrap();

        assert!(rendered.contains("HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"));
        assert!(rendered.contains("PermitRootLogin no"));
        assert!(rendered.contains("name: singbox-ops"));
        assert!(rendered.contains("hostname: edge-1"));
        assert!(!rendered.contains("StrictHostKeyChecking=accept-new"));
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
}
