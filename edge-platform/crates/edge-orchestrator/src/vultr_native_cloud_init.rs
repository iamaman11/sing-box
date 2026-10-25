//! Secret-free, SSH-free first-use cloud-init for the existing VM Root Agent.
//! This prepares native root enrollment only. It does NOT grant a runner
//! registration or deliver long-lived Cloudflare Access credentials.
//! The provider CREATE gate remains closed until those two steps are proven.
use super::HostSubstrateVersions;

const NATIVE_INIT_PATH: &str = "/usr/local/sbin/singbox-native-first-use.sh";
const NATIVE_FIRST_USE: &str = r#"#!/usr/bin/env bash
set -euo pipefail
umask 077
owner=/usr/local/libexec/sing-box/edge-agent
receipt=/opt/vultr-edge-stack/native-first-use.receipt
stage=/usr/local/libexec/sing-box/.edge-agent-first-use
# A partially completed cloud-init is UNKNOWN_NO_REPLAY, never adoption.
if test -e "$owner" || test -L "$owner" ||
   test -e "$stage" || test -L "$stage" ||
   test -e "$receipt" || test -L "$receipt" ||
   test -e /opt/vultr-edge-stack/native-host; then
  echo HOST_CLOUD_INIT_NATIVE_OWNER_ALREADY_PRESENT_NO_REPLAY >&2
  exit 72
fi
install -d -o root -g root -m 0755 /usr/local/libexec/sing-box
install -d -o root -g root -m 0755 /opt/vultr-edge-stack
install -d -o root -g root -m 0755 /var/lib/singbox-lifecycle
# The old acceptance RPC service is not a second native owner.
systemctl disable --now edge-agent.service >/dev/null 2>&1 || true
curl --fail --silent --show-error --location --proto '=https' \
  --proto-redir '=https' --connect-timeout 10 --max-time 180 \
  --output "$stage" \
  "https://github.com/iamaman11/sing-box/releases/download/edge-release-@@RELEASE@@/edge-agent-linux-amd64"
printf '%s  %s\n' '@@AGENT_SHA@@' "$stage" | sha256sum --check --status
chown root:root "$stage"
chmod 0755 "$stage"
# Commit only an exact hashed binary; a lost acknowledgement cannot retry.
mv -T "$stage" "$owner"
test "$(stat -c '%u:%g:%a' "$owner")" = '0:0:755'
test "$(sha256sum "$owner" | cut -d' ' -f1)" = '@@AGENT_SHA@@'
# Existing compiled native code verifies the accepted ReleaseSet, Git tree,
# fleet registry and Worker public signer BEFORE generating its receipt key.
# Receipt is public evidence only, retained root-private until Git registration.
(
  set -C
  "$owner" local host-enroll '@@MACHINE@@' '@@RELEASE@@' > "$receipt"
)
chmod 0600 "$receipt"
test "$(stat -c '%u:%g:%a' "$receipt")" = '0:0:600'
grep -Fxq 'host_enroll=PROTECTED_TRUST_STAGED' "$receipt"
grep -Fxq 'host_native_receipt_registration=AWAITING_PROTECTED_GIT' "$receipt"
# No self-hosted runner or credential service is activated by this script.
# Until a one-time root-only credential handoff is accepted, this VM is staged.
printf '%s\n' NATIVE_ROOT_ENROLLED_AWAITING_ONE_TIME_CREDENTIAL_HANDOFF \
  > /var/lib/singbox-lifecycle/native-first-use-stage
"#;

fn exact_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn host_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

/// Render one pinned, secret-free cloud-init from the existing substrate.
/// No SSH key/certificate, no generic sudo account and no shared credential.
/// Do not use for CREATE without separate verified one-use identity + runner.
pub fn render_native_first_use_cloud_init(
    base: &str,
    machine_id: &str,
    release_sha256: &str,
    agent_sha256: &str,
    substrate: &HostSubstrateVersions,
) -> Result<String, String> {
    if !host_id(machine_id) {
        return Err("HOST_NATIVE_CLOUD_INIT_MACHINE_INVALID".to_owned());
    }
    if !exact_sha(release_sha256) || !exact_sha(agent_sha256) {
        return Err("HOST_NATIVE_CLOUD_INIT_RELEASE_PIN_INVALID".to_owned());
    }
    let mut rendered = super::render_host_substrate_versions(base, substrate)?;
    if !rendered.starts_with("#cloud-config\n")
        || rendered.matches("write_files:\n").count() != 1
        || rendered.matches("\nruncmd:\n").count() != 1
        || rendered.contains("ssh_authorized_keys:")
        || rendered.contains("ssh_host_ed25519_key")
        || rendered.contains("@@RELEASE@@")
        || rendered.contains("@@AGENT_SHA@@")
    {
        return Err("HOST_NATIVE_CLOUD_INIT_TEMPLATE_INVALID".to_owned());
    }
    let pos = rendered
        .find("\nruncmd:\n")
        .ok_or("HOST_NATIVE_CLOUD_INIT_RUN_SEQUENCE_MISSING")?;
    let commands = &rendered[pos + "\nruncmd:\n".len()..];
    if commands
        .lines()
        .any(|line| !line.trim().is_empty() && !line.starts_with("  "))
    {
        return Err("HOST_NATIVE_CLOUD_INIT_EXTRA_TOP_LEVEL_KEY".to_owned());
    }

    let native = NATIVE_FIRST_USE
        .replace("@@MACHINE@@", machine_id)
        .replace("@@RELEASE@@", release_sha256)
        .replace("@@AGENT_SHA@@", agent_sha256);
    let file = super::cloud_init_file(NATIVE_INIT_PATH, "0700", &native);
    rendered = rendered.replacen("write_files:\n", &format!("write_files:\n{file}"), 1);
    // Exactly one initial identity; refuse any possibility of login over SSH.
    let header = format!(
        "#cloud-config\nhostname: {machine_id}\nmanage_etc_hosts: true\nssh_pwauth: false\ndisable_root: true\n"
    );
    rendered = rendered.replacen("#cloud-config\n", &header, 1);
    rendered.push_str(&format!("  - [bash, -lc, \"{NATIVE_INIT_PATH}\"]\n"));
    if !rendered.contains("native-first-use.sh")
        || rendered.contains("VULTR_SSH_PRIVATE_KEY")
        || rendered.contains("EDGE_RUNNER_REGISTRATION_TOKEN")
        || rendered.contains("CLOUDFLARE_VM_ACCESS_CLIENT_SECRET")
        || rendered.contains("NOPASSWD:ALL")
    {
        return Err("HOST_NATIVE_CLOUD_INIT_SECRET_OR_SSH_REGRESSION".to_owned());
    }
    Ok(rendered)
}


const RUNNER_INSTALLER: &str =
    include_str!("../../../scripts/install-vultr-production-runner.sh");
const RUNNER_INSTALL_PATH: &str = "/usr/local/sbin/singbox-native-runner-install.sh";
const RUNNER_BEGIN_PATH: &str = "/var/lib/singbox-lifecycle/runner-first-use.begin";
const RUNNER_TOKEN_PATH: &str = "/run/singbox-native-runner-registration-token";
const RUNNER_WRAP_PATH: &str = "/usr/local/sbin/singbox-native-runner-enroll.sh";

/// The only secret allowed in provider user-data is one short-lived GitHub
/// registration capability. Its provider copy must be scrubbed and observed
/// before physical acceptance. A permanent Worker Access identity MUST travel
/// separately through the protected Root Agent; it is never in user-data.
pub fn render_native_first_use_with_runner(
    base: &str,
    machine_id: &str,
    release_sha256: &str,
    agent_sha256: &str,
    substrate: &HostSubstrateVersions,
    registration_token: &str,
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<String, String> {
    if registration_token.len() < 40
        || registration_token.len() > 512
        || !registration_token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'
        })
    {
        return Err("HOST_NATIVE_RUNNER_REGISTRATION_TOKEN_INVALID".to_owned());
    }
    if expires_at_unix < now_unix.saturating_add(1200)
        || expires_at_unix > now_unix.saturating_add(3600)
    {
        return Err("HOST_NATIVE_RUNNER_REGISTRATION_EXPIRY_UNSAFE".to_owned());
    }
    let mut rendered = render_native_first_use_cloud_init(
        base,
        machine_id,
        release_sha256,
        agent_sha256,
        substrate,
    )?;
    if !RUNNER_INSTALLER.starts_with("#!/usr/bin/env bash\n")
        || !RUNNER_INSTALLER.contains("--runner-only")
        || !RUNNER_INSTALLER.contains("runner_native_mutation_authority=EXACT_HOST_INTENT_ONLY")
    {
        return Err("HOST_NATIVE_RUNNER_INSTALLER_NOT_ACCEPTED".to_owned());
    }
    let script = format!(
        "#!/usr/bin/env bash\n\
set -euo pipefail\n\
umask 077\n\
begin='{RUNNER_BEGIN_PATH}'\n\
token='{RUNNER_TOKEN_PATH}'\n\
if test -e \"$begin\" || test -L \"$begin\"; then\n\
  echo HOST_NATIVE_RUNNER_BEGIN_ALREADY_EXISTS_NO_REPLAY >&2\n\
  exit 74\n\
fi\n\
test \"$(date -u +%s)\" -lt '{expires_at_unix}' || {{\n\
  echo HOST_NATIVE_RUNNER_TOKEN_EXPIRED_NO_REPLAY >&2\n\
  exit 75\n\
}}\n\
test \"$(stat -c '%u:%g:%a' \"$token\")\" = '0:0:600'\n\
test \"$(stat -c '%u:%g:%a' /opt/vultr-edge-stack/native-first-use.receipt)\" = '0:0:600'\n\
grep -Fxq 'host_enroll=PROTECTED_TRUST_STAGED' /opt/vultr-edge-stack/native-first-use.receipt\n\
# Persist BEGIN before invoking GitHub's one-time runner registration.\n\
( set -C; printf '%s\\n' FIRST_USE_BEGIN_NO_REPLAY > \"$begin\" )\n\
sync -f \"$begin\"\n\
trap 'rm -f \"$token\"' EXIT\n\
{{ cat \"$token\"; printf '\\n'; }} | '{RUNNER_INSTALL_PATH}' '{machine_id}' --runner-only\n\
printf '%s\\n' RUNNER_REGISTERED_AWAITING_ROOT_ONLY_ACCESS_HANDOFF\n"
    );
    let additions = format!(
        "{}{}{}",
        super::cloud_init_file(RUNNER_INSTALL_PATH, "0700", RUNNER_INSTALLER),
        super::cloud_init_file(RUNNER_WRAP_PATH, "0700", &script),
        super::cloud_init_file(RUNNER_TOKEN_PATH, "0600", registration_token),
    );
    rendered = rendered.replacen("write_files:\n", &format!("write_files:\n{additions}"), 1);
    rendered.push_str(&format!(
        "  - [bash, -lc, \"{RUNNER_WRAP_PATH}\"]\n"
    ));
    // A root-only, expired ephemeral registration token is not the VM Access
    // identity. The acceptance owner must prove Vultr user-data scrub and
    // native receipt before any signed INSTALL.
    if rendered.contains("CF_ACCESS_CLIENT_SECRET=")
        || rendered.contains("EDGE_VM_CREDENTIAL_ACCESS_CLIENT_SECRET")
        || rendered.contains("VULTR_SSH_PRIVATE_KEY")
        || rendered.contains("NOPASSWD:ALL")
        || rendered.contains("ssh_authorized_keys:")
    {
        return Err("HOST_NATIVE_RUNNER_USER_DATA_CONTAINS_DURABLE_SECRET".to_owned());
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn substrate() -> HostSubstrateVersions {
        HostSubstrateVersions::new(
            "5:29.0.4-1~debian.12~bookworm".into(),
            "1.7.28-1".into(),
            "5.0.0-1~debian.12~bookworm".into(),
        )
        .unwrap()
    }

    fn fixture() -> &'static str {
        "#cloud-config\nwrite_files:\n  - path: /tmp/substrate\n    content: |\n      @@DOCKER_ENGINE_VERSION@@\n      @@CONTAINERD_VERSION@@\n      @@COMPOSE_VERSION@@\nruncmd:\n  - [bash, -lc, \"true\"]\n"
    }

    fn render() -> String {
        render_native_first_use_cloud_init(
            fixture(),
            "application-acceptance-5",
            &"a".repeat(64),
            &"b".repeat(64),
            &substrate(),
        )
        .unwrap()
    }

    #[test]
    fn first_use_runner_has_only_ephemeral_token_and_root_native_transport() {
        let token = "A".repeat(128);
        let config = render_native_first_use_with_runner(
            fixture(), "application-acceptance-5", &"a".repeat(64),
            &"b".repeat(64), &substrate(), &token, 3_500, 0,
        ).unwrap();
        assert_eq!(config.matches(&token).count(), 1);
        assert!(config.contains("runner-first-use.begin"));
        assert!(config.contains("FIRST_USE_BEGIN_NO_REPLAY"));
        assert!(config.contains("--runner-only"));
        assert!(config.contains("singbox-native-runner-enroll.sh"));
        assert!(config.contains("RUNNER_REGISTERED_AWAITING_ROOT_ONLY_ACCESS_HANDOFF"));
        assert!(config.contains("owner=/usr/local/libexec/sing-box/edge-agent"));
        assert!(!config.contains("CF_ACCESS_CLIENT_SECRET="));
        assert!(!config.contains("ssh_authorized_keys:"));
        assert!(!config.contains("NOPASSWD:ALL"));
    }

    #[test]
    fn first_use_runner_rejects_unsafe_token_or_deadline() {
        let validate = |token: &str, expiry: u64| {
            render_native_first_use_with_runner(
                fixture(), "application-acceptance-5", &"a".repeat(64),
                &"b".repeat(64), &substrate(), token, expiry, 0,
            ).is_err()
        };
        for bad in ["", "short", "bad token", "invalid\nsecret", "A&B", "äbc"] {
            assert!(validate(bad, 3_500));
        }
        let accepted_token = "x".repeat(128);
        assert!(validate(&accepted_token, 1_199));
        assert!(validate(&accepted_token, 3_601));
        assert!(!validate(&accepted_token, 3_500));
    }

    #[test]
    fn pinned_native_bootstrap_has_no_ssh_runner_or_durable_secrets() {
        let config = render();
        assert!(config.starts_with("#cloud-config\nhostname: application-acceptance-5\n"));
        assert!(config.contains("/usr/local/sbin/singbox-native-first-use.sh"));
        assert!(config.contains("local host-enroll 'application-acceptance-5' '"));
        assert!(config.contains("sha256sum --check --status"));
        assert!(config.contains("edge-release-"));
        assert!(config.contains("NATIVE_ROOT_ENROLLED_AWAITING_ONE_TIME_CREDENTIAL_HANDOFF"));
        assert!(config.contains("HOST_CLOUD_INIT_NATIVE_OWNER_ALREADY_PRESENT_NO_REPLAY"));
        assert!(config.contains("systemctl disable --now edge-agent.service"));
        assert!(!config.contains("ssh_authorized_keys"));
        assert!(!config.contains("ssh-keygen"));
        assert!(!config.contains("NOPASSWD:ALL"));
        assert!(!config.contains("CF_ACCESS_CLIENT_SECRET="));
        assert!(!config.contains("EDGE_RUNNER_REGISTRATION_TOKEN"));
        assert!(!config.contains("@@"));
        assert!(
            config.ends_with("  - [bash, -lc, \"/usr/local/sbin/singbox-native-first-use.sh\"]\n")
        );
    }

    #[test]
    fn reject_untrusted_ids_and_missing_pins() {
        for id in [
            "", "../host", "host_5", "HOST-5", "-host", "host-", "host 5",
        ] {
            assert!(
                render_native_first_use_cloud_init(
                    fixture(),
                    id,
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &substrate()
                )
                .is_err()
            );
        }
        for digest in ["", "deadbeef", &"A".repeat(64), &"0".repeat(64)] {
            assert!(
                render_native_first_use_cloud_init(
                    fixture(),
                    "host-5",
                    digest,
                    &"b".repeat(64),
                    &substrate()
                )
                .is_err()
            );
        }
        assert!(
            render_native_first_use_cloud_init(
                fixture(),
                "host-5",
                &"a".repeat(64),
                &"0".repeat(64),
                &substrate()
            )
            .is_err()
        );
    }

    #[test]
    fn template_cannot_inject_ssh_or_add_unexpected_yaml_root() {
        for mutated in [
            fixture().replace("write_files:\n", "ssh_authorized_keys:\nwrite_files:\n"),
            fixture().replace("runcmd:\n", "ssh_host_ed25519_key: planted\nruncmd:\n"),
            format!("{}users:\n  - name: root\n", fixture()),
            fixture().replace("runcmd:\n", "runcmd:\nother_key: true\n"),
        ] {
            assert!(
                render_native_first_use_cloud_init(
                    &mutated,
                    "host-5",
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &substrate()
                )
                .is_err()
            );
        }
    }
}
