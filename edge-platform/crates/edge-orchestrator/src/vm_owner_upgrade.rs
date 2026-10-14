// One bounded native bootstrap-to-steady-state owner migration.
// No runner registration, sudoers rewriting, Docker operation, credential publication,
// provider reboot, or replay of a lost SSH acknowledgement.
use super::*;

const OWNER: &str = "/usr/local/libexec/sing-box/edge-agent";
const PREVIOUS: &str = "/usr/local/libexec/sing-box/edge-agent.previous";
const NEXT: &str = "/usr/local/libexec/sing-box/.edge-agent.next";
const JOURNAL: &str = "/usr/local/libexec/sing-box/.edge-agent-upgrade-begin";
const STAGED: &str = "/tmp/singbox-owner-upgrade-next";

fn exact_sha(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bound_upgrade_preflight(current: &str, old: &str, next: &str) -> Result<bool, String> {
    if !exact_sha(current) || !exact_sha(old) || !exact_sha(next) {
        return Err("VM owner digest is not an exact lowercase SHA256".to_owned());
    }
    if current == next {
        return Ok(false);
    }
    if current != old {
        return Err("VM owner drift: installed digest is not authorized previous ReleaseSet owner".to_owned());
    }
    if old == next {
        return Err("owner upgrade requires different installed and candidate SHA256".to_owned());
    }
    Ok(true)
}

pub(super) async fn run(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 4 || !exact_sha(&args[3]) {
        return Err("usage: vultr-lifecycle owner-upgrade <git-owned-vultr-spec> <machine-id> <exact-release-agent> <observed-previous-sha256>".to_owned());
    }
    if env::var("GITHUB_RUN_ATTEMPT").ok().as_deref() != Some("1") {
        return Err("VM owner upgrade requires one non-replayed GitHub attempt".to_owned());
    }
    context.application_release_authority()?;
    let desired = load_desired_state(Path::new(&args[0]))?;
    let expected = context.expected_application_artifact()?;
    context.validate_application_artifact(&expected, Path::new(&args[2]))?;
    if !exact_sha(&expected.sha256) {
        return Err("immutable ReleaseSet agent SHA256 is invalid".to_owned());
    }
    let observed = exact_existing_machine_observation(&desired, &args[1]).await?;
    let target_ip = observed.main_ip.as_deref().ok_or_else(|| {
        "exact owned VM has no observed public IPv4".to_owned()
    })?;
    let key = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key, &public_key)?;
    let capture = |script: &str| {
        strict_ssh_capture(target_ip, &args[1], &key, &public_key, script)
    };

    let owner_stat = capture(&format!(
        "set -eu; test -f {OWNER}; test ! -L {OWNER}; stat -c '%u:%g:%a' {OWNER}"
    ))?;
    if owner_stat != "0:0:755" {
        return Err("VM local owner is not a regular root:root 0755 binary".to_owned());
    }
    let current = capture(&format!("sha256sum {OWNER} | cut -d' ' -f1"))?;
    let must_change = bound_upgrade_preflight(&current, &args[3], &expected.sha256)?;
    if !must_change {
        print_json_value(serde_json::json!({
            "status": "PASS", "action": "NOOP_EXACT_OWNER",
            "machine_id": args[1], "observed_sha256": current,
            "expected_sha256": expected.sha256,
            "agent_operations": 0, "credential_mutations": 0,
            "runner_mutations": 0, "container_mutations": 0,
        }));
        return Ok(());
    }

    // A BEGIN marker or rollback copy means an earlier swap may have committed.
    // Stop before staging; never infer it is safe to replay from a failed ACK.
    let empty = capture(&format!(
        "set -eu; test ! -e {JOURNAL}; test ! -L {JOURNAL};          test ! -e {PREVIOUS}; test ! -L {PREVIOUS};          test ! -e {NEXT}; test ! -L {NEXT};          test ! -e {STAGED}; test ! -L {STAGED}; echo PASS"
    ))?;
    if empty != "PASS" {
        return Err("VM owner upgrade already staged or uncertain; read-only reconciliation required".to_owned());
    }
    let boot_before = capture("cat /proc/sys/kernel/random/boot_id")?;
    strict_scp_upload(
        target_ip,
        &args[1],
        &key,
        &public_key,
        Path::new(&args[2]),
        STAGED,
    )?;
    let staged_sha = capture(&format!(
        "set -eu; test -f {STAGED}; test ! -L {STAGED}; sha256sum {STAGED} | cut -d' ' -f1"
    ))?;
    if staged_sha != expected.sha256 {
        return Err("VM staged owner digest differs from exact ReleaseSet; no privileged mutation".to_owned());
    }

    // All paths are fixed source constants and both interpolated digests passed
    // exact lowercase SHA256 validation. Write durable BEGIN BEFORE atomic swap.
    // A missing response is UNKNOWN and must be reconciled, never retried.
    let remote = format!(
        "set -eu;          test ! -e {JOURNAL}; test ! -e {PREVIOUS}; test ! -e {NEXT};          test \"$(sha256sum {OWNER} | cut -d' ' -f1)\" = {current};          test \"$(sha256sum {STAGED} | cut -d' ' -f1)\" = {next};          sudo -n install -o root -g root -m 0755 {STAGED} {NEXT};          test \"$(sha256sum {NEXT} | cut -d' ' -f1)\" = {next};          printf '%s\\n' '{current} {next}' | sudo -n tee {JOURNAL} >/dev/null;          sudo -n chmod 0600 {JOURNAL};          sudo -n ln {OWNER} {PREVIOUS};          sudo -n mv -T {NEXT} {OWNER};          rm -f {STAGED}",
        next = expected.sha256
    );
    strict_ssh_run(target_ip, &args[1], &key, &public_key, &remote)?;
    let new_sha = capture(&format!("sha256sum {OWNER} | cut -d' ' -f1"))?;
    if new_sha != expected.sha256 {
        return Err("VM owner swap acknowledged but installed digest mismatched; STOP without replay".to_owned());
    }
    if capture("cat /proc/sys/kernel/random/boot_id")? != boot_before {
        return Err("VM boot identity changed during owner upgrade; STOP without replay".to_owned());
    }
    let bounded = capture(&format!(
        "sudo -u github-runner sudo -n {OWNER} local status >/dev/null && echo PASS"
    ))?;
    if bounded != "PASS" {
        return Err("new VM owner not executable through existing bounded dispatch; STOP without replay".to_owned());
    }
    print_json_value(serde_json::json!({
        "status": "PASS", "action": "OWNER_UPGRADED_ONCE",
        "machine_id": args[1], "previous_sha256": current,
        "installed_sha256": new_sha, "expected_sha256": expected.sha256,
        "rollback_binary_retained": true,
        "durable_nonreplay_begin": true,
        "runner_mutations": 0, "container_mutations": 0,
        "credential_mutations": 0, "reboot_mutations": 0,
        "next_safe_action": "READ_ONLY_VM_DIAGNOSE",
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_upgrade_requires_exact_sha_and_never_replays_drift() {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        assert_eq!(bound_upgrade_preflight(&old, &old, &new), Ok(true));
        assert_eq!(bound_upgrade_preflight(&new, &old, &new), Ok(false));
        assert!(bound_upgrade_preflight(&"c".repeat(64), &old, &new).is_err());
        assert!(bound_upgrade_preflight(&old, &old, &old).is_err());
        assert!(bound_upgrade_preflight(&old, &format!("{}x", old), &new).is_err());
        assert!(bound_upgrade_preflight(&old, &old.to_uppercase(), &new).is_err());
        assert!(!exact_sha(&"Z".repeat(64)));
    }

    #[test]
    fn owner_upgrade_paths_are_fixed_and_no_runtime_configuration_is_modified() {
        assert_eq!(OWNER, "/usr/local/libexec/sing-box/edge-agent");
        for p in [PREVIOUS, NEXT, JOURNAL] {
            assert!(p.starts_with("/usr/local/libexec/sing-box/"));
        }
        assert!(STAGED.starts_with("/tmp/singbox-"));
        assert_ne!(OWNER, PREVIOUS);
        assert_ne!(OWNER, NEXT);
    }
}
