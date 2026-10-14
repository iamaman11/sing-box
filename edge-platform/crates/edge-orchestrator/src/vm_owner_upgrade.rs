// One bounded native bootstrap-to-steady-state owner migration.
// No runner registration, sudoers rewriting, Docker operation, credential publication,
// provider reboot, or replay of a lost SSH acknowledgement.
use super::*;

const OWNER: &str = "/usr/local/libexec/sing-box/edge-agent";
const PREVIOUS: &str = "/usr/local/libexec/sing-box/edge-agent.previous";
const NEXT: &str = "/usr/local/libexec/sing-box/.edge-agent.next";
const JOURNAL: &str = "/usr/local/libexec/sing-box/.edge-agent-upgrade-begin";
const JOURNAL_NEXT: &str = "/usr/local/libexec/sing-box/.edge-agent-upgrade-next-begin";
const PREVIOUS_NEXT: &str = "/usr/local/libexec/sing-box/.edge-agent-previous-next";
const HISTORY: &str = "/usr/local/libexec/sing-box/.edge-agent-upgrade-history";
const STAGED: &str = "/tmp/singbox-owner-upgrade-next";
const ROLLBACK_BEGIN: &str = "/usr/local/libexec/sing-box/.edge-agent-rollback-begin";
const FAILED: &str = "/usr/local/libexec/sing-box/edge-agent.failed";

fn exact_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// One recorded previous upgrade is admissible only if the current binary
/// is exactly the successor named by the durable record and the predecessor
/// hardlink has the exact SHA. A missing/partial record is UNKNOWN, not FIRST.
fn bound_existing_owner_chain(
    record: &str,
    current: &str,
) -> Result<Option<String>, String> {
    if !exact_sha(current) {
        return Err("owner chain requires exact current SHA256".to_owned());
    }
    if record == "FIRST" {
        return Ok(None);
    }
    let pair = record
        .strip_prefix("PRIOR:")
        .ok_or_else(|| "existing owner journal observation is malformed".to_owned())?;
    let (previous, journal) = pair
        .split_once(':')
        .ok_or_else(|| "existing owner journal observation is incomplete".to_owned())?;
    if !exact_sha(previous) || journal != format!("{previous} {current}") {
        return Err("existing owner journal does not prove the installed predecessor chain".to_owned());
    }
    if previous == current {
        return Err("existing owner journal refuses identical predecessor and current".to_owned());
    }
    Ok(Some(previous.to_owned()))
}

fn bound_upgrade_preflight(current: &str, old: &str, next: &str) -> Result<bool, String> {
    if !exact_sha(current) || !exact_sha(old) || !exact_sha(next) {
        return Err("VM owner digest is not an exact lowercase SHA256".to_owned());
    }
    if old == next {
        return Err("owner upgrade requires different installed and candidate SHA256".to_owned());
    }
    if current == next {
        return Ok(false);
    }
    if current != old {
        return Err(
            "VM owner drift: installed digest is not authorized previous ReleaseSet owner"
                .to_owned(),
        );
    }
    Ok(true)
}

pub(super) async fn run(args: &[String], context: &OrchestrationContext) -> Result<(), String> {
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
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| "exact owned VM has no observed public IPv4".to_owned())?;
    let key = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key, &public_key)?;
    let capture = |script: &str| strict_ssh_capture(target_ip, &args[1], &key, &public_key, script);

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

    // A prior successful transition is a PROVEN chain, not permission to
    // replay that transition. An inconsistent/partial pair is UNKNOWN.
    let prior = capture(&format!(
        "set -eu; \
         if test -e {JOURNAL} || test -e {PREVIOUS}; then \
           test -f {JOURNAL}; test ! -L {JOURNAL}; \
           test \"$(stat -c '%u:%g:%a' {JOURNAL})\" = '0:0:600'; \
           test -f {PREVIOUS}; test ! -L {PREVIOUS}; \
           test \"$(stat -c '%u:%g:%a' {PREVIOUS})\" = '0:0:755'; \
           printf 'PRIOR:%s:%s\n' \"$(sha256sum {PREVIOUS} | cut -d' ' -f1)\" \"$(sudo -n cat {JOURNAL})\"; \
         else echo FIRST; fi"
    ))?;
    let prior_digest = bound_existing_owner_chain(&prior, &current)?;
    let archive = format!("{HISTORY}/{current}");
    let clean = capture(&format!(
        "set -eu; \
         test ! -e {NEXT}; test ! -L {NEXT}; \
         test ! -e {STAGED}; test ! -L {STAGED}; \
         test ! -e {JOURNAL_NEXT}; test ! -L {JOURNAL_NEXT}; \
         test ! -e {PREVIOUS_NEXT}; test ! -L {PREVIOUS_NEXT}; \
         test ! -e {ROLLBACK_BEGIN}; test ! -e {FAILED}; \
         test ! -L {HISTORY}; \
         if test -e {HISTORY}; then \
           test -d {HISTORY}; \
           test \"$(stat -c '%u:%g:%a' {HISTORY})\" = '0:0:700'; \
         fi; \
         test ! -e {archive}; test ! -L {archive}; echo PASS"
    ))?;
    if clean != "PASS" {
        return Err(
            "VM owner upgrade has a staged or uncertain successor; read-only reconciliation required"
                .to_owned(),
        );
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
        return Err(
            "VM staged owner digest differs from exact ReleaseSet; no privileged mutation"
                .to_owned(),
        );
    }

    // All path/digest interpolation is from fixed constants or exact SHA256.
    // Every new transition writes a *new durable BEGIN* before replacing the
    // prior latest-journal pointer and binary. UNKNOWN is never replayed.
    // The previous BEGIN is archived immutably; rollback retains only the
    // immediate predecessor binary, not a parallel agent.
    let prior_guard = match prior_digest.as_deref() {
        Some(predecessor) => format!(
            "test \"$(sudo -n cat {JOURNAL})\" = '{predecessor} {current}'; \
             test \"$(sha256sum {PREVIOUS} | cut -d' ' -f1)\" = {predecessor}; \
             test ! -e {archive}; \
             sudo -n install -d -o root -g root -m 0700 {HISTORY}; \
             sudo -n ln {JOURNAL} {archive}; sudo -n sync {HISTORY};"
        ),
        None => format!(
            "test ! -e {JOURNAL}; test ! -e {PREVIOUS};"
        ),
    };
    let remote = format!(
        "set -eu; \
         test ! -e {NEXT}; test ! -e {JOURNAL_NEXT}; test ! -e {PREVIOUS_NEXT}; \
         test \"$(sha256sum {OWNER} | cut -d' ' -f1)\" = {current}; \
         test \"$(sha256sum {STAGED} | cut -d' ' -f1)\" = {next}; \
         sudo -n install -o root -g root -m 0755 {STAGED} {NEXT}; \
         test \"$(sha256sum {NEXT} | cut -d' ' -f1)\" = {next}; \
         printf '%s\n' '{current} {next}' | sudo -n tee {JOURNAL_NEXT} >/dev/null; \
         sudo -n chmod 0600 {JOURNAL_NEXT}; \
         sudo -n sync {JOURNAL_NEXT}; sudo -n sync /usr/local/libexec/sing-box; \
         {prior_guard} \
         sudo -n ln {OWNER} {PREVIOUS_NEXT}; \
         sudo -n mv -Tf {PREVIOUS_NEXT} {PREVIOUS}; \
         sudo -n mv -Tf {JOURNAL_NEXT} {JOURNAL}; \
         sudo -n sync {JOURNAL}; sudo -n sync /usr/local/libexec/sing-box; \
         sudo -n mv -T {NEXT} {OWNER}; \
         rm -f {STAGED}",
        next = expected.sha256
    );
    strict_ssh_run(target_ip, &args[1], &key, &public_key, &remote)?;
    let new_sha = capture(&format!("sha256sum {OWNER} | cut -d' ' -f1"))?;
    if new_sha != expected.sha256 {
        return Err(
            "VM owner swap acknowledged but installed digest mismatched; STOP without replay"
                .to_owned(),
        );
    }
    if capture("cat /proc/sys/kernel/random/boot_id")? != boot_before {
        return Err(
            "VM boot identity changed during owner upgrade; STOP without replay".to_owned(),
        );
    }
    let bounded = capture(&format!(
        "sudo -u github-runner sudo -n {OWNER} local status >/dev/null && echo PASS"
    ))?;
    if bounded != "PASS" {
        return Err(
            "new VM owner not executable through existing bounded dispatch; STOP without replay"
                .to_owned(),
        );
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

fn bound_rollback_preflight(
    current: &str,
    expected_current: &str,
    previous: &str,
    expected_previous: &str,
    journal: &str,
) -> Result<(), String> {
    if !exact_sha(current)
        || !exact_sha(expected_current)
        || !exact_sha(previous)
        || !exact_sha(expected_previous)
    {
        return Err("VM owner rollback SHA256 arguments are invalid".to_owned());
    }
    if current != expected_current || previous != expected_previous {
        return Err("VM owner rollback refuses installed/backup digest drift".to_owned());
    }
    if current == previous || journal != format!("{previous} {current}") {
        return Err("VM owner rollback refuses missing or unrelated upgrade BEGIN".to_owned());
    }
    Ok(())
}

/// Explicit once-only recovery of a proven exact prior binary. This is never
/// run automatically when an SSH acknowledgement is uncertain.
pub(super) async fn rollback(
    args: &[String],
    context: &OrchestrationContext,
) -> Result<(), String> {
    if args.len() != 4 || !exact_sha(&args[2]) || !exact_sha(&args[3]) {
        return Err("usage: vultr-lifecycle owner-rollback <git-owned-vultr-spec> <machine-id> <observed-current-sha256> <observed-previous-sha256>".to_owned());
    }
    if env::var("GITHUB_RUN_ATTEMPT").ok().as_deref() != Some("1") {
        return Err("VM owner rollback requires one non-replayed GitHub attempt".to_owned());
    }
    context.application_release_authority()?;
    let expected = context.expected_application_artifact()?;
    if expected.sha256 != args[2] {
        return Err(
            "rollback requires the exact accepted ReleaseSet currently installed owner".to_owned(),
        );
    }
    let desired = load_desired_state(Path::new(&args[0]))?;
    let observed = exact_existing_machine_observation(&desired, &args[1]).await?;
    let target_ip = observed
        .main_ip
        .as_deref()
        .ok_or_else(|| "exact rollback target has no observed IPv4".to_owned())?;
    let key = operator_private_key_path_from_env()?;
    let public_key = read_canonical_ssh_public_key()?;
    verify_operator_key_matches(&key, &public_key)?;
    let capture = |script: &str| strict_ssh_capture(target_ip, &args[1], &key, &public_key, script);
    let owner_stat = capture(&format!(
        "set -eu; test -f {OWNER}; test ! -L {OWNER}; stat -c '%u:%g:%a' {OWNER}"
    ))?;
    let backup_stat = capture(&format!(
        "set -eu; test -f {PREVIOUS}; test ! -L {PREVIOUS}; stat -c '%u:%g:%a' {PREVIOUS}"
    ))?;
    if owner_stat != "0:0:755" || backup_stat != "0:0:755" {
        return Err("owner rollback requires exact root:root 0755 binaries".to_owned());
    }
    let current = capture(&format!("sha256sum {OWNER} | cut -d' ' -f1"))?;
    let previous = capture(&format!("sha256sum {PREVIOUS} | cut -d' ' -f1"))?;
    let journal = capture(&format!("sudo -n cat {JOURNAL}"))?;
    bound_rollback_preflight(&current, &args[2], &previous, &args[3], &journal)?;
    let absent = capture(&format!(
        "set -eu; test ! -e {FAILED}; test ! -L {FAILED}; test ! -e {ROLLBACK_BEGIN}; test ! -L {ROLLBACK_BEGIN}; echo PASS"
    ))?;
    if absent != "PASS" {
        return Err("prior rollback may have committed; STOP without replay".to_owned());
    }
    let boot_before = capture("cat /proc/sys/kernel/random/boot_id")?;
    let remote = format!(
        "set -eu; test ! -e {FAILED}; test ! -e {ROLLBACK_BEGIN};          test \"$(sha256sum {OWNER} | cut -d' ' -f1)\" = {current};          test \"$(sha256sum {PREVIOUS} | cut -d' ' -f1)\" = {previous};          test \"$(sudo -n cat {JOURNAL})\" = '{previous} {current}';          printf '%s\\n' '{previous} {current}' | sudo -n tee {ROLLBACK_BEGIN} >/dev/null;          sudo -n chmod 0600 {ROLLBACK_BEGIN};          sudo -n sync {ROLLBACK_BEGIN}; sudo -n sync /usr/local/libexec/sing-box;          sudo -n ln {OWNER} {FAILED}; sudo -n mv -T {PREVIOUS} {OWNER}"
    );
    strict_ssh_run(target_ip, &args[1], &key, &public_key, &remote)?;
    let installed = capture(&format!("sha256sum {OWNER} | cut -d' ' -f1"))?;
    if installed != previous || capture("cat /proc/sys/kernel/random/boot_id")? != boot_before {
        return Err(
            "owner rollback outcome not proven; reconcile read-only without retry".to_owned(),
        );
    }
    let bounded = capture(&format!(
        "sudo -u github-runner sudo -n {OWNER} local status >/dev/null && echo PASS"
    ))?;
    if bounded != "PASS" {
        return Err("restored VM owner failed existing bounded dispatch".to_owned());
    }
    print_json_value(serde_json::json!({
        "status": "PASS", "action": "OWNER_ROLLED_BACK_ONCE",
        "machine_id": args[1], "installed_sha256": installed,
        "failed_binary_sha256": current, "durable_nonreplay_begin": true,
        "failed_binary_retained": true, "runner_mutations": 0,
        "container_mutations": 0, "credential_mutations": 0,
        "reboot_mutations": 0, "next_safe_action": "READ_ONLY_VM_DIAGNOSE",
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
    fn rollback_is_bound_to_exact_previous_and_durable_upgrade_journal() {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        assert!(bound_rollback_preflight(&new, &new, &old, &old, &format!("{old} {new}")).is_ok());
        assert!(bound_rollback_preflight(&new, &new, &old, &old, "").is_err());
        assert!(bound_rollback_preflight(&new, &old, &old, &old, &format!("{old} {new}")).is_err());
        assert!(bound_rollback_preflight(&new, &new, &new, &old, &format!("{old} {new}")).is_err());
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
