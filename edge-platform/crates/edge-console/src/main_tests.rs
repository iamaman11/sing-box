use super::*;

fn offline_test_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "edge-offline-restore-{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    root
}

#[cfg(windows)]
#[test]
fn offline_first_use_native_root_paths_are_exact_and_not_reparse_files() {
    let root = Path::new(r"C:\sing-box");
    let [protected, journal] = native_host_acl_paths(root);
    assert_eq!(protected, root.join("native-host"));
    assert_eq!(journal, protected.join("journal"));
    let tmp = offline_test_root("native-root-identity");
    assert!(existing_native_host_directory_is_safe(
        &fs::symlink_metadata(&tmp).unwrap()
    ));
    let foreign = tmp.join("native-host");
    fs::write(&foreign, b"not-a-protected-directory").unwrap();
    assert!(!existing_native_host_directory_is_safe(
        &fs::symlink_metadata(&foreign).unwrap()
    ));
    fs::remove_dir_all(tmp).unwrap();
}

#[cfg(windows)]
fn create_zip_identity_fixture(root: &Path, include_installer: bool) -> (PathBuf, PathBuf) {
    let package = root.join("package");
    let bootstrap = package.join("bootstrap");
    fs::create_dir_all(&bootstrap).unwrap();
    let expected_installer = bootstrap.join("install-windows-release.ps1");
    fs::write(
        &expected_installer,
        b"Write-Output 'verified-archive-bytes'\r\n",
    )
    .unwrap();
    if !include_installer {
        fs::remove_file(&expected_installer).unwrap();
        fs::write(package.join("different.txt"), b"not an installer").unwrap();
    }
    let zip = root.join("candidate.zip");
    let fixture_script = r#"
$ErrorActionPreference='Stop'
Compress-Archive -Path (Join-Path $env:EDGE_ZIP_TEST_PACKAGE '*') -DestinationPath $env:EDGE_ZIP_TEST_DEST -CompressionLevel Optimal
"#;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_powershell_command(fixture_script),
        ])
        .env("EDGE_ZIP_TEST_PACKAGE", &package)
        .env("EDGE_ZIP_TEST_DEST", &zip)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "disposable ZIP fixture build failed: {}",
        bounded_privileged_child_evidence(&output.stdout, &output.stderr)
    );
    (zip, expected_installer)
}

#[cfg(windows)]
#[test]
fn native_offline_zip_proof_uses_real_rust_child_and_rejects_all_mismatches() {
    // No mocked PowerShell invocation: run this on the native Windows
    // candidate runner, using the exact Rust -> powershell.exe argv/env.
    // The root deliberately contains Unicode to exercise path encoding.
    let root = offline_test_root("zip-unicode-кириллица");
    let (zip, packaged) = create_zip_identity_fixture(&root, true);
    if let Err(err) = require_offline_bootstrap_installer_archive_identity(&zip, &packaged) {
        panic!("positive native ZIP proof failed: {err}");
    }
    fs::write(&packaged, b"tampered packaged script").unwrap();
    let mismatch =
        require_offline_bootstrap_installer_archive_identity(&zip, &packaged).unwrap_err();
    assert!(mismatch.contains("COMPARE_DIGEST"), "{mismatch}");
    fs::remove_file(&packaged).unwrap();
    let missing =
        require_offline_bootstrap_installer_archive_identity(&zip, &packaged).unwrap_err();
    assert!(missing.contains("HASH_LOCAL_INSTALLER"), "{missing}");

    let empty_root = offline_test_root("zip-no-entry");
    let (no_entry, _) = create_zip_identity_fixture(&empty_root, false);
    let absent =
        require_offline_bootstrap_installer_archive_identity(&no_entry, &packaged).unwrap_err();
    assert!(absent.contains("FIND_UNIQUE_ENTRY"), "{absent}");

    let corrupt_zip = root.join("corrupt.zip");
    fs::write(&corrupt_zip, b"not-a-zip").unwrap();
    let corrupt =
        require_offline_bootstrap_installer_archive_identity(&corrupt_zip, &packaged).unwrap_err();
    assert!(corrupt.contains("OPEN_ZIP"), "{corrupt}");

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(empty_root);
}

#[cfg(windows)]
#[test]
fn encoded_powershell_command_survives_windows_command_quoting() {
    let probe = r#"
$ErrorActionPreference = 'Stop'
if ('embedded "quotes" and кириллица' -cne 'embedded "quotes" and кириллица') {
    throw 'argv encoding defect'
}
"#;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_powershell_command(probe),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn previous_snapshot_only_treats_missing_file_as_absence() {
    let root = offline_test_root("snapshot");
    let previous = root.join("previous.pb");
    assert!(snapshot_offline_previous(&previous).unwrap().is_none());
    fs::write(&previous, b"previous-exact").unwrap();
    assert_eq!(
        snapshot_offline_previous(&previous).unwrap(),
        Some(b"previous-exact".to_vec())
    );
    fs::remove_file(&previous).unwrap();
    fs::create_dir(&previous).unwrap();
    assert!(
        snapshot_offline_previous(&previous)
            .unwrap_err()
            .contains("OFFLINE_PREVIOUS_SNAPSHOT_BLOCKED")
    );
    assert!(previous.is_dir());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_pointer_restore_uses_verified_saved_bytes_even_when_current_torn() {
    let root = offline_test_root("torn-pointer");
    let current = root.join("current.pb");
    let previous = root.join("previous.pb");
    fs::write(&current, b"torn-current").unwrap();
    fs::write(&previous, b"new-previous").unwrap();
    restore_offline_authority_pointers(
        &root,
        b"verified-old-current",
        &Some(b"verified-old-previous".to_vec()),
    )
    .unwrap();
    assert_eq!(fs::read(&current).unwrap(), b"verified-old-current");
    assert_eq!(fs::read(&previous).unwrap(), b"verified-old-previous");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_pointer_restore_never_deletes_unknown_previous_or_replays_current() {
    let root = offline_test_root("unknown-previous");
    let current = root.join("current.pb");
    let previous = root.join("previous.pb");
    fs::write(&current, b"new-current").unwrap();
    fs::write(&previous, b"foreign-previous").unwrap();
    let err =
        restore_offline_authority_pointers(&root, b"verified-old-current", &None).unwrap_err();
    assert!(err.contains("OFFLINE_PREVIOUS_RESTORE_BLOCKED"));
    assert_eq!(fs::read(&current).unwrap(), b"new-current");
    assert_eq!(fs::read(&previous).unwrap(), b"foreign-previous");

    fs::write(&previous, b"verified-old-current").unwrap();
    restore_offline_authority_pointers(&root, b"verified-old-current", &None).unwrap();
    assert_eq!(fs::read(&current).unwrap(), b"verified-old-current");
    assert!(!previous.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_pointer_restore_blocks_unreadable_previous_before_current_rewrite() {
    let root = offline_test_root("read-error");
    let current = root.join("current.pb");
    let previous = root.join("previous.pb");
    fs::write(&current, b"torn-current").unwrap();
    fs::create_dir(&previous).unwrap();
    assert!(
        restore_offline_authority_pointers(&root, b"saved-current", &None)
            .unwrap_err()
            .contains("OFFLINE_PREVIOUS_RESTORE_BLOCKED")
    );
    assert_eq!(fs::read(&current).unwrap(), b"torn-current");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_bootstrap_identifiers_require_exact_lowercase_immutable_values() {
    let revision = "a".repeat(40);
    let digest = "b".repeat(64);
    assert!(offline_bootstrap_identifiers_valid(&revision, &digest));
    assert!(!offline_bootstrap_identifiers_valid(
        &revision[..39],
        &digest
    ));
    assert!(!offline_bootstrap_identifiers_valid(
        &revision,
        &digest[..63]
    ));
    assert!(!offline_bootstrap_identifiers_valid(
        &revision.to_uppercase(),
        &digest
    ));
    assert!(!offline_bootstrap_identifiers_valid(
        &revision,
        &format!("{}g", &digest[..63])
    ));
}

#[test]
fn offline_bootstrap_accepts_only_exact_stopped_native_mode_evidence() {
    assert!(
        require_offline_bootstrap_supported_source(
            "windows_datapath_mode=ProxyOnly\nscm_start_type=OnDemand\n"
        )
        .is_ok()
    );
    assert!(
        require_offline_bootstrap_supported_source(
            "windows_datapath_mode=ManagedTun\nscm_start_type=OnDemand\n"
        )
        .is_ok()
    );
    for bad in [
        "",
        "windows_datapath_mode=ProxyOnly\nscm_start_type=AutoStart\n",
        "windows_datapath_mode=ProxyOnly\n",
        "windows_datapath_mode=Other\nscm_start_type=OnDemand\n",
        "windows_datapath_mode=ProxyOnly\nwindows_datapath_mode=ManagedTun\nscm_start_type=OnDemand\n",
    ] {
        assert!(
            require_offline_bootstrap_supported_source(bad).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn offline_bootstrap_prebegin_blocks_legacy_request_signed_intent_and_uncertain_markers() {
    let root = offline_test_root("bootstrap-pending-gate");
    assert!(require_offline_bootstrap_quiescent(&root).is_ok());
    for relative in [
        "offline-bootstrap-intent-v1",
        "exchange/requests/request.pb",
        "exchange/requests/host-intent.pb",
        "current.pb.new",
        "previous.pb.new",
        "offline-recovery-proof.pb",
    ] {
        let pending = root.join(relative);
        fs::create_dir_all(pending.parent().unwrap()).unwrap();
        fs::write(&pending, b"pending").unwrap();
        assert!(
            require_offline_bootstrap_quiescent(&root).is_err(),
            "must fail closed on {relative}"
        );
        fs::remove_file(&pending).unwrap();
    }
    fs::create_dir(root.join("offline-bootstrap-intent-v1")).unwrap();
    assert!(require_offline_bootstrap_quiescent(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn offline_legacy_intent_fixture() -> (Vec<u8>, String, String) {
    // Historical marker shape is immutable; the actual 242-byte October
    // sample is verified byte-for-byte in the separate known-hash test.
    let from = "a".repeat(64);
    let to = "b".repeat(64);
    let revision = "c".repeat(40);
    let bytes = format!(
        "schema=sing-box.windows-offline-bootstrap/v1\\nfrom={from}\\nto={to}\\naccepted_revision={revision}\\n"
    )
    .replace("\\n", "\n")
    .into_bytes();
    let digest: String = ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    (bytes, digest, "d".repeat(64))
}

#[test]
fn old_offline_bootstrap_marker_exact_historical_sha_matches_independent_report() {
    let marker = format!(
        "schema=sing-box.windows-offline-bootstrap/v1\nfrom={}\nto={}\naccepted_revision={}\n",
        "15990b33ebb40a44d13a844d9d6462d9015bf995af0b46b858cd52e66512ea36",
        "e1c1d0f39d055a40612b5b813cc6579097d5a10586e5b6eea86778ea657365ce",
        "d35a0cddfa54933bfbd65bae1c9a2b76d0526baf",
    );
    assert_eq!(marker.len(), 242);
    let digest = ring::digest::digest(&ring::digest::SHA256, marker.as_bytes());
    let hex: String = digest.as_ref().iter().map(|v| format!("{v:02x}")).collect();
    assert_eq!(
        hex,
        "bf7a091a4c3b0a61ead3d3cf1388f599baeed8803c5f1edfcd0289029e53327b"
    );
}

#[test]
fn retained_historical_begin_requires_exact_two_pins_and_never_claims_terminal() {
    let root = offline_test_root("retained-historical");
    let (bytes, digest, installed) = offline_legacy_intent_fixture();
    let path = root.join("offline-bootstrap-intent-v1");
    fs::write(&path, &bytes).unwrap();
    assert!(require_offline_bootstrap_quiescent(&root).is_err());
    let pins = RetainedOfflineBootstrapSupersession {
        expected_intent_sha256: digest.clone(),
        expected_current_release_set_sha256: installed.clone(),
    };
    let decoded = inspect_retained_offline_bootstrap_intent(&root, &pins, &installed).unwrap();
    assert_eq!(decoded.original_bytes, bytes);
    assert_eq!(decoded.sha256, digest);
    assert_eq!(decoded.from, "a".repeat(64));
    assert_eq!(decoded.to, "b".repeat(64));
    assert_eq!(decoded.accepted_revision, "c".repeat(40));
    let mut bad = pins.clone();
    bad.expected_intent_sha256 = "0".repeat(64);
    assert!(
        inspect_retained_offline_bootstrap_intent(&root, &bad, &installed)
            .unwrap_err()
            .contains("SHA_MISMATCH")
    );
    bad = pins.clone();
    bad.expected_current_release_set_sha256 = "0".repeat(64);
    assert!(
        inspect_retained_offline_bootstrap_intent(&root, &bad, &installed)
            .unwrap_err()
            .contains("INSTALLED_RELEASE_DRIFT")
    );
    assert!(path.is_file());
    assert!(
        root.join(format!("offline-bootstrap-intent-v1.historical-{digest}"))
            .is_file()
            == false
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn disabled_retained_begin_admits_both_historical_endpoints_but_never_replays() {
    let old_from = "a".repeat(64);
    let old_to = "b".repeat(64);
    let old_revision = "c".repeat(40);
    let new_revision = "d".repeat(40);
    let new_release = "e".repeat(64);
    let retained = VerifiedRetainedOfflineBootstrap {
        original_bytes: Vec::new(),
        sha256: "f".repeat(64),
        from: old_from.clone(),
        to: old_to.clone(),
        accepted_revision: old_revision.clone(),
    };
    // Compensated UNKNOWN may leave its old source installed.
    assert!(
        require_distinct_offline_bootstrap_successor(
            &retained,
            &old_from,
            &new_revision,
            &new_release
        )
        .is_ok()
    );
    // Physical October handoff: old to=... is already active. This is NOT
    // proof of old terminal SUCCESS, only permission for a distinct successor.
    assert!(
        require_distinct_offline_bootstrap_successor(
            &retained,
            &old_to,
            &new_revision,
            &new_release
        )
        .is_ok()
    );
    for (installed, revision, next) in [
        ("f".repeat(64), new_revision.clone(), new_release.clone()),
        (old_from.clone(), old_revision.clone(), new_release.clone()),
        (old_to.clone(), old_revision.clone(), new_release.clone()),
        (old_from.clone(), new_revision.clone(), old_to.clone()),
        (old_to.clone(), new_revision.clone(), old_from.clone()),
        (old_to.clone(), new_revision.clone(), old_to.clone()),
        (old_to.clone(), new_revision.clone(), "bad".into()),
    ] {
        let result =
            require_distinct_offline_bootstrap_successor(&retained, &installed, &revision, &next);
        assert!(
            result.unwrap_err().contains("NOT_DISTINCT_NO_REPLAY"),
            "retained operation admitted an unrelated/replayed successor"
        );
    }
    let forged = VerifiedRetainedOfflineBootstrap {
        from: old_to.clone(),
        ..retained
    };
    assert!(require_distinct_offline_bootstrap_successor(
        &forged,
        &old_to,
        &new_revision,
        &new_release,
    ).is_err());
}

#[test]
fn historical_begin_supersession_preserves_exact_bytes_and_replay_is_blocked() {
    let root = offline_test_root("historical-supersede");
    let (bytes, digest, installed) = offline_legacy_intent_fixture();
    let marker = root.join("offline-bootstrap-intent-v1");
    fs::write(&marker, &bytes).unwrap();
    let pins = RetainedOfflineBootstrapSupersession {
        expected_intent_sha256: digest.clone(),
        expected_current_release_set_sha256: installed.clone(),
    };
    archive_retained_offline_bootstrap_intent(&root, &pins, &installed).unwrap();
    let archive = root.join(format!("offline-bootstrap-intent-v1.historical-{digest}"));
    assert_eq!(fs::read(&archive).unwrap(), bytes);
    assert!(!marker.exists());
    // A crash NOW (after removing the old name, before the new BEGIN) must
    // never appear as a clean bootstrap window.
    assert!(
        require_offline_bootstrap_quiescent(&root)
            .unwrap_err()
            .contains("historical supersession record exists")
    );
    assert!(archive_retained_offline_bootstrap_intent(&root, &pins, &installed).is_err());
    // The next operation owns a NEW exclusive BEGIN, never a replay of the old one.
    let mut first_use = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .unwrap();
    first_use.write_all(b"fresh-durable-BEGIN").unwrap();
    first_use.sync_all().unwrap();
    assert!(require_offline_bootstrap_quiescent(&root).is_err());
    assert_eq!(fs::read(&archive).unwrap(), bytes);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn historical_handoff_interruption_never_admits_replay_with_or_without_old_name() {
    let root = offline_test_root("historical-crash-gap");
    let (bytes, digest, installed) = offline_legacy_intent_fixture();
    let original = root.join("offline-bootstrap-intent-v1");
    let archive = root.join(format!("offline-bootstrap-intent-v1.historical-{digest}"));
    fs::write(&original, &bytes).unwrap();
    let pins = RetainedOfflineBootstrapSupersession {
        expected_intent_sha256: digest.clone(),
        expected_current_release_set_sha256: installed.clone(),
    };
    // Crash just after exclusive hard_link: two names, same bytes.
    fs::hard_link(&original, &archive).unwrap();
    assert_eq!(fs::read(&archive).unwrap(), fs::read(&original).unwrap());
    assert!(require_offline_bootstrap_quiescent(&root).is_err());
    assert!(archive_retained_offline_bootstrap_intent(&root, &pins, &installed).is_err());
    // Crash after unlinking historical name but BEFORE fresh create_new BEGIN.
    fs::remove_file(&original).unwrap();
    assert!(!original.exists());
    assert_eq!(fs::read(&archive).unwrap(), bytes);
    let gate = require_offline_bootstrap_quiescent(&root).unwrap_err();
    assert!(
        gate.contains("historical supersession record exists"),
        "{gate}"
    );
    assert!(archive_retained_offline_bootstrap_intent(&root, &pins, &installed).is_err());
    // A case variant is also protected (NTFS filename comparisons are case-insensitive).
    fs::rename(
        &archive,
        root.join(format!("OFFLINE-BOOTSTRAP-INTENT-V1.HISTORICAL-{digest}")),
    )
    .unwrap();
    assert!(require_offline_bootstrap_quiescent(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn historical_intent_reconciliation_refuses_malformed_marker_other_pending_and_archive_collision() {
    let root = offline_test_root("historical-negative");
    let (bytes, digest, installed) = offline_legacy_intent_fixture();
    let marker = root.join("offline-bootstrap-intent-v1");
    let pins = RetainedOfflineBootstrapSupersession {
        expected_intent_sha256: digest.clone(),
        expected_current_release_set_sha256: installed.clone(),
    };
    fs::write(&marker, b"not canonical").unwrap();
    assert!(inspect_retained_offline_bootstrap_intent(&root, &pins, &installed).is_err());
    fs::write(&marker, &bytes).unwrap();
    fs::create_dir_all(root.join("exchange/requests")).unwrap();
    fs::write(root.join("exchange/requests/host-intent.pb"), b"pending").unwrap();
    assert!(archive_retained_offline_bootstrap_intent(&root, &pins, &installed).is_err());
    assert!(marker.exists());
    fs::remove_file(root.join("exchange/requests/host-intent.pb")).unwrap();
    let archive = root.join(format!("offline-bootstrap-intent-v1.historical-{digest}"));
    fs::write(&archive, b"foreign history").unwrap();
    assert!(archive_retained_offline_bootstrap_intent(&root, &pins, &installed).is_err());
    assert_eq!(fs::read(&archive).unwrap(), b"foreign history");
    assert_eq!(fs::read(&marker).unwrap(), bytes);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_bootstrap_disabled_phase_refuses_any_new_request() {
    let root = offline_test_root("bootstrap-disabled-gate");
    assert!(require_offline_bootstrap_request_queue_empty(&root).is_ok());
    for relative in [
        "exchange/requests/request.pb",
        "exchange/requests/host-intent.pb",
    ] {
        let request = root.join(relative);
        fs::create_dir_all(request.parent().unwrap()).unwrap();
        fs::write(&request, b"pending").unwrap();
        assert!(require_offline_bootstrap_request_queue_empty(&root).is_err());
        fs::remove_file(&request).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn offline_release_handoff_refuses_running_scm_any_child_tun_or_wrong_owner() {
    assert!(offline_handoff_gate(true, true, true, true).is_ok());
    for (stopped, zero_process, no_tun, exact_owner) in [
        (false, true, true, true),
        (true, false, true, true),
        (true, true, false, true),
        (true, true, true, false),
        (false, false, false, false),
    ] {
        assert!(
            offline_handoff_gate(stopped, zero_process, no_tun, exact_owner)
                .unwrap_err()
                .contains("OFFLINE_HANDOFF_BLOCKED")
        );
    }
}

#[test]
fn offline_release_operations_have_dedicated_wire_numbers() {
    assert_eq!(
        WindowsPrivilegedOperation::OfflineActivateRelease as i32,
        12
    );
    assert_eq!(
        WindowsPrivilegedOperation::OfflineRollbackPreviousRelease as i32,
        13
    );
    for operation in [
        WindowsPrivilegedOperation::OfflineActivateRelease,
        WindowsPrivilegedOperation::OfflineRollbackPreviousRelease,
    ] {
        let req = WindowsPrivilegedRequest {
            schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
            request_id: "offline-exact-test".to_owned(),
            operation: operation as i32,
            accepted_revision: Some("a".repeat(40)),
            release_set_sha256: Some("b".repeat(64)),
            credential_generation: None,
            credential_transition_action: None,
            initial_commit_intent_sha256: None,
            initial_commit_slot: None,
            initial_recovery_intent_sha256: None,
            initial_candidate_sha256: None,
            existing_join_vm_candidate_sha256: None,
            existing_join_windows_active_sha256: None,
            existing_join_windows_candidate_sha256: None,
            existing_join_intent_sha256: None,
            existing_join_slot: None,
        };
        let encoded = encode_windows_privileged_request(&req).unwrap();
        assert_eq!(
            decode_windows_privileged_request(&encoded)
                .unwrap()
                .operation,
            operation as i32
        );
        assert_eq!(privileged_wait_secs(&req), PRIVILEGED_ACTIVATE_WAIT_SECS);
        // An offline mutation cannot be re-observed as a successful
        // normal activation without exact stopped SCM and owner proof.
        assert!(activation_matches_request(Path::new("__absent__"), &req).is_none());
    }
}

async fn test_route_restore(
    failed_route: Option<&'static str>,
    failed_restore: bool,
) -> (Result<(), String>, Vec<String>) {
    use std::sync::{Arc, Mutex};

    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let check_events = Arc::clone(&events);
    let restore_events = Arc::clone(&events);
    let result = verify_routes_with_restore(
        "hysteria2-direct".to_owned(),
        move |route, _warp| {
            let events = Arc::clone(&check_events);
            async move {
                events.lock().unwrap().push(format!("verify:{route}"));
                if failed_route == Some(route) {
                    Err(format!("trace failed for {route}"))
                } else {
                    Ok(())
                }
            }
        },
        move |original| async move {
            restore_events
                .lock()
                .unwrap()
                .push(format!("restore:{original}"));
            if failed_restore {
                Err("restore read-back mismatch".to_owned())
            } else {
                Ok(())
            }
        },
    )
    .await;
    let observations = events.lock().unwrap().clone();
    (result, observations)
}

#[tokio::test]
async fn stage4b3_route_checks_restore_original_after_success() {
    let (result, events) = test_route_restore(None, false).await;
    assert!(result.is_ok());
    assert_eq!(
        events,
        [
            "verify:auto-direct-tunnel",
            "verify:auto-warp-tunnel",
            "restore:hysteria2-direct"
        ]
    );
}

#[tokio::test]
async fn stage4b3_route_checks_restore_after_first_route_error() {
    let (result, events) = test_route_restore(Some("auto-direct-tunnel"), false).await;
    assert!(result.unwrap_err().contains("original selector restored"));
    assert_eq!(
        events,
        ["verify:auto-direct-tunnel", "restore:hysteria2-direct"]
    );
}

#[tokio::test]
async fn stage4b3_route_checks_restore_after_second_route_error() {
    let (result, events) = test_route_restore(Some("auto-warp-tunnel"), false).await;
    assert!(result.unwrap_err().contains("original selector restored"));
    assert_eq!(
        events,
        [
            "verify:auto-direct-tunnel",
            "verify:auto-warp-tunnel",
            "restore:hysteria2-direct"
        ]
    );
}

#[tokio::test]
async fn stage4b3_restore_failure_keeps_error_without_stopping_runtime() {
    let (result, events) = test_route_restore(None, true).await;
    assert!(result.unwrap_err().contains("restoration is unverified"));
    assert_eq!(events.last().unwrap(), "restore:hysteria2-direct");
    let (result, events) = test_route_restore(Some("auto-direct-tunnel"), true).await;
    let error = result.unwrap_err();
    assert!(error.contains("trace failed"));
    assert!(error.contains("restoration is unverified"));
    assert_eq!(events.last().unwrap(), "restore:hysteria2-direct");
}

#[test]
fn stage4b3_unknown_live_selector_never_guesses_git_default() {
    let mut selector = SelectorState::placeholder();
    selector.desired_main_route = Some("auto-direct-tunnel".to_owned());
    assert!(
        observed_restore_route(selector)
            .unwrap_err()
            .contains("no mutation made")
    );
}

fn rollback_test_activation(
    install_root: &Path,
    release_name: &str,
    release_set_sha256: &str,
) -> WindowsActivationState {
    let release_dir = install_root.join("releases").join(release_name);
    let bin_dir = release_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();

    let controller = bin_dir.join("edge-controller.exe");
    let console = bin_dir.join("edge-console.exe");
    let sing_box = bin_dir.join("sing-box.exe");
    let diagnostic = bin_dir.join("edge-diagnostic.exe");
    std::fs::write(&controller, b"controller").unwrap();
    std::fs::write(&console, b"console").unwrap();
    std::fs::write(&sing_box, b"singbox").unwrap();
    std::fs::write(&diagnostic, b"diagnostic").unwrap();

    WindowsActivationState {
        schema_version: 1,
        release_set_sha256: release_set_sha256.to_owned(),
        source_revision: "1".repeat(40),
        release_dir: release_dir.to_string_lossy().into_owned(),
        controller_path: controller.to_string_lossy().into_owned(),
        console_path: console.to_string_lossy().into_owned(),
        sing_box_path: sing_box.to_string_lossy().into_owned(),
        diagnostic_path: diagnostic.to_string_lossy().into_owned(),
        controller_sha256: vec![
            193, 71, 33, 53, 177, 76, 119, 200, 190, 249, 142, 115, 247, 2, 8, 50, 95, 160, 220,
            241, 230, 189, 102, 138, 233, 179, 26, 156, 234, 41, 95, 231,
        ],
        console_sha256: vec![
            147, 216, 135, 76, 140, 134, 240, 252, 137, 61, 190, 21, 199, 101, 255, 160, 252, 211,
            66, 247, 152, 219, 246, 105, 224, 143, 140, 190, 9, 93, 35, 12,
        ],
        sing_box_sha256: vec![
            106, 175, 72, 98, 84, 64, 79, 91, 126, 34, 43, 199, 22, 96, 133, 30, 4, 200, 107, 148,
            52, 206, 132, 38, 56, 207, 20, 34, 143, 61, 95, 113,
        ],
        diagnostic_sha256: vec![
            90, 105, 94, 234, 91, 0, 163, 31, 138, 239, 125, 187, 137, 200, 247, 152, 250, 179,
            113, 36, 106, 193, 84, 154, 254, 132, 177, 100, 32, 112, 123, 153,
        ],
    }
}

fn rollback_test_root() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("edge-console-release-rollback-{unique}"));
    std::fs::create_dir_all(root.join("releases")).unwrap();
    root
}

#[test]
fn canonical_reinstall_authority_accepts_managed_tun() {
    require_supported_reinstall_authority().unwrap();
}

#[test]
fn stable_release_tools_follow_exact_activation() {
    let root = rollback_test_root();
    let activation = rollback_test_activation(&root, "previous", &"b".repeat(64));
    let stable_bin = root.join("bin");
    std::fs::create_dir_all(&stable_bin).unwrap();
    std::fs::write(stable_bin.join("edge-console.exe"), b"stale-console").unwrap();
    std::fs::write(stable_bin.join("edge-diagnostic.exe"), b"stale-diagnostic").unwrap();

    sync_stable_windows_release_tools(&root, &activation).unwrap();

    assert_eq!(
        std::fs::read(stable_bin.join("edge-console.exe")).unwrap(),
        std::fs::read(&activation.console_path).unwrap()
    );
    assert_eq!(
        std::fs::read(stable_bin.join("edge-diagnostic.exe")).unwrap(),
        std::fs::read(&activation.diagnostic_path).unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn previous_release_rollback_preflight_accepts_only_verified_previous_pb() {
    let root = rollback_test_root();
    let current = rollback_test_activation(&root, "current", &"a".repeat(64));
    let previous = rollback_test_activation(&root, "previous", &"b".repeat(64));
    std::fs::write(
        root.join("current.pb"),
        encode_windows_activation_state(&current).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("previous.pb"),
        encode_windows_activation_state(&previous).unwrap(),
    )
    .unwrap();

    let (observed_current, observed_previous) = load_previous_release_rollback_pair(&root).unwrap();
    assert_eq!(observed_current.release_set_sha256, "a".repeat(64));
    assert_eq!(observed_previous.release_set_sha256, "b".repeat(64));

    std::fs::write(root.join("previous.pb"), b"not-protobuf").unwrap();
    assert!(load_previous_release_rollback_pair(&root).is_err());

    std::fs::remove_file(root.join("previous.pb")).unwrap();
    let error = load_previous_release_rollback_pair(&root).unwrap_err();
    assert!(error.contains("previous.pb is absent"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn previous_managed_tun_rollback_requires_exact_unchanged_authority_pair() {
    let root = rollback_test_root();
    let current = rollback_test_activation(&root, "current", &"a".repeat(64));
    let previous = rollback_test_activation(&root, "previous", &"b".repeat(64));
    let mut request = WindowsPrivilegedRequest {
        schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
        request_id: "rollback-test".to_owned(),
        operation: WindowsPrivilegedOperation::RollbackPreviousRelease as i32,
        accepted_revision: Some(current.source_revision.clone()),
        release_set_sha256: Some(previous.release_set_sha256.clone()),
        credential_generation: None,
        credential_transition_action: None,
        initial_commit_intent_sha256: None,
        initial_commit_slot: None,
        initial_recovery_intent_sha256: None,
        initial_candidate_sha256: None,
        existing_join_vm_candidate_sha256: None,
        existing_join_windows_active_sha256: None,
        existing_join_windows_candidate_sha256: None,
        existing_join_intent_sha256: None,
        existing_join_slot: None,
    };
    // The immutable authority pair is checked in both build modes.
    // Actual release rollback remains forbidden on first-install ProxyOnly.
    require_exact_rollback_authority_pair(&request, &current, &previous).unwrap();
    let compiled_mode = canonical_production_desired_state()
        .unwrap()
        .windows_datapath_mode;
    if compiled_mode == WindowsDatapathMode::ManagedTun as i32 {
        require_managed_tun_rollback_pair(&request, &current, &previous).unwrap();
    } else {
        assert_eq!(compiled_mode, WindowsDatapathMode::ProxyOnly as i32);
        assert!(
            require_managed_tun_rollback_pair(&request, &current, &previous)
                .unwrap_err()
                .contains("non-ManagedTun")
        );
    }

    request.release_set_sha256 = Some("c".repeat(64));
    assert!(
        require_exact_rollback_authority_pair(&request, &current, &previous)
            .unwrap_err()
            .contains("authority changed")
    );
    request.release_set_sha256 = Some(previous.release_set_sha256.clone());
    request.accepted_revision = Some("f".repeat(40));
    assert!(
        require_exact_rollback_authority_pair(&request, &current, &previous)
            .unwrap_err()
            .contains("authority changed")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn previous_release_rollback_preflight_rejects_same_release() {
    let root = rollback_test_root();
    let current = rollback_test_activation(&root, "current", &"c".repeat(64));
    let previous = rollback_test_activation(&root, "previous", &"c".repeat(64));
    std::fs::write(
        root.join("current.pb"),
        encode_windows_activation_state(&current).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("previous.pb"),
        encode_windows_activation_state(&previous).unwrap(),
    )
    .unwrap();

    let error = load_previous_release_rollback_pair(&root).unwrap_err();
    assert!(error.contains("same ReleaseSet"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn formats_operation_lifecycle_labels() {
    assert_eq!(
        lifecycle_status_label(edge_shared_types::OperationLifecycleStatus::Running as i32),
        "running"
    );
    assert_eq!(lifecycle_status_label(99), "unknown");
}

#[test]
fn resolves_install_root_from_immutable_release_console_path() {
    let root = PathBuf::from("install-root");
    let executable = root
        .join("releases")
        .join("release-set")
        .join("bin")
        .join("edge-console.exe");

    assert_eq!(installed_root_from_executable(&executable).unwrap(), root);
}

#[test]
fn rejects_obsolete_root_bin_console_layout() {
    let executable = PathBuf::from("install-root")
        .join("bin")
        .join("edge-console.exe");

    let error = installed_root_from_executable(&executable).unwrap_err();
    assert!(error.to_string().contains("releases"));
}

#[test]
fn builds_canonical_windows_runtime_state_from_client_only_env() {
    let values = std::collections::BTreeMap::from([
        ("EDGE_WINDOWS_DEPLOYMENT_LABEL", "production".to_owned()),
        ("EDGE_WINDOWS_INSTANCE_ID", "instance-1".to_owned()),
        ("EDGE_WINDOWS_SERVER_IP", "203.0.113.10".to_owned()),
        ("EDGE_WINDOWS_DIRECT_DOMAIN", "edge.example.com".to_owned()),
        ("EDGE_WINDOWS_DIRECT_HY2_PORT", "8443".to_owned()),
        ("HY2_PASSWORD", "direct-password".to_owned()),
        ("EDGE_WINDOWS_DIRECT_VLESS_PORT", "443".to_owned()),
        (
            "VLESS_UUID",
            "00000000-0000-4000-8000-000000000001".to_owned(),
        ),
        ("REALITY_PUBLIC_KEY", "direct-public-key".to_owned()),
        ("REALITY_SHORT_ID", "a1b2c3d4".to_owned()),
        ("EDGE_WINDOWS_WARP_DOMAIN", "edge.example.com".to_owned()),
        ("EDGE_WINDOWS_WARP_HY2_PORT", "9444".to_owned()),
        ("HY2_WARP_PASSWORD", "warp-password".to_owned()),
        ("EDGE_WINDOWS_WARP_VLESS_PORT", "5443".to_owned()),
        (
            "VLESS_WARP_UUID",
            "00000000-0000-4000-8000-000000000002".to_owned(),
        ),
        ("REALITY_WARP_PUBLIC_KEY", "warp-public-key".to_owned()),
        ("REALITY_WARP_SHORT_ID", "b1c2d3e4".to_owned()),
    ]);
    let state = windows_runtime_state_from_provision_env(|name| values.get(name).cloned()).unwrap();
    assert_eq!(state.schema_version, 1);
    assert_eq!(state.instance_id, "instance-1");
    assert_eq!(state.server_ip, "203.0.113.10");
    assert_eq!(state.direct.as_ref().unwrap().hy2_port, 8443);
    assert_eq!(state.warp.as_ref().unwrap().vless_port, 5443);
    assert!(encode_windows_runtime_state(&state).is_ok());
}

#[test]
fn provisioning_requires_every_client_secret_but_no_server_private_key() {
    let values = std::collections::BTreeMap::from([
        ("EDGE_WINDOWS_INSTANCE_ID", "instance-1".to_owned()),
        ("EDGE_WINDOWS_SERVER_IP", "203.0.113.10".to_owned()),
        ("EDGE_WINDOWS_DIRECT_DOMAIN", "edge.example.com".to_owned()),
        ("EDGE_WINDOWS_DIRECT_HY2_PORT", "8443".to_owned()),
        ("HY2_PASSWORD", "direct-password".to_owned()),
        ("EDGE_WINDOWS_DIRECT_VLESS_PORT", "443".to_owned()),
        (
            "VLESS_UUID",
            "00000000-0000-4000-8000-000000000001".to_owned(),
        ),
        ("REALITY_PUBLIC_KEY", "direct-public-key".to_owned()),
        ("REALITY_SHORT_ID", "a1b2c3d4".to_owned()),
        ("EDGE_WINDOWS_WARP_DOMAIN", "edge.example.com".to_owned()),
        ("EDGE_WINDOWS_WARP_HY2_PORT", "9444".to_owned()),
        ("HY2_WARP_PASSWORD", "warp-password".to_owned()),
        ("EDGE_WINDOWS_WARP_VLESS_PORT", "5443".to_owned()),
        (
            "VLESS_WARP_UUID",
            "00000000-0000-4000-8000-000000000002".to_owned(),
        ),
        ("REALITY_WARP_PUBLIC_KEY", "warp-public-key".to_owned()),
    ]);
    let err =
        windows_runtime_state_from_provision_env(|name| values.get(name).cloned()).unwrap_err();
    assert!(err.contains("REALITY_WARP_SHORT_ID"));
    assert!(!err.contains("PRIVATE_KEY"));
    assert!(!err.contains("PROXY_PASSWORD"));
}

#[test]
fn redacts_sensitive_runtime_evidence_tokens() {
    let redacted = redact_runtime_evidence(
        "uuid=00000000-0000-4000-8000-000000000001 short=0011223344556677 password=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef host=miu.alegria.by",
    );
    assert!(!redacted.contains("00000000-0000-4000-8000-000000000001"));
    assert!(!redacted.contains("0011223344556677"));
    assert!(!redacted.contains("0123456789abcdef0123456789abcdef"));
    assert!(redacted.contains("<redacted-uuid>"));
    assert!(redacted.contains("<redacted-hex>"));
    assert!(redacted.contains("miu.alegria.by"));
}

#[test]
fn privileged_activation_has_operation_specific_wait_budget() {
    let activate = WindowsPrivilegedRequest {
        schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
        request_id: "activate".to_owned(),
        operation: WindowsPrivilegedOperation::ActivateRelease as i32,
        accepted_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
        release_set_sha256: Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        ),
        credential_generation: None,
        credential_transition_action: None,
        initial_commit_intent_sha256: None,
        initial_commit_slot: None,
        initial_recovery_intent_sha256: None,
        initial_candidate_sha256: None,
        existing_join_vm_candidate_sha256: None,
        existing_join_windows_active_sha256: None,
        existing_join_windows_candidate_sha256: None,
        existing_join_intent_sha256: None,
        existing_join_slot: None,
    };
    let ping = WindowsPrivilegedRequest {
        schema_version: PRIVILEGED_REQUEST_SCHEMA_VERSION,
        request_id: "ping".to_owned(),
        operation: WindowsPrivilegedOperation::Ping as i32,
        accepted_revision: None,
        release_set_sha256: None,
        credential_generation: None,
        credential_transition_action: None,
        initial_commit_intent_sha256: None,
        initial_commit_slot: None,
        initial_recovery_intent_sha256: None,
        initial_candidate_sha256: None,
        existing_join_vm_candidate_sha256: None,
        existing_join_windows_active_sha256: None,
        existing_join_windows_candidate_sha256: None,
        existing_join_intent_sha256: None,
        existing_join_slot: None,
    };

    assert_eq!(
        privileged_wait_secs(&activate),
        PRIVILEGED_ACTIVATE_WAIT_SECS
    );
    assert_eq!(privileged_wait_secs(&ping), PRIVILEGED_SHORT_WAIT_SECS);
    assert!(PRIVILEGED_ACTIVATE_WAIT_SECS > PRIVILEGED_SHORT_WAIT_SECS);
}

#[test]
fn runtime_evidence_exchange_failure_has_one_safe_correlated_result() {
    let safe = unproven_runtime_evidence("123456789-10");
    assert!(safe.contains("request_id=123456789-10"));
    assert!(safe.contains("status=UNPROVEN"));
    assert!(safe.contains("error_class=SYSTEM_RESULT_NOT_OBSERVED"));
    assert!(safe.contains("operation_outcome=UNKNOWN_NO_REPLAY"));
    assert!(!safe.contains("status=PASS"));
    assert!(!safe.contains("credential_mutations=0"));
}

#[test]
fn privileged_child_failure_evidence_is_bounded_and_secret_safe() {
    let stdout = b"source_revision=0123456789abcdef0123456789abcdef01234567\n";
    let stderr = format!(
        "Invoke-WebRequest failed token={} url=https://example.invalid/path\n{}",
        "abcdef0123456789abcdef0123456789",
        "download failed ".repeat(200)
    );
    let detail = bounded_privileged_child_evidence(stdout, stderr.as_bytes());

    assert!(detail.len() <= PRIVILEGED_CHILD_EVIDENCE_MAX_BYTES);
    assert!(!detail.chars().any(|ch| ch.is_control()));
    assert!(!detail.contains("0123456789abcdef0123456789abcdef01234567"));
    assert!(!detail.contains("abcdef0123456789abcdef0123456789"));

    let result = WindowsPrivilegedResult {
        schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
        request_id: "installer-evidence-test".to_owned(),
        success: false,
        code: "PRIVILEGED_OPERATION_FAILED".to_owned(),
        detail,
        active_release_set_sha256: None,
    };
    assert!(encode_windows_privileged_result(&result).is_ok());
}

#[test]
fn initial_windows_proof_refuses_active_or_incomplete_local_state() {
    assert!(initial_windows_credential_eligibility(false, false, false).is_ok());
    assert!(
        initial_windows_credential_eligibility(true, false, false)
            .unwrap_err()
            .contains("incomplete v2 credential store")
    );
    assert!(
        initial_windows_credential_eligibility(false, true, false)
            .unwrap_err()
            .contains("managed runtime state")
    );
    assert!(initial_windows_credential_eligibility(true, true, true).is_err());
    assert!(
        initial_windows_credential_eligibility(false, false, true)
            .unwrap_err()
            .contains("rendered sing-box config")
    );
}

#[test]
fn persistent_windows_cursor_proof_refuses_torn_store_without_guessing_absence() {
    let root = offline_test_root("first-use-cursor");
    assert_eq!(
        read_bounded_windows_credential_cursor(&root).unwrap(),
        "credential_cursor=ABSENT"
    );
    let store = windows_credential_store_path(&root);
    fs::create_dir_all(&store).unwrap();
    assert!(
        read_bounded_windows_credential_cursor(&root)
            .unwrap_err()
            .contains("no durable cursor")
    );
    fs::write(store.join("state.pb"), b"corrupt").unwrap();
    assert!(read_bounded_windows_credential_cursor(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_credential_status_is_not_a_remote_origin_proof() {
    let active = "credential_cursor=VALID;credential_active_present=true;credential_candidate_present=false;credential_active_generation=7;credential_active_slot=B";
    assert_eq!(
        classify_windows_credential_lifecycle(
            active,
            "PRESENT",
            "PRESENT",
            "PRESENT_NONEMPTY_UNVERIFIED"
        ),
        ("EXISTING_ACTIVE_UNVERIFIED", "READ_ONLY_ORIGIN_RECONCILE")
    );
    assert_eq!(
        classify_windows_credential_lifecycle(
            active,
            "ABSENT",
            "PRESENT",
            "PRESENT_NONEMPTY_UNVERIFIED"
        ),
        ("PARTIAL", "READ_ONLY_RECONCILE")
    );
    assert_eq!(
        classify_windows_credential_lifecycle(
            "credential_cursor=ABSENT",
            "ABSENT",
            "ABSENT",
            "PRESENT_NONEMPTY_UNVERIFIED"
        ),
        ("FRESH_LOCAL_ONLY", "JOURNAL_AUTHORIZATION_REQUIRED")
    );
    assert_eq!(
        classify_windows_credential_lifecycle(
            "credential_cursor=ABSENT",
            "PRESENT",
            "ABSENT",
            "PRESENT_NONEMPTY_UNVERIFIED"
        ),
        ("PARTIAL", "READ_ONLY_RECONCILE")
    );
    assert_eq!(
        classify_windows_credential_lifecycle(
            "credential_cursor=VALID;credential_active_present=false;credential_candidate_present=true",
            "ABSENT",
            "ABSENT",
            "PRESENT_NONEMPTY_UNVERIFIED"
        ),
        (
            "EXISTING_CANDIDATE_UNVERIFIED",
            "READ_ONLY_ORIGIN_RECONCILE"
        )
    );
    assert_eq!(
        classify_windows_credential_lifecycle(
            "credential_cursor=VALID;credential_active_present=true;credential_active_present=false;credential_candidate_present=false",
            "PRESENT",
            "PRESENT",
            "PRESENT_NONEMPTY_UNVERIFIED"
        ),
        ("PARTIAL", "READ_ONLY_RECONCILE")
    );
}

#[test]
fn first_use_recovery_proof_and_full_task_hashes_fit_bounded_result() {
    let tasks = format!(
        "tasks=EdgePlatformController|1|3|{},EdgePlatformReconcile|1|3|{},EdgePlatformShutdown|1|3|{},EdgePlatformPrivilegedDispatch|1|4|{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64)
    );
    let cursor = format!(
        "credential_cursor=VALID;credential_active_present=false;credential_candidate_present=true;credential_candidate_generation=38503639351;credential_candidate_slot=B;credential_previous_present=false;credential_active_generation=0;credential_active_slot=NONE;credential_active_sha256=ABSENT;credential_candidate_sha256={};credential_initial_commit_receipt_present=true;credential_initial_commit_intent_sha256={};credential_initial_recovery_receipt_present=false;credential_initial_recovery_intent_sha256=ABSENT",
        "e".repeat(64),
        "f".repeat(64),
    );
    let critical = format!(
        "runtime_evidence=BOUNDED_READ_ONLY;controller_service_error=ABSENT;process_classification=ABSENT;process_evidence_complete=true;process_count=0;managed_pid=ABSENT;managed_parent_pid=ABSENT;controller_pid=ABSENT;{tasks};external_owner_evidence=INCOMPLETE;external_count=0;{cursor};first_use_runtime=PRESENT;first_use_config=PRESENT;first_use_access_identity=PRESENT_NONEMPTY_UNVERIFIED"
    );
    assert!(
        critical.len() > 1024,
        "the original cap made initial recovery unobservable"
    );
    assert!(critical.len() <= RUNTIME_EVIDENCE_RESULT_MAX_BYTES);
    let result = WindowsPrivilegedResult {
        schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
        request_id: "exact-first-use-recovery-evidence".to_owned(),
        success: true,
        code: "RUNTIME_EVIDENCE_READ".to_owned(),
        detail: critical,
        active_release_set_sha256: None,
    };
    assert!(encode_windows_privileged_result(&result).is_ok());
}

#[test]
fn existing_line1_system_projection_requires_exact_worker_b_and_begin_receipt() {
    let begin = "a".repeat(64);
    let candidate = "b".repeat(64);
    let sample = format!(
        "status=PASS\ndetail=runtime_evidence=BOUNDED_READ_ONLY;credential_cursor=VALID;credential_origin=WORKER_OK;credential_active_present=true;credential_active_slot=A;credential_candidate_present=true;credential_candidate_slot=B;credential_candidate_sha256={candidate};credential_candidate_generation=203;credential_previous_present=false;credential_existing_join_prepare_receipt_present=true;credential_existing_join_receipt_present=false;credential_existing_join_prepare_begin_sha256={begin}\n"
    );
    assert_eq!(
        parse_existing_line1_system_result(&sample, 203, &candidate).unwrap(),
        begin
    );
    // Match the native SYSTEM runtime-evidence envelope, not an artificially
    // credential-only string. Windows OS/process/log metadata is not a
    // credential contract and must not block a valid authenticated B.
    let real_envelope = sample.replace(
        "credential_cursor=VALID;",
        "controller_service_error=ABSENT;process_classification=ABSENT;external_owner_evidence=BOUNDED_READ_ONLY;OS_LOG_TRUNCATED;credential_cursor=VALID;",
    ).replace(
        &format!("credential_existing_join_prepare_begin_sha256={begin}"),
        &format!("credential_existing_join_prepare_begin_sha256={begin};first_use_runtime=PRESENT;first_use_config=PRESENT;stderr_tail=unstructured;"),
    );
    assert_eq!(
        parse_existing_line1_system_result(&real_envelope, 203, &candidate).unwrap(),
        begin
    );
    // Irrelevant malformed OS fragments are allowed, but duplicate or
    // malformed required credential evidence must continue to fail closed.
    assert!(
        parse_existing_line1_system_result(
            &real_envelope.replace(
                "credential_candidate_slot=B;",
                "credential_candidate_slot=B;credential_candidate_slot=B;",
            ),
            203,
            &candidate,
        )
        .is_err()
    );
    assert!(
        parse_existing_line1_system_result(
            &real_envelope.replace("credential_origin=WORKER_OK", "credential_origin=UNPROVEN"),
            203,
            &candidate,
        )
        .is_err()
    );
    for invalid in [
        sample.replace("WORKER_OK", "UNPROVEN"),
        sample.replace("candidate_slot=B", "candidate_slot=A"),
        sample.replace(
            "prepare_receipt_present=true",
            "prepare_receipt_present=false",
        ),
        sample.replace("generation=203", "generation=204"),
        sample.replace("previous_present=false", "previous_present=true"),
        sample.replace(
            &format!("candidate_sha256={candidate}"),
            "candidate_sha256=ABSENT",
        ),
        sample.replace(&format!("begin_sha256={begin}"), "begin_sha256=ABSENT"),
        sample.replace("status=PASS", "status=PASS\nstatus=PASS"),
        sample.replace(
            "credential_candidate_slot=B;",
            "credential_candidate_slot=B;credential_candidate_slot=B;",
        ),
    ] {
        assert!(
            parse_existing_line1_system_result(&invalid, 203, &candidate).is_err(),
            "malformed or mismatched SYSTEM evidence must block Line1"
        );
    }
}

#[test]
fn critical_runtime_evidence_fits_without_truncating_owner_or_tasks() {
    let tasks = format!(
        "tasks=EdgePlatformController|1|3|{},EdgePlatformReconcile|1|3|{},EdgePlatformShutdown|1|3|{},EdgePlatformPrivilegedDispatch|1|4|{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64)
    );
    let external_owner = "external_owner_evidence=BOUNDED_READ_ONLY;external_pid=7464;external_exe=C:\\Users\\Bose\\AppData\\Local\\sing-box-vultr-dual\\runtime\\sing-box.exe;external_config=C:\\Users\\Bose\\temp\\sing-box\\win\\windows\\edge-dns-clean-vultr-dual.json;external_run_shape=true;external_exe_exists=true;external_config_exists=true;external_check=PASS;parent_pid=3792;parent_name=edge-controller.exe;parent_exe=C:\\Users\\Bose\\AppData\\Local\\edge-platform-win-target\\x86_64-pc-windows-msvc\\debug\\edge-controller.exe;startup_owner=OTHER_LIVE_PARENT;restore_preflight=PASS";
    let detail = format!("runtime_evidence=BOUNDED_READ_ONLY;{tasks};{external_owner}");
    assert!(detail.len() <= RUNTIME_EVIDENCE_RESULT_MAX_BYTES);
    assert!(detail.contains("EdgePlatformPrivilegedDispatch"));
    assert!(detail.contains("restore_preflight=PASS"));
    assert!(!detail.contains("[truncated]"));

    let result = WindowsPrivilegedResult {
        schema_version: PRIVILEGED_RESULT_SCHEMA_VERSION,
        request_id: "runtime-evidence-test".to_owned(),
        success: true,
        code: "RUNTIME_EVIDENCE_READ".to_owned(),
        detail,
        active_release_set_sha256: None,
    };
    assert!(encode_windows_privileged_result(&result).is_ok());
}
