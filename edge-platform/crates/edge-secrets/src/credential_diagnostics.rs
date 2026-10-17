//! One native, bounded, non-secret observation shared by Fleet Windows/VM doctors.
//! An owner-local cursor cannot establish the terminal status of a two-owner
//! transaction. It never authorizes COMMIT, ABORT, replay, or GC of a bundle.
use crate::CredentialStore;
use edge_shared_types::{CredentialProjectionKind, LocalCredentialState};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSafetyObservation {
    pub state: &'static str,
    pub cursor_present: Option<bool>,
    pub active_generation: Option<u64>,
    pub candidate_generation: Option<u64>,
    pub previous_generation: Option<u64>,
    pub windows_prepare_receipt: Option<bool>,
    pub local_join_receipt: Option<bool>,
}

impl CredentialSafetyObservation {
    fn unknown() -> Self {
        Self {
            state: "UNKNOWN_NO_REPLAY",
            cursor_present: None,
            active_generation: None,
            candidate_generation: None,
            previous_generation: None,
            windows_prepare_receipt: None,
            local_join_receipt: None,
        }
    }

    fn classify(
        projection: CredentialProjectionKind,
        state: Option<&LocalCredentialState>,
        prepare: Option<bool>,
        join: bool,
    ) -> Self {
        let active_generation = state.and_then(|v| v.active.as_ref().map(|r| r.generation));
        let candidate_generation = state.and_then(|v| v.candidate.as_ref().map(|r| r.generation));
        let previous_generation = state.and_then(|v| v.previous.as_ref().map(|r| r.generation));
        let active = active_generation.is_some();
        let candidate = candidate_generation.is_some();
        let previous = previous_generation.is_some();
        let verdict = match projection {
            CredentialProjectionKind::Windows => match (active, candidate, previous, prepare, join) {
                (true, true, false, Some(true), false) => "WINDOWS_BEGIN_BOUND_PARTIAL_NO_REPLAY",
                (true, true, false, Some(false), false) => "WINDOWS_CANDIDATE_UNBOUND_NO_REPLAY",
                (true, false, false, Some(false), false) => "WINDOWS_ACTIVE_LOCAL_ONLY",
                (true, false, true, Some(true), true) => "LOCAL_JOIN_CROSS_OWNER_UNPROVEN",
                _ => "UNKNOWN_NO_REPLAY",
            },
            CredentialProjectionKind::Vm => match (active, candidate, previous, join) {
                (false, true, false, false) => "VM_CANDIDATE_CROSS_OWNER_UNPROVEN",
                (true, false, false, false) => "VM_ACTIVE_LOCAL_ONLY",
                (true, false, false, true) => "LOCAL_JOIN_CROSS_OWNER_UNPROVEN",
                _ => "UNKNOWN_NO_REPLAY",
            },
            CredentialProjectionKind::Unspecified => "UNKNOWN_NO_REPLAY",
        };
        Self {
            state: verdict,
            cursor_present: Some(state.is_some()),
            active_generation,
            candidate_generation,
            previous_generation,
            windows_prepare_receipt: prepare,
            local_join_receipt: Some(join),
        }
    }

    pub fn report_lines(&self) -> Vec<String> {
        fn generation(value: Option<u64>) -> String {
            value.map_or_else(|| "UNPROVEN".to_owned(), |v| v.to_string())
        }
        fn boolean(value: Option<bool>) -> &'static str {
            match value {
                Some(true) => "true",
                Some(false) => "false",
                None => "UNPROVEN",
            }
        }
        vec![
            format!("credential_safety_state={}", self.state),
            format!("credential_cursor_present={}", boolean(self.cursor_present)),
            format!("credential_active_generation={}", generation(self.active_generation)),
            format!("credential_candidate_generation={}", generation(self.candidate_generation)),
            format!("credential_previous_generation={}", generation(self.previous_generation)),
            format!(
                "credential_windows_prepare_receipt={}",
                boolean(self.windows_prepare_receipt)
            ),
            format!("credential_local_join_receipt={}", boolean(self.local_join_receipt)),
            "credential_pair_terminal=UNPROVEN".to_owned(),
            "credential_replay_authorized=false".to_owned(),
            "credential_mutations=0".to_owned(),
        ]
    }
}

/// An inability to read a private cursor or a torn one-shot receipt is
/// UNKNOWN, not absence. Never print a secret, raw bundle, or filesystem
/// error to an unprivileged GitHub diagnostic log.
pub fn observe_credential_safety(
    root: &Path,
    projection: CredentialProjectionKind,
) -> CredentialSafetyObservation {
    let result = (|| {
        let store = CredentialStore::open_existing(root, projection)?;
        let Some(store) = store else {
            return Ok(CredentialSafetyObservation {
                state: "STORE_ABSENT_NO_MUTATION",
                cursor_present: Some(false),
                active_generation: None,
                candidate_generation: None,
                previous_generation: None,
                windows_prepare_receipt: None,
                local_join_receipt: None,
            });
        };
        let state = store.read_state()?;
        let prepare = if projection == CredentialProjectionKind::Windows {
            Some(store.read_windows_existing_join_prepare_receipt()?.is_some())
        } else {
            None
        };
        let join = store.read_existing_join_receipt()?.is_some();
        Ok(CredentialSafetyObservation::classify(
            projection,
            state.as_ref(),
            prepare,
            join,
        ))
    })();
    result.unwrap_or_else(|_: String| CredentialSafetyObservation::unknown())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::{LocalCredentialBundleRef, LocalCredentialState};

    fn reference(generation: u64, slot: i32, byte: char) -> LocalCredentialBundleRef {
        LocalCredentialBundleRef {
            generation,
            slot,
            sha256: byte.to_string().repeat(64),
        }
    }

    fn state(projection: CredentialProjectionKind, candidate: bool) -> LocalCredentialState {
        LocalCredentialState {
            schema_version: 1,
            projection: projection as i32,
            active: if projection == CredentialProjectionKind::Windows {
                Some(reference(100, 1, 'a'))
            } else {
                None
            },
            candidate: candidate.then(|| reference(200, 2, 'b')),
            previous: None,
        }
    }

    #[test]
    fn windows_begin_bound_is_never_treated_as_terminal_abort_or_commit() {
        let snapshot = state(CredentialProjectionKind::Windows, true);
        let result = CredentialSafetyObservation::classify(
            CredentialProjectionKind::Windows,
            Some(&snapshot),
            Some(true),
            false,
        );
        assert_eq!(result.state, "WINDOWS_BEGIN_BOUND_PARTIAL_NO_REPLAY");
        assert!(result.report_lines().contains(&"credential_replay_authorized=false".to_owned()));
        assert!(result.report_lines().contains(&"credential_pair_terminal=UNPROVEN".to_owned()));
        assert!(!result.report_lines().join("\n").contains(&"a".repeat(64)));
        assert!(!result.report_lines().join("\n").contains(&"b".repeat(64)));
    }

    #[test]
    fn vm_candidate_is_unproven_even_with_a_complete_local_cursor() {
        let snapshot = state(CredentialProjectionKind::Vm, true);
        let result = CredentialSafetyObservation::classify(
            CredentialProjectionKind::Vm,
            Some(&snapshot),
            None,
            false,
        );
        assert_eq!(result.state, "VM_CANDIDATE_CROSS_OWNER_UNPROVEN");
        assert_eq!(result.candidate_generation, Some(200));
        assert_eq!(result.windows_prepare_receipt, None);
        assert_eq!(result.local_join_receipt, Some(false));
    }

    #[test]
    fn wrong_or_torn_local_receipts_can_never_indicate_pair_terminal() {
        let snapshot = state(CredentialProjectionKind::Windows, true);
        assert_eq!(
            CredentialSafetyObservation::classify(
                CredentialProjectionKind::Windows,
                Some(&snapshot),
                Some(false),
                true,
            )
            .state,
            "UNKNOWN_NO_REPLAY"
        );
        let unknown = CredentialSafetyObservation::unknown().report_lines().join("\n");
        assert!(unknown.contains("credential_cursor_present=UNPROVEN"));
        assert!(unknown.contains("credential_replay_authorized=false"));
    }
}
