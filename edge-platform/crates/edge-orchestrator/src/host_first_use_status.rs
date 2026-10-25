//! Read-only Git readiness for first-use VM lifecycle.
//! Git facts do not attest Cloudflare Access, provider CREATE or a native receipt.
use edge_shared_types::FleetHost;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GitStage {
    phase: &'static str,
    owner: &'static str,
    reason: &'static str,
    last_proven_step: &'static str,
    next_action: &'static str,
}

fn git_stage(worker_signer: bool, credential_pin: bool, receipt_pin: bool) -> GitStage {
    match (worker_signer, credential_pin, receipt_pin) {
        (false, _, _) => GitStage {
            phase: "BLOCKED",
            owner: "CLOUDFLARE_WORKER_SIGNER",
            reason: "HOST_VM_GIT_WORKER_SIGNER_REQUIRED",
            last_proven_step: "GIT_HOST_REGISTERED",
            next_action: "PIN_PUBLIC_WORKER_SIGNER",
        },
        (true, false, _) => GitStage {
            phase: "BLOCKED",
            owner: "FIRST_USE_CREDENTIAL_OWNER",
            reason: "HOST_VM_FIRST_USE_CREDENTIAL_GIT_REQUIRED",
            last_proven_step: "GIT_WORKER_SIGNER_PINNED_NOT_LIVE_ATTESTED",
            next_action: "PUBLISH_TYPED_VM_CREDENTIAL_AND_PIN_DIGEST",
        },
        (true, true, false) => GitStage {
            phase: "PREPARED_GIT_ONLY",
            owner: "VULTR_FIRST_USE_OWNER",
            reason: "PROVIDER_AND_WORKER_PREFLIGHT_REQUIRED",
            last_proven_step: "GIT_FIRST_USE_DIGEST_PINNED_NOT_WORKER_ATTESTED",
            next_action: "VERIFY_WORKER_ACCESS_AND_PROVIDER_PREFLIGHT",
        },
        (true, true, true) => GitStage {
            phase: "ENROLLED_GIT_ONLY",
            owner: "VM_NATIVE_ROOT_OWNER",
            reason: "SIGNED_NATIVE_OBSERVATION_REQUIRED",
            last_proven_step: "GIT_RECEIPT_PINNED_NOT_PHYSICAL_PROOF",
            next_action: "VERIFY_SIGNED_NATIVE_RECEIPT_AND_DESIRED",
        },
    }
}

pub(super) fn print_git_readiness(host: &FleetHost) -> Result<(), &'static str> {
    let signer = host.worker_authority_public_key.len();
    let receipt = host.native_receipt_public_key.len();
    if !matches!(signer, 0 | 32) || !matches!(receipt, 0 | 32) {
        return Err("HOST_VM_GIT_KEY_LENGTH_INVALID");
    }
    let stage = git_stage(
        signer == 32,
        host.vm_first_use_credential.is_some(),
        receipt == 32,
    );
    println!("host_first_use_evidence_scope=GIT_ONLY_NOT_PHYSICAL");
    println!("host_first_use_phase={}", stage.phase);
    println!("host_first_use_owner={}", stage.owner);
    println!("host_first_use_reason={}", stage.reason);
    println!("host_first_use_last_proven_step={}", stage.last_proven_step);
    println!("host_first_use_next_action={}", stage.next_action);
    println!("host_first_use_replay_allowed=false");
    println!("host_first_use_mutation_authorized=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_never_confuse_git_with_signed_physical_proof() {
        assert_eq!(
            git_stage(false, false, false).reason,
            "HOST_VM_GIT_WORKER_SIGNER_REQUIRED"
        );
        assert_eq!(
            git_stage(true, false, false).owner,
            "FIRST_USE_CREDENTIAL_OWNER"
        );
        assert_eq!(git_stage(true, true, false).phase, "PREPARED_GIT_ONLY");
        assert_eq!(git_stage(true, true, true).phase, "ENROLLED_GIT_ONLY");
        for signer in [false, true] {
            for credential in [false, true] {
                for receipt in [false, true] {
                    let stage = git_stage(signer, credential, receipt);
                    assert_ne!(stage.phase, "ACCEPTED");
                    assert_ne!(stage.next_action, "CREATE_VM_NOW");
                }
            }
        }
    }

    #[test]
    fn wrong_public_key_lengths_fail_closed() {
        let mut host = FleetHost::default();
        host.worker_authority_public_key = vec![42; 31];
        assert!(print_git_readiness(&host).is_err());
        host.worker_authority_public_key = vec![42; 32];
        host.native_receipt_public_key = vec![7; 31];
        assert!(print_git_readiness(&host).is_err());
    }
}
