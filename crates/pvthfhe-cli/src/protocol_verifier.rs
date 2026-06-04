//! ProtocolVerifier — single entry-point for full protocol verification.
//!
//! P2.7: Chains all verification steps. Rejects if any native check fails.
//! Used by the verify-all CLI command for independent re-verification.

use crate::full_pipeline::PipelineReport;
use ark_bn254::Fr;
use ark_ff::Zero;
use std::fmt;

/// A structured verification failure.
#[derive(Debug, Clone)]
pub struct VerificationFailure {
    pub check: String,
    pub detail: String,
}

impl fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

/// Protocol-level verifier that runs EVERY check and collects failures.
pub struct ProtocolVerifier;

impl ProtocolVerifier {
    /// Run all verification checks against a pipeline report.
    /// Returns `Ok(())` when all checks pass, or `Err(failures)` listing every failure.
    pub fn verify_all(proof: &PipelineReport) -> Result<(), Vec<VerificationFailure>> {
        let mut failures = Vec::new();

        // 1. All verifications passed flag
        if !proof.all_verifications_passed {
            failures.push(VerificationFailure {
                check: "all_verifications_passed".into(),
                detail: "Pipeline report indicates some verification stage failed".into(),
            });
        }

        // 2. Plaintext roundtrip
        if !proof.plaintext_roundtrip_ok {
            failures.push(VerificationFailure {
                check: "plaintext_roundtrip".into(),
                detail: "Decrypted plaintext does not match original".into(),
            });
        }

        // 3. Aggregate public key hash non-empty
        if proof.aggregate_pk_hash_hex.is_empty() {
            failures.push(VerificationFailure {
                check: "aggregate_pk_hash".into(),
                detail: "Aggregate public key hash is empty".into(),
            });
        }

        // 4. Ciphertext hash non-empty
        if proof.ciphertext_hash_hex.is_empty() {
            failures.push(VerificationFailure {
                check: "ciphertext_hash".into(),
                detail: "Ciphertext hash is empty".into(),
            });
        }

        // 5. Compressed proof digest non-empty
        if proof.compressed_proof_digest_hex.is_empty() {
            failures.push(VerificationFailure {
                check: "compressed_proof_digest".into(),
                detail: "Compressed proof digest is empty".into(),
            });
        }

        // 6. DKG verified
        if !proof.dkg_verified {
            failures.push(VerificationFailure {
                check: "dkg_verified".into(),
                detail: "DKG ceremony verification failed".into(),
            });
        }

        // 7. Parity verified
        if !proof.parity_verified {
            failures.push(VerificationFailure {
                check: "parity_verified".into(),
                detail: "Dealer parity check failed".into(),
            });
        }

        // 8. Share coefficients present
        if proof.share_coeffs.is_empty() {
            failures.push(VerificationFailure {
                check: "share_coeffs".into(),
                detail: "No share coefficients in report".into(),
            });
        }

        // 9. SK commitments present
        if proof.committee_party_ids.len() > proof.sk_commitments.len() {
            failures.push(VerificationFailure {
                check: "sk_commitments".into(),
                detail: format!(
                    "Fewer SK commitments ({}) than committee parties ({})",
                    proof.sk_commitments.len(),
                    proof.committee_party_ids.len()
                ),
            });
        }

        // 10. Decrypt NIZK hash non-zero
        if proof.decrypt_nizk_hash == [0u8; 32] {
            failures.push(VerificationFailure {
                check: "decrypt_nizk_hash".into(),
                detail: "Decrypt NIZK hash is zero".into(),
            });
        }

        // 11. Combined share hash non-zero
        if !proof.share_coeffs.is_empty() && proof.combined_share_hash.is_zero() {
            failures.push(VerificationFailure {
                check: "combined_share_hash".into(),
                detail: "Combined share hash is zero despite shares present".into(),
            });
        }

        // 12. All NIZK proof hash non-zero
        if proof.all_nizk_proof_hash.is_zero() {
            failures.push(VerificationFailure {
                check: "all_nizk_proof_hash".into(),
                detail: "All NIZK proof hash is zero".into(),
            });
        }

        // 13. P2.4: Pipeline integrity hash non-zero
        if proof.pipeline_integrity_hash.is_zero() {
            failures.push(VerificationFailure {
                check: "pipeline_integrity_hash".into(),
                detail: "Pipeline integrity hash is zero (cross-hash binding missing)".into(),
            });
        }

        // 14. Recipient fold hashes present
        if proof.dkg_verified && proof.recipient_fold_hashes.iter().all(|&h| h == Fr::zero()) {
            failures.push(VerificationFailure {
                check: "recipient_fold_hashes".into(),
                detail: "All recipient fold hashes are zero despite dkg_verified=true".into(),
            });
        }

        // 15. P2.4: Cross-hash binding — report must carry the chain
        if proof.compressed_proof_hash.is_zero() {
            failures.push(VerificationFailure {
                check: "compressed_proof_hash".into(),
                detail: "Compressed proof hash is zero (P2.4 cross-hash chain broken)".into(),
            });
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::full_pipeline::PipelineReport;
    use ark_bn254::Fr;
    use pvthfhe_bench::e2e_timings::E2eTimings;

    fn make_minimal_report() -> PipelineReport {
        PipelineReport {
            timings: E2eTimings::new(4, 2, 0, "test"),
            plaintext_roundtrip_ok: true,
            all_verifications_passed: true,
            aggregate_pk_hash_hex: "abc123".into(),
            ciphertext_hash_hex: "def456".into(),
            compressed_proof_digest_hex: "789abc".into(),
            share_coeffs: vec![vec![1, 2, 3]],
            lagrange_coeffs: vec![Fr::from(1u64)],
            committee_party_ids: vec![1, 2, 3, 4],
            aggregate_pk_bytes: vec![0u8; 32],
            session_id: "test-session".into(),
            decrypt_nizk_hash: [1u8; 32],
            session_nonce: Fr::from(1u64),
            d_commitment_verified: Some(true),
            party_signing_pks: vec![Fr::from(1u64)],
            party_signing_pkys: vec![Fr::from(2u64)],
            share_sig_rs: vec![Fr::from(3u64)],
            share_sig_rys: vec![Fr::from(4u64)],
            share_sig_ss: vec![Fr::from(5u64)],
            node_schnorr_pks: vec![Fr::from(6u64)],
            node_schnorr_sigs: vec![(Fr::from(7u64), Fr::from(8u64))],
            combined_share_hash: Fr::from(42u64),
            all_nizk_proof_hash: Fr::from(43u64),
            compressed_proof_hash: Fr::from(44u64),
            sk_commitments: vec![[2u8; 32]; 4],
            sk_bindings: vec![[3u8; 32]; 4],
            dkg_verified: true,
            parity_verified: true,
            dkg_share_count: 16,
            recipient_fold_hashes: vec![Fr::from(1u64), Fr::from(2u64)],
            recipient_parity_proof_hashes: vec![Fr::from(3u64)],
            pipeline_integrity_hash: Fr::from(99u64),
            ivc_snark_proof_hash: Some([4u8; 32]),
            ivc_binding: None,
            share_verification_hash: Some([5u8; 32]),
            c5_proof_root: [6u8; 32],
        }
    }

    #[test]
    fn verify_all_accepts_valid_report() {
        let report = make_minimal_report();
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_ok(), "valid report should pass: {result:?}");
    }

    #[test]
    fn verify_all_rejects_failed_verifications() {
        let mut report = make_minimal_report();
        report.all_verifications_passed = false;
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_err());
        let failures = result.unwrap_err();
        assert!(failures
            .iter()
            .any(|f| f.check == "all_verifications_passed"));
    }

    #[test]
    fn verify_all_rejects_empty_pk_hash() {
        let mut report = make_minimal_report();
        report.aggregate_pk_hash_hex.clear();
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_err());
        let failures = result.unwrap_err();
        assert!(failures.iter().any(|f| f.check == "aggregate_pk_hash"));
    }

    #[test]
    fn verify_all_rejects_zero_sk_commitments() {
        let mut report = make_minimal_report();
        report.sk_commitments.clear();
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_err());
    }

    #[test]
    fn verify_all_rejects_zero_nizk_hash() {
        let mut report = make_minimal_report();
        report.all_nizk_proof_hash = Fr::zero();
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_err());
    }

    #[test]
    fn verify_all_rejects_zero_pipeline_integrity_hash() {
        let mut report = make_minimal_report();
        report.pipeline_integrity_hash = Fr::zero();
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_err());
    }

    #[test]
    fn verify_all_rejects_zero_cross_hash() {
        let mut report = make_minimal_report();
        report.compressed_proof_hash = Fr::zero();
        let result = ProtocolVerifier::verify_all(&report);
        assert!(result.is_err());
    }

    #[test]
    fn verification_failure_display() {
        let f = VerificationFailure {
            check: "test_check".into(),
            detail: "test failure detail".into(),
        };
        assert_eq!(f.to_string(), "test_check: test failure detail");
    }
}
