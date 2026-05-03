//! Integration tests: folding_tamper.
#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::folding::{FoldingAccumulator, FoldingError, PartyProof};

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => unreachable!("{ctx}: {e:?}"),
    }
}

#[test]
fn test_folding_tamper() {
    let mut accumulator = FoldingAccumulator::new();

    for i in 0..64 {
        let nizk = if i == 42 { vec![] } else { vec![1, 2, 3] };
        let proof = PartyProof {
            party_id: i as u32,
            share_hash: [i as u8; 32],
            nizk_bytes: nizk,
        };
        accumulator.add_proof(proof).unwrap();
    }

    let result = accumulator.finalize();
    match result {
        Err(FoldingError::InvalidLeaf(id)) => assert_eq!(id, 42),
        _ => unreachable!("Expected InvalidLeaf error"),
    }
}

// ── T16 real-folding gap tests ─────────────────────────────────────────────

#[cfg(feature = "real-folding")]
mod real_folding_gaps {
    use super::ok;
    use pvthfhe_aggregator::folding::{
        fold, FoldAccumulator, FoldStatement, FoldWitness, NizkProof, NizkStatement,
    };

    const PARAMS: (u64, usize, u64) = (65_537, 1_024, 17);
    const SESSION: &str = "test-session-p2";
    const CTXT_TAG: u8 = 0x05;

    fn base_acc() -> FoldAccumulator {
        FoldAccumulator::new(vec![0x01; 32], 0, SESSION.to_owned(), PARAMS, [0u8; 32])
    }

    fn stmt(fold_index: u64) -> FoldStatement {
        FoldStatement {
            fold_index,
            session_id: SESSION.to_owned(),
            params: PARAMS,
            nizk_statement: NizkStatement {
                session_id: SESSION.to_owned(),
                params: PARAMS,
                ciphertext_bytes: vec![CTXT_TAG; 4],
            },
        }
    }

    fn valid_witness(len: usize) -> FoldWitness {
        FoldWitness {
            nizk_proof: NizkProof {
                proof_bytes: vec![CTXT_TAG; len],
            },
            fold_randomness: vec![0x11, 0x22, 0x33],
        }
    }

    fn large_norm_stmt(fold_index: u64) -> FoldStatement {
        FoldStatement {
            fold_index,
            session_id: SESSION.to_owned(),
            params: PARAMS,
            nizk_statement: NizkStatement {
                session_id: SESSION.to_owned(),
                params: PARAMS,
                ciphertext_bytes: vec![200u8; 4],
            },
        }
    }

    /// P2-G1: a single tampered byte in nizk_proof.proof_bytes must be
    /// rejected by fold().
    ///
    /// Falsifies P2-T2 (Knowledge Soundness): "depth-d accepting fold tree
    /// yields valid RLWE witnesses".
    #[test]
    fn test_fold_tampered_witness_rejected() {
        let acc = base_acc();
        let s = stmt(1);
        let mut tampered = valid_witness(4);
        tampered.nizk_proof.proof_bytes[2] ^= 0xFF;
        assert!(
            fold(&acc, &tampered, &s).is_err(),
            "fold must reject witness with tampered nizk proof bytes"
        );
    }

    /// P2-G2: fold must reject a FoldStatement whose params differ from the
    /// accumulator params.
    ///
    /// Falsifies P2-T4 Part A (Parameter Binding): "no adversary can produce
    /// accumulator with acc*.params ≠ P".
    #[test]
    fn test_fold_mismatched_params_rejected() {
        let acc = base_acc();
        let mut bad_stmt = stmt(1);
        bad_stmt.params = (65_537, 512, 17);
        let w = valid_witness(4);
        let result = fold(&acc, &w, &bad_stmt);
        assert!(result.is_err(), "fold must reject mismatched params");
        assert!(
            result.unwrap_err().0.contains("param mismatch"),
            "error must mention param mismatch"
        );
    }

    /// P2-G3: witness with proof_bytes containing value 200 (exceeds B_e=17)
    /// must be rejected by fold().
    ///
    /// Falsifies P2-T4 Part B (Norm Bound): arithmetic norm bound B_e=17 is
    /// enforced in validate_witness. Serves as a regression guard — if the
    /// norm check is ever dropped this test goes RED.
    // BUG(P2-T4): norm bound not enforced — test intentionally RED until validate_witness is fixed
    #[test]
    fn test_fold_large_norm_witness_rejected() {
        let acc = base_acc();
        let s = large_norm_stmt(1);
        let large_norm = FoldWitness {
            nizk_proof: NizkProof {
                // Uniform bytes with correct tag (200) but value 200 >> B_e=17.
                // Tag check passes; only an arithmetic norm check catches this.
                proof_bytes: vec![200u8; 4],
            },
            fold_randomness: vec![0x44, 0x55],
        };
        assert!(
            fold(&acc, &large_norm, &s).is_err(),
            "fold must reject witness with coefficients exceeding norm bound B_e=17"
        );
    }

    /// P2-G4: folding the same batch with different fold_randomness must
    /// produce distinct acc_commitment, demonstrating ZK randomization.
    ///
    /// Falsifies P2-T3 (ZK Preservation): "folding preserves projected ZK
    /// view".
    #[test]
    fn test_fold_proof_not_deterministic() {
        let acc = base_acc();
        let s = stmt(1);
        let mut w1 = valid_witness(4);
        let mut w2 = valid_witness(4);
        w1.fold_randomness = vec![0x01, 0x02, 0x03];
        w2.fold_randomness = vec![0xAA, 0xBB, 0xCC];
        let acc1 = ok(fold(&acc, &w1, &s), "first fold should succeed");
        let acc2 = ok(fold(&acc, &w2, &s), "second fold should succeed");
        assert_ne!(
            acc1.acc_commitment(),
            acc2.acc_commitment(),
            "different fold_randomness must produce distinct acc_commitment"
        );
    }
}
