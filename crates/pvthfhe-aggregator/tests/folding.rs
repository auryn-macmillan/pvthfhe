#![cfg(feature = "real-folding")]
#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::folding::{
    finalize, fold, verify_acc, FinalProof, FoldAccumulator, FoldError, FoldStatement, FoldWitness,
    NizkProof, NizkStatement,
};

fn base_params() -> (u64, usize, u64) {
    (65537, 1024, 17)
}

fn make_statement(
    fold_index: u64,
    session_id: &str,
    params: (u64, usize, u64),
    tag: u8,
) -> FoldStatement {
    FoldStatement {
        fold_index,
        session_id: session_id.to_string(),
        params,
        nizk_statement: NizkStatement {
            session_id: session_id.to_string(),
            params,
            ciphertext_bytes: vec![tag; 8],
        },
    }
}

fn make_witness(tag: u8) -> FoldWitness {
    FoldWitness {
        nizk_proof: NizkProof {
            proof_bytes: vec![tag; 16],
        },
        fold_randomness: vec![tag; 32],
    }
}

fn make_acc(
    session_id: &str,
    params: (u64, usize, u64),
    depth: u64,
    chain: [u8; 32],
) -> FoldAccumulator {
    FoldAccumulator::new(
        vec![depth as u8; 4],
        depth,
        session_id.to_string(),
        params,
        chain,
    )
}

fn real_fold_stub(
    acc: &FoldAccumulator,
    witness: &FoldWitness,
    stmt: &FoldStatement,
) -> Result<FoldAccumulator, FoldError> {
    fold(acc, witness, stmt)
}

fn real_verify_acc_stub(
    acc: &FoldAccumulator,
    expected_params: &(u64, usize, u64),
) -> Result<(), FoldError> {
    verify_acc(acc, expected_params)
}

fn real_finalize_stub(acc: &FoldAccumulator) -> Result<FinalProof, FoldError> {
    finalize(acc)
}

mod folding {
    use super::*;

    #[test]
    fn test_fold_two_valid_p1_nizks_verifies() {
        let params = base_params();
        let acc = make_acc("session-a", params, 0, [0u8; 32]);
        let stmt1 = make_statement(1, "session-a", params, 1);
        let wit1 = make_witness(1);
        let acc1 = real_fold_stub(&acc, &wit1, &stmt1).expect("fold 1 should succeed");
        let stmt2 = make_statement(2, "session-a", params, 2);
        let wit2 = make_witness(2);
        let acc2 = real_fold_stub(&acc1, &wit2, &stmt2).expect("fold 2 should succeed");
        real_verify_acc_stub(&acc2, &params).expect("verify_acc should accept");
    }

    #[test]
    fn test_fold_of_fold_verifies_depth_three() {
        let params = base_params();
        let acc = make_acc("session-b", params, 0, [0u8; 32]);
        let acc1 = real_fold_stub(
            &acc,
            &make_witness(10),
            &make_statement(1, "session-b", params, 10),
        )
        .unwrap();
        let acc2 = real_fold_stub(
            &acc1,
            &make_witness(11),
            &make_statement(2, "session-b", params, 11),
        )
        .unwrap();
        let acc3 = real_fold_stub(
            &acc2,
            &make_witness(12),
            &make_statement(3, "session-b", params, 12),
        )
        .unwrap();
        assert_eq!(acc3.fold_depth(), 3);
        real_verify_acc_stub(&acc3, &params).expect("verify_acc should accept at depth 3");
    }

    #[test]
    fn test_tampered_inner_proof_rejected() {
        let params = base_params();
        let acc = make_acc("session-c", params, 0, [0u8; 32]);
        let stmt = make_statement(1, "session-c", params, 21);
        let mut wit = make_witness(21);
        wit.nizk_proof.proof_bytes[0] ^= 0xff;
        let result = real_fold_stub(&acc, &wit, &stmt);
        assert!(result.is_err(), "tampered proof must be rejected");
    }

    #[test]
    fn test_wrong_fhe_param_across_folds_rejected() {
        let params = base_params();
        let acc = make_acc("session-d", params, 0, [0u8; 32]);
        let acc1 = real_fold_stub(
            &acc,
            &make_witness(15),
            &make_statement(1, "session-d", params, 15),
        )
        .unwrap();
        let wrong_params = (65537, 512, 17);
        let stmt2 = make_statement(2, "session-d", wrong_params, 32);
        let result = real_fold_stub(&acc1, &make_witness(32), &stmt2);
        assert!(result.is_err(), "mismatched params must be rejected");
    }

    #[test]
    fn test_accumulator_binding() {
        let params = base_params();
        let acc = make_acc("session-e", params, 0, [0u8; 32]);
        let left = real_fold_stub(
            &acc,
            &make_witness(13),
            &make_statement(1, "session-e", params, 13),
        )
        .unwrap();
        let right = real_fold_stub(
            &acc,
            &make_witness(14),
            &make_statement(1, "session-e", params, 14),
        )
        .unwrap();
        assert_ne!(
            left, right,
            "different fold histories must produce different accumulators"
        );
    }

    #[test]
    fn test_fold_determinism() {
        let params = base_params();
        let acc = make_acc("session-f", params, 0, [0u8; 32]);
        let stmt = make_statement(1, "session-f", params, 16);
        let wit = make_witness(16);
        let left = real_fold_stub(&acc, &wit, &stmt).unwrap();
        let right = real_fold_stub(&acc, &wit, &stmt).unwrap();
        assert_eq!(left, right, "same inputs should fold deterministically");
        let _ = real_finalize_stub(&left).expect("finalize should work");
    }
}
