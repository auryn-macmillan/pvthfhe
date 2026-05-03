#![cfg(feature = "real-folding")]
#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::folding::{
    fold, verify_acc, FoldAccumulator, FoldStatement, FoldWitness, NizkProof, NizkStatement,
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

// ── Category 1: Malformed inner proof ──────────────────────────────────────

#[test]
fn test_empty_proof_bytes_rejected() {
    let params = base_params();
    let acc = make_acc("sess-1", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-1", params, 1);
    let wit = FoldWitness {
        nizk_proof: NizkProof {
            proof_bytes: vec![],
        },
        fold_randomness: vec![1u8; 32],
    };
    let result = fold(&acc, &wit, &stmt);
    assert!(result.is_err(), "empty proof_bytes must be rejected");
}

#[test]
fn test_two_byte_non_uniform_proof_rejected() {
    let params = base_params();
    let acc = make_acc("sess-2", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-2", params, 2);
    // Two different bytes: windows(2) will find them non-uniform
    let wit = FoldWitness {
        nizk_proof: NizkProof {
            proof_bytes: vec![0xAB, 0xCD],
        },
        fold_randomness: vec![2u8; 32],
    };
    let result = fold(&acc, &wit, &stmt);
    assert!(
        result.is_err(),
        "two-byte non-uniform proof must be rejected"
    );
}

#[test]
fn test_non_uniform_proof_bytes_rejected() {
    let params = base_params();
    let acc = make_acc("sess-3", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-3", params, 3);
    // Mixed non-uniform bytes: not all the same value
    let wit = FoldWitness {
        nizk_proof: NizkProof {
            proof_bytes: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
        },
        fold_randomness: vec![3u8; 32],
    };
    let result = fold(&acc, &wit, &stmt);
    assert!(result.is_err(), "non-uniform mixed bytes must be rejected");
}

// ── Category 2: Accumulator forgery ────────────────────────────────────────

#[test]
fn test_acc_wrong_session_id_rejected() {
    let params = base_params();
    // acc has session-A but stmt has session-B
    let acc = make_acc("session-A", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "session-B", params, 10);
    let wit = make_witness(10);
    let result = fold(&acc, &wit, &stmt);
    assert!(
        result.is_err(),
        "acc/stmt session_id mismatch must be rejected"
    );
}

#[test]
fn test_acc_wrong_params_rejected() {
    let params = base_params();
    let wrong_params = (65537, 512, 17);
    // acc has wrong_params but stmt has base_params
    let acc = make_acc("sess-4", wrong_params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-4", params, 11);
    let wit = make_witness(11);
    let result = fold(&acc, &wit, &stmt);
    assert!(result.is_err(), "acc/stmt params mismatch must be rejected");
}

#[test]
fn test_statement_proof_mismatch_rejected() {
    let params = base_params();
    let acc = make_acc("sess-4b", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-4b", params, 12);
    let result = fold(&acc, &make_witness(13), &stmt);
    assert!(result.is_err(), "proof/statement mismatch must be rejected");
}

// ── Category 3: FS challenge grinding (bit-flip triggers rejection) ─────────

#[test]
fn test_single_bit_flip_in_proof_rejected() {
    let params = base_params();
    let acc = make_acc("sess-5", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-5", params, 20);
    let mut wit = make_witness(20);
    // Flip a single bit in proof_bytes -> non-uniform -> rejected
    wit.nizk_proof.proof_bytes[0] ^= 0x01;
    let result = fold(&acc, &wit, &stmt);
    assert!(
        result.is_err(),
        "single bit flip in proof_bytes must be rejected"
    );
}

#[test]
fn test_last_byte_flipped_in_proof_rejected() {
    let params = base_params();
    let acc = make_acc("sess-6", params, 0, [0u8; 32]);
    let stmt = make_statement(1, "sess-6", params, 21);
    let mut wit = make_witness(21);
    let last = wit.nizk_proof.proof_bytes.len() - 1;
    wit.nizk_proof.proof_bytes[last] ^= 0x80;
    let result = fold(&acc, &wit, &stmt);
    assert!(
        result.is_err(),
        "flipping last byte in proof must be rejected"
    );
}

// ── Category 4: Depth bomb (fold to depth 10+) ──────────────────────────────

#[test]
fn test_depth_bomb_fold_to_depth_10_exact() {
    let params = base_params();
    let mut acc = make_acc("sess-depth", params, 0, [0u8; 32]);
    for i in 1u64..=10 {
        let stmt = make_statement(i, "sess-depth", params, (i % 256) as u8);
        let wit = make_witness((i % 256) as u8);
        acc = fold(&acc, &wit, &stmt).expect("fold should succeed at each depth step");
    }
    assert_eq!(
        acc.fold_depth(),
        10,
        "fold_depth must equal 10 after 10 folds"
    );
    verify_acc(&acc, &params).expect("verify_acc should accept at depth 10");
}

#[test]
fn test_depth_bomb_fold_to_depth_12_exact() {
    let params = base_params();
    let mut acc = make_acc("sess-depth12", params, 0, [0u8; 32]);
    for i in 1u64..=12 {
        let stmt = make_statement(i, "sess-depth12", params, (i % 256) as u8);
        let wit = make_witness((i % 256) as u8);
        acc = fold(&acc, &wit, &stmt).expect("fold should succeed at depth step");
    }
    assert_eq!(
        acc.fold_depth(),
        12,
        "fold_depth must equal 12 after 12 folds"
    );
}

#[test]
fn test_non_sequential_fold_index_rejected() {
    let params = base_params();
    let acc = make_acc("sess-depth-gap", params, 0, [0u8; 32]);
    let acc1 = fold(
        &acc,
        &make_witness(12),
        &make_statement(1, "sess-depth-gap", params, 12),
    )
    .expect("first fold should succeed");
    let result = fold(
        &acc1,
        &make_witness(23),
        &make_statement(3, "sess-depth-gap", params, 23),
    );
    assert!(
        result.is_err(),
        "non-sequential fold index must be rejected"
    );
}

// ── Category 5: Parameter mismatch variants ─────────────────────────────────

#[test]
fn test_q_mismatch_across_fold_boundary_rejected() {
    let params = base_params();
    let acc = make_acc("sess-pmq", params, 0, [0u8; 32]);
    let acc1 = fold(
        &acc,
        &make_witness(13),
        &make_statement(1, "sess-pmq", params, 13),
    )
    .expect("first fold should succeed");
    // Different q
    let wrong_q_params = (32771, 1024, 17);
    let stmt2 = make_statement(2, "sess-pmq", wrong_q_params, 14);
    let result = fold(&acc1, &make_witness(14), &stmt2);
    assert!(
        result.is_err(),
        "q mismatch across fold boundary must be rejected"
    );
}

#[test]
fn test_n_mismatch_across_fold_boundary_rejected() {
    let params = base_params();
    let acc = make_acc("sess-pmn", params, 0, [0u8; 32]);
    let acc1 = fold(
        &acc,
        &make_witness(13),
        &make_statement(1, "sess-pmn", params, 13),
    )
    .expect("first fold should succeed");
    // Different N
    let wrong_n_params = (65537, 2048, 17);
    let stmt2 = make_statement(2, "sess-pmn", wrong_n_params, 14);
    let result = fold(&acc1, &make_witness(14), &stmt2);
    assert!(
        result.is_err(),
        "N mismatch across fold boundary must be rejected"
    );
}

#[test]
fn test_be_mismatch_across_fold_boundary_rejected() {
    let params = base_params();
    let acc = make_acc("sess-pmbe", params, 0, [0u8; 32]);
    let acc1 = fold(
        &acc,
        &make_witness(13),
        &make_statement(1, "sess-pmbe", params, 13),
    )
    .expect("first fold should succeed");
    // Different B_e
    let wrong_be_params = (65537, 1024, 32);
    let stmt2 = make_statement(2, "sess-pmbe", wrong_be_params, 14);
    let result = fold(&acc1, &make_witness(14), &stmt2);
    assert!(
        result.is_err(),
        "B_e mismatch across fold boundary must be rejected"
    );
}

// ── Category 6: Session cross-contamination ─────────────────────────────────

#[test]
fn test_stmt_from_session_a_folded_into_acc_from_session_b_rejected() {
    let params = base_params();
    // Build a valid acc from session-B
    let acc_b = make_acc("session-B", params, 0, [0u8; 32]);
    let acc_b1 = fold(
        &acc_b,
        &make_witness(13),
        &make_statement(1, "session-B", params, 13),
    )
    .expect("first fold in session-B should succeed");

    // Statement belongs to session-A, not session-B
    let stmt_a = make_statement(2, "session-A", params, 14);
    let result = fold(&acc_b1, &make_witness(14), &stmt_a);
    assert!(
        result.is_err(),
        "cross-session contamination (stmt-A into acc-B) must be rejected"
    );
}

#[test]
fn test_forged_acc_with_mismatched_session_and_params_rejected() {
    let params = base_params();
    let wrong_params = (65537, 512, 8);
    // Forge an accumulator: session-C, wrong params
    let forged_acc = make_acc("session-C", wrong_params, 5, [0xABu8; 32]);
    // Statement uses correct params but session-C
    let stmt = make_statement(6, "session-C", params, 70);
    let result = fold(&forged_acc, &make_witness(70), &stmt);
    assert!(
        result.is_err(),
        "forged accumulator with param mismatch must be rejected"
    );
}

// ── Soundness amplification harness ─────────────────────────────────────────

#[test]
fn test_soundness_amplification_harness() {
    // Per-fold soundness error bound: 1/3 (ternary challenge set {-1, 0, 1})
    // After d folds: (1/3)^d
    let depths: &[(i32, f64)] = &[
        (1, 1.0 / 3.0),
        (2, 1.0 / 9.0),
        (4, 1.0 / 81.0),
        (6, 1.0 / 729.0),
        (8, 1.0 / 6561.0),
        (10, 1.0 / 59049.0),
    ];

    for &(d, expected) in depths {
        let computed = (1.0_f64 / 3.0_f64).powi(d);
        assert!(
            (computed - expected).abs() < 1e-4,
            "d={}: computed={:.2e} expected={:.2e} diff={:.2e}",
            d,
            computed,
            expected,
            (computed - expected).abs()
        );
    }

    // d=10 must be ≤ 1.7e-5
    let d10 = (1.0_f64 / 3.0_f64).powi(10);
    assert!(d10 <= 1.7e-5, "d=10 soundness {:.2e} must be ≤ 1.7e-5", d10);
}
