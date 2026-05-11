//! R4.1 RED: folding_relation — assert fold produces witness for combined
//! RLWE relation; verify checks relation, not SHA chain.
//!
//! These tests encode the desired behaviour of `HashChainFoldingScheme` after the
//! GREEN rewrite: the fold step must commit to a Cyclo-verifiable RLWE
//! relation, and `verify_acc` must re-check that relation, not merely compare
//! parameter tuples.
//!
//! Against the current hash-chain stub every test here MUST fail (RED).

#![cfg(feature = "real-folding")]
#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::folding::{
    fold, verify_acc, FoldAccumulator, FoldStatement, FoldWitness, NizkProof, NizkStatement,
};

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => unreachable!("{ctx}: {e:?}"),
    }
}

fn base_params() -> (u64, usize, u64) {
    (65537, 1024, 17)
}

const SESSION: &str = "r4-rel-test";

// ── Tests ───────────────────────────────────────────────────────────────────

/// R4.1-T1: fold must commit to a Cyclo-verifiable RLWE relation.
///
/// The current hash-chain stub does NOT produce a Cyclo-verifiable
/// commitment — this test must FAIL (RED) against the stub and PASS
/// after the GREEN rewrite wire the Cyclo adapter.
#[test]
fn test_fold_commits_to_cyclo_relation() {
    let params = base_params();
    let tag: u8 = 0x42;

    // Build Fold*/Fold* types and fold via HashChainFoldingScheme.
    let acc = FoldAccumulator::new(
        vec![0u8; 4],
        0,
        SESSION.to_string(),
        params,
        [0u8; 32],
    );
    let stmt = FoldStatement {
        fold_index: 1,
        session_id: SESSION.to_string(),
        params,
        nizk_statement: NizkStatement {
            session_id: SESSION.to_string(),
            params,
            ciphertext_bytes: vec![tag; 32],
        },
    };
    let wit = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: vec![0u8; 64],
        },
        fold_randomness: vec![0u8; 8],
    };

    let result = ok(fold(&acc, &wit, &stmt), "HashChainFoldingScheme fold should succeed");

    // After GREEN: the accumulated result must carry a Cyclo accumulator
    // that passes structural verification.
    let cyclo_acc = result.cyclo_acc().expect("accumulator must carry Cyclo data after fold");
    assert_eq!(cyclo_acc.fold_depth, 1, "Cyclo fold depth must be 1 after one fold step");
    assert!(!cyclo_acc.acc_commitment_bytes.is_empty(), "Cyclo commitment must not be empty");
    assert!(!cyclo_acc.acc_public_io_bytes.is_empty(), "Cyclo public IO must not be empty");
    assert_eq!(cyclo_acc.session_id, SESSION, "Cyclo session must match");
}

/// R4.1-T2: verify_acc must check the RLWE relation, not just (params tuple).
///
/// The current hash-chain stub only checks `acc.params == expected_params`.
/// After GREEN, verify_acc must additionally verify the accumulated Cyclo
/// witness satisfies the RLWE relation.
/// This test constructs an accumulator with valid params but garbage Cyclo
/// data and asserts verify_acc REJECTS it.
#[test]
fn test_verify_checks_relation_not_sha_chain() {
    let params = base_params();

    // Build an accumulator that passes all stub checks:
    // - non-empty acc_commitment  ✓
    // - non-empty session_id      ✓
    // - params match              ✓
    // - BUT: no valid Cyclo witness embedded
    let fake_acc = FoldAccumulator::new(
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        5,
        SESSION.to_string(),
        params,
        [0xBA; 32],
    );

    // RED assertion: verify_acc should REJECT this accumulator.
    // The stub accepts it (params match); GREEN will reject (no Cyclo relation).
    let result = verify_acc(&fake_acc, &params);
    assert!(
        result.is_err(),
        "verify_acc must reject accumulator without valid Cyclo relation; \
         stub accepts (params only), but GREEN requires RLWE relation check"
    );
}

/// R4.1-T3: after a successful fold, verify_acc must accept the result.
///
/// Sanity check that the happy path still works through the fold-verify
/// round-trip — this already passes on the stub but is a needed regression
/// guard for the GREEN rewrite.
#[test]
fn test_fold_then_verify_succeeds() {
    let params = base_params();
    let tag: u8 = 0x07;
    let acc = FoldAccumulator::new(
        vec![0u8; 4],
        0,
        SESSION.to_string(),
        params,
        [0u8; 32],
    );
    let stmt = FoldStatement {
        fold_index: 1,
        session_id: SESSION.to_string(),
        params,
        nizk_statement: NizkStatement {
            session_id: SESSION.to_string(),
            params,
            ciphertext_bytes: vec![tag; 8],
        },
    };
    let wit = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: vec![0u8; 32],
        },
        fold_randomness: vec![0u8; 32],
    };

    let acc1 = ok(fold(&acc, &wit, &stmt), "fold must succeed");
    ok(
        verify_acc(&acc1, &params),
        "verify_acc must accept folded result",
    );
}
