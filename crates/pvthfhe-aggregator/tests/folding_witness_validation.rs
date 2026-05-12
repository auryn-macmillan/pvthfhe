//! R4.1 RED: folding_witness_validation — assert real Cyclo witness passes,
//! tampered witness fails, junk witness rejects.
//!
//! Against the current hash-chain stub every Cyclo-positive test MUST fail
//! (RED) because the stub's `validate_witness` enforces byte-uniformity
//! rather than Cyclo CCS satisfiability.

#![cfg(feature = "real-folding")]
#![allow(missing_docs, clippy::unwrap_used, clippy::as_conversions)]

use pvthfhe_aggregator::folding::{
    fold, FoldAccumulator, FoldStatement, FoldWitness, NizkProof, NizkStatement,
};
fn base_params() -> (u64, usize, u64) {
    (65537, 1024, 17)
}

const SESSION: &str = "r4-wval-test";

fn base_acc() -> FoldAccumulator {
    FoldAccumulator::new(
        vec![0u8; 4],
        0,
        SESSION.to_string(),
        base_params(),
        [0u8; 32],
    )
}

fn make_stmt(tag: u8, fold_index: u64) -> FoldStatement {
    FoldStatement {
        fold_index,
        session_id: SESSION.to_string(),
        params: base_params(),
        nizk_statement: NizkStatement {
            session_id: SESSION.to_string(),
            params: base_params(),
            ciphertext_bytes: vec![tag; 8],
            multi_track_metadata: None,
        },
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// R4.1-T4: A real Cyclo-compatible witness must pass fold().
///
/// The current hash-chain stub REQUIRES all proof_bytes to be uniform
/// (the `windows(2).all(|w| w[0] == w[1])` check in `validate_witness`).
/// A real Cyclo witness is NOT byte-uniform — its bytes encode BN254 Fr
/// elements in LE format.
///
/// This test MUST FAIL on the stub (RED) and PASS after the GREEN rewrite
/// delegates witness validation to the Cyclo adapter.
#[test]
fn test_real_cyclo_witness_passes_fold() {
    let acc = base_acc();
    let stmt = make_stmt(0x42, 1);

    // A "real" Cyclo-compatible witness: non-uniform bytes that would be
    // accepted by Cyclo's CCS satisfiability + norm checks.
    // Bytes represent valid Fr-serialized small integers.
    let real_witness = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            // Non-uniform bytes — will be REJECTED by the stub's uniformity check
            // but ACCEPTED by Cyclo's CCS satisfiability check (zero witness, norm=0).
            proof_bytes: vec![
                0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, // first coefficient = 0x42 (66)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // second = 0
            ],
        },
        fold_randomness: vec![0x42; 8],
    };

    let result = fold(&acc, &real_witness, &stmt);
    assert!(
        result.is_ok(),
        "fold must accept a real Cyclo-compatible witness; \
         stub rejects because of byte-uniformity requirement"
    );
}

/// R4.1-T5: A tampered Cyclo witness must be rejected.
///
/// Tampering the witness (flipping one byte in a Fr element) must cause
/// fold() to reject. The current stub checks for byte uniformity, so a
/// tamper that preserves uniformity might slip through.
///
/// This test demonstrates that the stub's uniformity-based check is
/// insufficient for real Cyclo validation.
#[test]
fn test_tampered_cyclo_witness_fails_fold() {
    let acc = base_acc();
    let tag: u8 = 0x01;
    let stmt = make_stmt(tag, 1);

    // Build a witness that PASSES the stub's validate_witness checks:
    //   a) proof_bytes non-empty          ✓
    //   b) all bytes uniform              ✓  (all 0x01)
    //   c) proof_bytes[0] == stmt tag     ✓  (0x01 == 0x01 from ciphertext_bytes[0])
    //   d) no byte > error_bound          ✓  (0x01 < 17)
    //
    // This witness passes the stub but represents garbage Cyclo data
    // (sha256 binding will NOT match when Cyclo encodes & checks satisfiability).
    // After GREEN, Cyclo verification should reject it.
    let stub_valid_witness = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: vec![tag; 16],
        },
        fold_randomness: vec![tag; 8],
    };

    // The stub accepts this; after GREEN, Cyclo should reject.
    let result = fold(&acc, &stub_valid_witness, &stmt);
    assert!(
        result.is_err(),
        "tampered/garbage witness must be rejected by Cyclo; \
         stub accepts because uniformity + tag + norm checks pass"
    );
}

/// R4.1-T6: Junk/random witness must be rejected.
///
/// Completely random bytes that happen to be non-uniform must still be
/// rejected by fold().
#[test]
fn test_junk_witness_rejected() {
    let acc = base_acc();
    let stmt = make_stmt(0x09, 1);

    let junk_witness = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            // Random non-uniform bytes — stub rejects via uniformity check,
            // Cyclo would also reject via CCS satisfiability.
            proof_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        },
        fold_randomness: vec![0x00; 8],
    };

    let result = fold(&acc, &junk_witness, &stmt);
    assert!(result.is_err(), "junk witness must be rejected by fold");
}

/// R4.1-T7: A valid uniform witness (which the stub accepts) must still be
/// accepted after GREEN. This is a regression guard.
#[test]
fn test_valid_uniform_witness_still_passes() {
    let acc = base_acc();
    let tag: u8 = 0x07;
    let stmt = make_stmt(tag, 1);

    let uniform_witness = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: vec![0u8; 32],
        },
        fold_randomness: vec![0u8; 32],
    };

    let result = fold(&acc, &uniform_witness, &stmt);
    assert!(
        result.is_ok(),
        "uniform witness with matching tag must pass fold"
    );
}
