//! R4.4 RED+GREEN: End-to-end fold soundness — adversary game.
//!
//! Adversary model:
//! - n parties, t threshold, t-1 corrupted
//! - Honest aggregator
//! - Adversary controls t-1 parties and can forge their NIZK proofs
//! - Adversary must not produce an accepted fold without ≥t valid per-party instances
//!
//! RED condition (no `real-nizk` feature): adversary uses `EXPECTED_BACKEND_ID`
//! with 32-byte forged proof bytes. `validate_nizk_structure` only checks
//! backend_id → passes. Cyclo fold processes 32 bytes as low-norm polynomial
//! → succeeds. Adversary forges → test FAILS.
//!
//! GREEN condition (`--features real-nizk`): `validate_nizk_structure` enforces
//! minimum NIZK proof size (≥ 26,658 bytes — version + ccs_id + Ajtai
//! commitment). 32-byte forged proofs are rejected before the Cyclo fold.
//! Adversary cannot forge → test PASSES.
//!
//! Soundness target: ≤ 2⁻¹²⁸ per forgery attempt.
//! Attempts: ≥ 10³.

#![cfg(feature = "real-folding")]

use pvthfhe_aggregator::folding::{
    fold, verify_acc, FoldAccumulator, FoldStatement, FoldWitness, NizkProof, NizkStatement,
};

/// Returns the base Cyclo fold parameters used throughout these tests.
fn base_params() -> (u64, usize, u64) {
    (65537, 1024, 17)
}

/// Creates a fresh [`FoldAccumulator`] at the given depth.
fn make_acc(session_id: &str, params: (u64, usize, u64), depth: u64) -> FoldAccumulator {
    let low_byte = u8::try_from(depth % 256).unwrap_or(0);
    FoldAccumulator::new(
        vec![low_byte; 4],
        depth,
        session_id.to_string(),
        params,
        [0u8; 32],
    )
}

/// Creates a [`FoldStatement`] with the given parameters and ciphertext tag.
fn make_statement(
    session_id: &str,
    fold_index: u64,
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
            multi_track_metadata: None,
        },
    }
}

/// Returns 32 proof bytes with the given tag in position 0 and all other
/// bytes zero.  This passes the Cyclo fold norm check (u64 LE values ≤ 17
/// ≪ per-step budget 102).
fn proof_bytes_tagged(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[0] = tag;
    bytes
}

/// Builds a witness that the adversary believes will be accepted.
///
/// Uses the expected NIZK backend ID so the lightweight `validate_nizk_structure`
/// check passes.  In RED phase (no `real-nizk`), the fold path accepts these
/// forged bytes because no cryptographic NIZK verification is performed.
fn forge_witness(tag: u8) -> FoldWitness {
    FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: proof_bytes_tagged(tag),
        },
        fold_randomness: vec![0u8; 32],
    }
}

/// Attempts to produce an accepted fold with two "honest" (corrupted-party)
/// instances followed by one forged instance.
///
/// Returns `true` if the adversary successfully produces a verified
/// accumulator that passes `verify_acc`.
fn adversary_game(session_id: &str, params: (u64, usize, u64), seed: u64) -> bool {
    let acc = make_acc(session_id, params, 0);

    // Fold two "honest" (corrupted party) instances
    let stmt0 = make_statement(session_id, 1, params, 0x01);
    let wit0 = forge_witness(0x01);
    let acc1 = match fold(&acc, &wit0, &stmt0) {
        Ok(a) => a,
        Err(_) => return false,
    };

    let stmt1 = make_statement(session_id, 2, params, 0x02);
    let wit1 = forge_witness(0x02);
    let acc2 = match fold(&acc1, &wit1, &stmt1) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Adversary inserts a FORGED third instance
    let forged_tag = u8::try_from(seed % 256).unwrap_or(0) % 18;
    let adv_stmt = make_statement(session_id, 3, params, forged_tag);
    let adv_wit = forge_witness(forged_tag);

    let acc3 = match fold(&acc2, &adv_wit, &adv_stmt) {
        Ok(a) => a,
        Err(_) => return false,
    };

    verify_acc(&acc3, &params).is_ok()
}

// ── Adversary tests ─────────────────────────────────────────────────────────

/// R4.4-T1: Threshold soundness — adversary with t-1 corrupted parties
/// cannot produce a verified fold (≥ t instances) without at least t
/// valid per-party NIZK proofs.
///
/// Runs 10³ forge attempts and asserts zero successes.
#[test]
fn test_adversary_cannot_forge_fold_with_t_minus_1_valid() {
    let params = base_params();
    let session_id = "e2e-soundness-game";
    let attempts: u32 = 1000;

    let mut forgeries = 0u32;
    for attempt in 0..attempts {
        let seed = u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        if adversary_game(session_id, params, seed) {
            forgeries += 1;
        }
    }

    assert_eq!(
        forgeries, 0,
        "R4.4 RED: adversary forged {forgeries}/{attempts} fold completions.\n\
         NIZK verification is not wired — the fold path accepts proof bytes\n\
         that pass only syntax-level checks.  GREEN must integrate R3 NIZK +\n\
         R2 Cyclo + R4.1 fold so each instance is bound to a verified NIZK."
    );
}

/// R4.4-T2: Adversary cannot fold even a single entirely-forged instance
/// (zero valid shares, n=1 party).
///
/// Runs 10³ forge attempts and asserts zero successes.
#[test]
fn test_adversary_cannot_forge_single_instance() {
    let params = base_params();
    let session_id = "e2e-single-forged";
    let attempts: u32 = 1000;

    let mut forgeries = 0u32;
    for attempt in 0..attempts {
        let tag = u8::try_from(attempt % 256).unwrap_or(0) % 18;
        let acc = make_acc(session_id, params, 0);
        let stmt = make_statement(session_id, 1, params, tag);
        let wit = forge_witness(tag);

        if fold(&acc, &wit, &stmt).is_ok() {
            forgeries += 1;
        }
    }

    assert_eq!(
        forgeries, 0,
        "R4.4 RED: adversary forged {forgeries}/{attempts} single-instance attempts.\n\
         The fold path currently accepts any proof bytes that satisfy\n\
         syntactic checks — true NIZK verification is required (GREEN)."
    );
}

/// R4.4-T3: Adversary cannot forge with mismatched ciphertext tag
/// (proof-witness to statement-ciphertext binding).
///
/// Runs 10³ forge attempts and asserts zero successes.
#[test]
fn test_adversary_cannot_forge_with_mismatched_ciphertext() {
    let params = base_params();
    let session_id = "e2e-ct-mismatch";
    let attempts: u32 = 1000;

    let mut forgeries = 0u32;
    for _attempt in 0..attempts {
        let acc = make_acc(session_id, params, 0);
        // Statement ciphertext uses tag 0x01
        let stmt = FoldStatement {
            fold_index: 1,
            session_id: session_id.to_string(),
            params,
            nizk_statement: NizkStatement {
                session_id: session_id.to_string(),
                params,
                ciphertext_bytes: vec![0x01; 8],
                multi_track_metadata: None,
            },
        };
        // Witness proof uses tag 0x02 (mismatch with statement)
        let wit = forge_witness(0x02);

        if fold(&acc, &wit, &stmt).is_ok() {
            forgeries += 1;
        }
    }

    assert_eq!(
        forgeries, 0,
        "R4.4 RED: ciphertext-mismatch fold accepted in {forgeries}/{attempts} attempts.\n\
         The fold path does not verify NIZK proofs against statement ciphertexts."
    );
}

/// R4.4-T4: Structural test — verifies the Cyclo backend is active so the
/// adversary tests exercise the real fold path.
///
/// This test uses small 32-byte proof bytes that pass the Cyclo norm check
/// but would be rejected by the real-NIZK size check (gated behind
/// `real-nizk`).  It is disabled when `real-nizk` is active.
#[cfg(not(feature = "real-nizk"))]
#[test]
fn test_cyclo_backend_is_active_for_soundness_tests() {
    let params = base_params();
    let acc = make_acc("e2e-cyclo-check", params, 0);
    // Depth-0 accumulator (no Cyclo data) — verify_acc should accept
    assert!(
        verify_acc(&acc, &params).is_ok(),
        "verify_acc must accept a valid depth-0 accumulator"
    );

    // Fold one instance so Cyclo data is populated.
    let stmt = make_statement("e2e-cyclo-check", 1, params, 0x01);
    let wit = FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: proof_bytes_tagged(0x01),
        },
        fold_randomness: vec![0u8; 32],
    };
    let acc1 = fold(&acc, &wit, &stmt).expect("fold of standard instance must succeed");
    assert_eq!(acc1.fold_depth(), 1);
    assert!(
        acc1.cyclo_acc().is_some(),
        "accumulator after fold must carry Cyclo data"
    );
    assert!(
        verify_acc(&acc1, &params).is_ok(),
        "verify_acc must accept a depth-1 Cyclo-backed accumulator"
    );
}
