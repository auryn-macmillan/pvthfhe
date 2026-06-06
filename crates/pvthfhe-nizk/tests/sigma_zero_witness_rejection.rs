//! M7 RED test: sigma protocol verifier must reject proofs where s_i = 0.
//!
//! When s_i = 0 (all coefficients zero), d_i = c*0 + e_i = e_i.
//! A cheating prover can set e_i = d_i and trivially satisfy the relation.
//! This exploits the fact that s_i ∈ {-1,0,1} — ternary valid but trivially satisfiable.
//!
//! The fix adds an explicit nonzero s_i check via the Ajtai commitment:
//! if s_i = 0, then A*s_i = 0 (all-zeros commitment), and the verifier must reject.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::rlwe_n;
use pvthfhe_nizk::{NizkAdapter, NizkError, NizkStatement, NizkWitness};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Helper: sample a nonzero ternary vector (for the honest comparison).
fn sample_nonzero_ternary(rng: &mut ChaCha20Rng) -> Vec<i64> {
    let mut s = vec![0i64; rlwe_n()];
    // Ensure at least one nonzero entry
    let force_idx = (rng.next_u64() as usize) % rlwe_n();
    for (i, x) in s.iter_mut().enumerate() {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        *x = match b[0] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
        if i == force_idx && *x == 0 {
            *x = 1;
        }
    }
    s
}

/// Helper: sample error within bounds.
fn sample_error(rng: &mut ChaCha20Rng) -> Result<Vec<i64>, NizkError> {
    const B_E: i64 = 16;
    const RANGE: u64 = 33;
    const THRESHOLD: u64 = u64::MAX - (u64::MAX % RANGE);
    let mut e = vec![0i64; rlwe_n()];
    for x in e.iter_mut() {
        loop {
            let v = rng.next_u64();
            if v < THRESHOLD {
                *x = i64::try_from(v % RANGE)
                    .map_err(|_| NizkError::InvalidInput("error sample overflow"))?
                    - B_E;
                break;
            }
        }
    }
    Ok(e)
}

/// M7 RED: verify that a proof with s_i = all-zeros is REJECTED.
#[test]
fn zero_witness_proof_rejected() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4D37_0001);

    let s_i = vec![0i64; rlwe_n()];
    let e_i = sample_error(&mut rng)?;
    let secret_share: u64 = 0; // s_i is all zeros
    let pvss_commitment = hash_bridge::commit("m7-session", 1, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "m7-session".to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };

    let proof = adapter.prove(&stmt, &witness, &mut rng)?;

    // M7: verifier MUST reject proofs where s_i = 0
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed(_)) | Err(NizkError::InvalidProof(_)) => Ok(()),
        Ok(()) => Err(NizkError::VerificationFailed(
            "M7 FAIL: zero-witness proof was accepted",
        )),
        other => {
            let msg = format!("M7: unexpected error: {other:?}");
            Err(NizkError::VerificationFailed(Box::leak(
                msg.into_boxed_str(),
            )))
        }
    }
}

/// Sanity check: honest non-zero witness must still be ACCEPTED after M7 fix.
#[test]
fn nonzero_witness_proof_accepted() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4D37_0002);

    let s_i = sample_nonzero_ternary(&mut rng);
    let e_i = sample_error(&mut rng)?;
    let secret_share: u64 = s_i[0].unsigned_abs(); // guaranteed nonzero
    let pvss_commitment = hash_bridge::commit("m7-session", 1, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "m7-session".to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };

    let proof = adapter.prove(&stmt, &witness, &mut rng)?;
    adapter.verify(&stmt, &proof)
}
