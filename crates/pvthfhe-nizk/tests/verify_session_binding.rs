#![allow(clippy::unwrap_used, clippy::expect_used)]
//! C2 regression test: proof-encoded session_id and participant_id
//! MUST be compared against the input statement during verify.
//!
//! Prior to the C2 fix, `adapter.rs:165-167` parsed these fields then
//! explicitly discarded them with `let _ = ...`, so a proof whose
//! envelope claimed a different session than the verifier's statement
//! would still be accepted.

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::rlwe_n;
use pvthfhe_nizk::{NizkAdapter, NizkError, NizkStatement, NizkWitness};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn sample_ternary(rng: &mut ChaCha20Rng) -> Vec<i64> {
    let mut s = vec![0i64; rlwe_n()];
    for x in s.iter_mut() {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        *x = match b[0] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }
    s
}

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

/// Shorthand: offset within proof bytes at which the encoded session_id bytes begin.
///
/// Proof layout (spec §3.4):
///   version[2] | ccs_id[32] | ajtai_commitment[26624]
///   | sid_len[4] | sid_bytes[sid_len] | pid[2] | sha256_commitment[32]
fn session_id_bytes_offset() -> usize {
    2 + 32 + 26_624 + 4
}

/// Shorthand: offset within proof bytes at which the encoded participant_id (u16 BE) begins,
/// given a session_id of a known length.
fn participant_id_offset(session_id: &str) -> usize {
    session_id_bytes_offset() + session_id.len()
}

// ---------------------------------------------------------------------------
// RED tests — these MUST fail (verification MUST reject) when the proof
// envelope's session_id / participant_id does not match the statement.
// ---------------------------------------------------------------------------

/// C2-RED-1: Tampered session_id in proof envelope against original statement.
///
/// We create a valid proof for session "sess-A", then flip the encoded
/// session_id bytes to "sess-B" (same length) while keeping every other
/// field intact.  The verifier must notice that the proof claims a
/// different session than the statement and reject.
#[test]
fn tampered_session_id_must_be_rejected() {
    let session_a = "sess-A";
    let session_b = "sess-B";
    assert_eq!(session_a.len(), session_b.len());

    let mut rng = ChaCha20Rng::seed_from_u64(0xC2_01);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit(session_a, 1, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session_a.to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let mut proof = adapter.prove(&stmt, &witness, &mut rng).expect("prove");

    // Overwrite the encoded session_id in the proof envelope.
    let sid_offset = session_id_bytes_offset();
    proof.proof_bytes[sid_offset..sid_offset + session_b.len()]
        .copy_from_slice(session_b.as_bytes());

    // Verifier MUST reject — the proof claims session "sess-B" but the
    // statement says "sess-A".
    let result = adapter.verify(&stmt, &proof);
    assert!(
        result.is_err(),
        "C2-RED-1: tampered session_id must be rejected, got {result:?}"
    );
}

/// C2-RED-2: Tampered participant_id in proof envelope against original statement.
#[test]
fn tampered_participant_id_must_be_rejected() {
    let session = "sess-C2";
    let pid_a: u16 = 1;
    let pid_b: u16 = 2;

    let mut rng = ChaCha20Rng::seed_from_u64(0xC2_02);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit(session, pid_a, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session.to_owned(),
        participant_id: pid_a,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let mut proof = adapter.prove(&stmt, &witness, &mut rng).expect("prove");

    // Overwrite the encoded participant_id in the proof envelope.
    let pid_offset = participant_id_offset(session);
    proof.proof_bytes[pid_offset] = (pid_b >> 8) as u8;
    proof.proof_bytes[pid_offset + 1] = (pid_b & 0xFF) as u8;

    // Verifier MUST reject — the proof claims participant 2 but the
    // statement says participant 1.
    let result = adapter.verify(&stmt, &proof);
    assert!(
        result.is_err(),
        "C2-RED-2: tampered participant_id must be rejected, got {result:?}"
    );
}

/// C2-RED-3: Cross-session: proof_for_X verified against statement_for_Y
/// (where only the pvss_commitment differs but ccs_id matches because
/// ccs_id does not commit to pvss_commitment).
///
/// We create a proof for session‑B and verify it against a statement
/// for session‑A.  The ccs_id check *may* already catch this, but C2
/// adds a direct comparison as defence-in-depth — if the ccs_id check
/// were ever weakened, the discarded `session_id_encoded` would be the
/// only remaining defence.
///
/// We accept either `VerificationFailed` or `InvalidProof` and panic
/// on `Ok(())`.
#[test]
fn cross_session_verify_must_fail() {
    let session_a = "cs-A";
    let session_b = "cs-B";

    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha20Rng::seed_from_u64(0xC2_03);

    // Create a valid proof for session_b.
    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_b = hash_bridge::commit(session_b, 1, secret_share);
    let stmt_b = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: pvss_b,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session_b.to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let proof_b = adapter.prove(&stmt_b, &witness, &mut rng).expect("prove");

    // Build statement for session_a — same params but different session + commitment.
    let pvss_a = hash_bridge::commit(session_a, 1, secret_share);
    let stmt_a = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: pvss_a,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session_a.to_owned(),
        participant_id: 1,
        epoch: 0,
    };

    let result = adapter.verify(&stmt_a, &proof_b);
    assert!(
        result.is_err(),
        "C2-RED-3: cross-session verify must fail, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// GREEN tests — after the C2 fix these MUST pass (legitimate proofs accepted).
// ---------------------------------------------------------------------------

/// C2-GRN-1: Valid proof for matching statement passes.
#[test]
fn matching_session_binding_passes() {
    let session = "match-me";
    let mut rng = ChaCha20Rng::seed_from_u64(0xC2_04);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit(session, 1, secret_share);

    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session.to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let proof = adapter.prove(&stmt, &witness, &mut rng).expect("prove");
    adapter
        .verify(&stmt, &proof)
        .expect("legitimate proof must verify");
}

/// C2-GRN-2: Different participant_id is correctly rejected (not a false
/// positive from the fix).
#[test]
fn different_participant_id_is_rejected() {
    let session = "pid-test";
    let mut rng = ChaCha20Rng::seed_from_u64(0xC2_05);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit(session, 1, secret_share);

    let stmt_p1 = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session.to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let proof = adapter.prove(&stmt_p1, &witness, &mut rng).expect("prove");

    // Verify against a statement for participant 2 (different commitment too).
    let pvss_p2 = hash_bridge::commit(session, 2, secret_share);
    let stmt_p2 = NizkStatement {
        pvss_commitment: pvss_p2,
        participant_id: 2,
        ..stmt_p1
    };
    let result = adapter.verify(&stmt_p2, &proof);
    assert!(
        result.is_err(),
        "C2-GRN-2: different participant_id must be rejected, got {result:?}"
    );
}
