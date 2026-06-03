//! Regression tests for the non-folded A1 Cyclo accumulator placeholder.
//!
//! Until full Cyclo accumulator transcript verification lands, verifier acceptance
//! is only for proofs that carry the encoder's documented empty non-folded placeholder.

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::rlwe_n;
use pvthfhe_nizk::{NizkAdapter, NizkError, NizkProof, NizkStatement, NizkWitness};
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

fn valid_accumulator_placeholder_proof(seed: u64) -> (CycloNizkAdapter, NizkStatement, NizkProof) {
    let session = "accumulator-fail-closed";
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share = s_i[0].unsigned_abs();
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

    (adapter, stmt, proof)
}

#[test]
fn accumulator_nonzero_transcript_bytes_fail_closed() {
    let (adapter, stmt, mut proof) = valid_accumulator_placeholder_proof(0xF4_00);

    let acc_len_offset = proof
        .proof_bytes
        .len()
        .checked_sub(4)
        .expect("proof contains accumulator length");
    assert_eq!(&proof.proof_bytes[acc_len_offset..], &0u32.to_be_bytes());

    proof.proof_bytes[acc_len_offset..].copy_from_slice(&4u32.to_be_bytes());
    proof
        .proof_bytes
        .extend_from_slice(&[0xA1, 0xCC, 0x00, 0x42]);

    let result = adapter.verify(&stmt, &proof);
    assert!(
        matches!(
            result,
            Err(NizkError::VerificationFailed(
                "cyclo accumulator present but unverified (fail-closed)"
            ))
        ),
        "nonzero accumulator bytes must fail closed, got {result:?}"
    );
}

#[test]
fn accumulator_nonzero_length_without_bytes_fails_closed() {
    let (adapter, stmt, mut proof) = valid_accumulator_placeholder_proof(0xF4_02);

    let acc_len_offset = proof
        .proof_bytes
        .len()
        .checked_sub(4)
        .expect("proof contains accumulator length");
    assert_eq!(&proof.proof_bytes[acc_len_offset..], &0u32.to_be_bytes());

    proof.proof_bytes[acc_len_offset..].copy_from_slice(&4u32.to_be_bytes());

    let result = adapter.verify(&stmt, &proof);
    assert!(
        matches!(
            result,
            Err(NizkError::VerificationFailed(
                "cyclo accumulator present but unverified (fail-closed)"
            ))
        ),
        "nonzero accumulator length without bytes must fail closed before any parse/skip semantics, got {result:?}"
    );
}

#[test]
fn accumulator_empty_placeholder_honest_proof_still_verifies() {
    let (adapter, stmt, proof) = valid_accumulator_placeholder_proof(0xF4_01);

    assert_eq!(
        &proof.proof_bytes[proof.proof_bytes.len() - 4..],
        &0u32.to_be_bytes()
    );
    adapter
        .verify(&stmt, &proof)
        .expect("empty accumulator placeholder must remain accepted");
}
