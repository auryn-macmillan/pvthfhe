#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Regression tests for the Cyclo accumulator transcript verification (A1).
//!
//! Covers the transition from fail-closed stub to real codec-based verification:
//!   - Empty (non-folded) placeholder still accepted
//!   - Invalid accumulator bytes rejected by codec
//!   - Valid accumulator transcripts accepted
//!   - Framing errors (length without bytes) rejected

use pvthfhe_cyclo::accumulator_codec;
use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
use pvthfhe_cyclo::{CcsPShareInstance, CycloAccumulator, PVTHFHE_CYCLO_PARAMS};
use pvthfhe_nizk::adapter::{self, CycloNizkAdapter};
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::rlwe_n;
use pvthfhe_nizk::{NizkAdapter, NizkError, NizkProof, NizkStatement, NizkWitness};
use pvthfhe_types::{CcsWitnessSecret, ProtocolBytes};
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
                    .map_err(|_| NizkError::InvalidInput { reason: "error sample overflow", party_id: None })?
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
fn accumulator_invalid_nonzero_transcript_bytes_rejected() {
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
        result.is_err(),
        "invalid accumulator bytes must be rejected, got {result:?}"
    );
}

#[test]
fn accumulator_nonzero_length_without_bytes_rejected() {
    let (adapter, stmt, mut proof) = valid_accumulator_placeholder_proof(0xF4_02);

    let acc_len_offset = proof
        .proof_bytes
        .len()
        .checked_sub(4)
        .expect("proof contains accumulator length");
    assert_eq!(&proof.proof_bytes[acc_len_offset..], &0u32.to_be_bytes());

    proof.proof_bytes[acc_len_offset..].copy_from_slice(&4u32.to_be_bytes());

    let result = adapter.verify(&stmt, &proof);
    assert!(result.is_err(), "nonzero length without bytes must reject");
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

#[test]
fn valid_accumulator_transcript_accepted() {
    let (adapter, stmt, mut proof) = valid_accumulator_placeholder_proof(0xF4_10);

    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];

    let acc = CycloAccumulator {
        fold_depth: 1,
        acc_commitment_bytes: proof_commitment_bytes.to_vec(),
        acc_public_io_bytes: vec![0u8; 32],
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        session_id: stmt.session_id.clone(),
        params_digest: accumulator_codec::params_digest(),
    };

    let mut sha_binding = [0u8; 32];
    sha_binding[0..2].copy_from_slice(&stmt.participant_id.to_be_bytes());

    let instances = vec![CcsPShareInstance {
        participant_id: stmt.participant_id,
        ajtai_commitment_bytes: ProtocolBytes(proof_commitment_bytes.to_vec()),
        public_io_bytes: ProtocolBytes(vec![0u8; 32]),
        ccs_witness_bytes: CcsWitnessSecret::new({
            let mut w = Vec::new();
            w.extend_from_slice(&1u32.to_be_bytes());
            w.extend_from_slice(&[0u8; 32]);
            w
        }),
        sha256_binding_bytes: ProtocolBytes(sha_binding.to_vec()),
        ccs_matrix_bytes: ProtocolBytes({
            let mut m = Vec::new();
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(&[0u8; 32]);
            m
        }),
    }];

    adapter::append_accumulator_to_proof(&mut proof.proof_bytes, &acc, &instances)
        .expect("append accumulator");

    adapter
        .verify(&stmt, &proof)
        .expect("valid accumulator transcript must be accepted");
}

#[test]
fn accumulator_too_many_bytes_rejected() {
    let (adapter, stmt, mut proof) = valid_accumulator_placeholder_proof(0xF4_20);

    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];

    let acc = CycloAccumulator {
        fold_depth: 1,
        acc_commitment_bytes: proof_commitment_bytes.to_vec(),
        acc_public_io_bytes: vec![0u8; 32],
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        session_id: stmt.session_id.clone(),
        params_digest: accumulator_codec::params_digest(),
    };

    let mut sha_binding = [0u8; 32];
    sha_binding[0..2].copy_from_slice(&stmt.participant_id.to_be_bytes());

    let instances = vec![CcsPShareInstance {
        participant_id: stmt.participant_id,
        ajtai_commitment_bytes: ProtocolBytes(proof_commitment_bytes.to_vec()),
        public_io_bytes: ProtocolBytes(vec![0u8; 32]),
        ccs_witness_bytes: CcsWitnessSecret::new({
            let mut w = Vec::new();
            w.extend_from_slice(&1u32.to_be_bytes());
            w.extend_from_slice(&[0u8; 32]);
            w
        }),
        sha256_binding_bytes: ProtocolBytes(sha_binding.to_vec()),
        ccs_matrix_bytes: ProtocolBytes({
            let mut m = Vec::new();
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(&[0u8; 32]);
            m
        }),
    }];

    adapter::append_accumulator_to_proof(&mut proof.proof_bytes, &acc, &instances)
        .expect("append accumulator");

    proof.proof_bytes.extend_from_slice(&[0xDE, 0xAD]);

    let result = adapter.verify(&stmt, &proof);
    assert!(result.is_err(), "trailing proof bytes must reject");
}
