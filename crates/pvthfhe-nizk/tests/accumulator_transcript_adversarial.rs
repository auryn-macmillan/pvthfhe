#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Adversarial tests for Cyclo accumulator transcript verification (A1).
//!
//! These tests verify that an adversary cannot produce an accepted
//! accumulator transcript without satisfying the fold relation.

use pvthfhe_cyclo::accumulator_codec::{self};
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
                    .map_err(|_| NizkError::InvalidInput("error sample overflow"))?
                    - B_E;
                break;
            }
        }
    }
    Ok(e)
}

fn make_base_proof(seed: u64) -> (CycloNizkAdapter, NizkStatement, NizkProof) {
    let session = "adversarial-acc";
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

fn build_valid_transcript(
    proof_commitment_bytes: &[u8],
    stmt: &NizkStatement,
) -> (CycloAccumulator, CcsPShareInstance) {
    let mut sha_binding = [0u8; 32];
    sha_binding[0..2].copy_from_slice(&stmt.participant_id.to_be_bytes());

    let instance = CcsPShareInstance {
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
    };

    let acc = CycloAccumulator {
        fold_depth: 1,
        acc_commitment_bytes: proof_commitment_bytes.to_vec(),
        acc_public_io_bytes: vec![0u8; 32],
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        session_id: stmt.session_id.clone(),
        params_digest: accumulator_codec::params_digest(),
    };

    (acc, instance)
}

#[test]
fn adversary_tampered_commitment_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_02);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    let mut tampered = encoded.clone();

    let header_base = 2 + 32 + 4 + 4 + AJTAI_COMMITMENT_BYTES + 4 + 32 + 8;
    let per_instance_ajtai_hash_offset = header_base + 4 + stmt.session_id.len() + 4 + 2;
    if tampered.len() > per_instance_ajtai_hash_offset {
        tampered[per_instance_ajtai_hash_offset] ^= 0xFF;
    }

    let mut proof_copy = proof.proof_bytes.clone();
    let old_len = proof_copy.len();
    proof_copy.truncate(old_len - 4);
    let acc_len = u32::try_from(tampered.len()).unwrap();
    proof_copy.extend_from_slice(&acc_len.to_be_bytes());
    proof_copy.extend_from_slice(&tampered);

    let tampered_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes: proof_copy,
    };

    let result = adapter.verify(&stmt, &tampered_proof);
    assert!(
        result.is_err(),
        "tampered commitment hash must be rejected, got {result:?}"
    );
}

#[test]
fn adversary_tampered_ajtai_commitment_hash_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_01);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    // Compute offset to per-instance ajtai_commitment_hash:
    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    let header_base = 2 + 32 + 4 + 4 + AJTAI_COMMITMENT_BYTES + 4 + 32 + 8;
    let per_instance_ajtai_hash_offset = header_base + 4 + stmt.session_id.len() + 4 + 2;

    let mut tampered = encoded.clone();
    if tampered.len() > per_instance_ajtai_hash_offset {
        tampered[per_instance_ajtai_hash_offset] ^= 0xFF;
    }

    let mut proof_copy = proof.proof_bytes.clone();
    let old_len = proof_copy.len();
    proof_copy.truncate(old_len - 4);
    let acc_len = u32::try_from(tampered.len()).unwrap();
    proof_copy.extend_from_slice(&acc_len.to_be_bytes());
    proof_copy.extend_from_slice(&tampered);

    let tampered_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes: proof_copy,
    };

    let result = adapter.verify(&stmt, &tampered_proof);
    assert!(
        result.is_err(),
        "tampered ajtai_commitment_hash must be rejected, got {result:?}"
    );
}

#[test]
fn adversary_norm_bound_violation_rejected() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAD_03);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.norm_bound_current = PVTHFHE_CYCLO_PARAMS.beta_at_t + 1;

    let result = adapter::append_accumulator_to_proof(&mut proof.proof_bytes, &acc, &[instance]);
    assert!(
        result.is_err() || { adapter.verify(&stmt, &proof).is_err() },
        "norm_bound_current exceeding beta_at_t must be rejected"
    );
}

#[test]
fn adversary_wrong_instance_count_rejected() {
    let (_adapter, stmt, mut proof) = make_base_proof(0xAD_04);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.fold_depth = 3;

    let result = adapter::append_accumulator_to_proof(&mut proof.proof_bytes, &acc, &[instance]);
    assert!(
        result.is_err(),
        "fold_depth != instance_count must be rejected at encode time"
    );
}

#[test]
fn adversary_wrong_params_digest_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_05);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.params_digest = [0xFFu8; 32];

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    let mut proof_copy = proof.proof_bytes.clone();
    let old_len = proof_copy.len();
    proof_copy.truncate(old_len - 4);
    let acc_len = u32::try_from(encoded.len()).unwrap();
    proof_copy.extend_from_slice(&acc_len.to_be_bytes());
    proof_copy.extend_from_slice(&encoded);

    let tampered_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes: proof_copy,
    };

    let result = adapter.verify(&stmt, &tampered_proof);
    assert!(result.is_err(), "wrong params_digest must be rejected");
}

#[test]
fn adversary_wrong_session_id_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_06);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.session_id = "different-session".to_string();

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    let mut proof_copy = proof.proof_bytes.clone();
    let old_len = proof_copy.len();
    proof_copy.truncate(old_len - 4);
    let acc_len = u32::try_from(encoded.len()).unwrap();
    proof_copy.extend_from_slice(&acc_len.to_be_bytes());
    proof_copy.extend_from_slice(&encoded);

    let tampered_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes: proof_copy,
    };

    let result = adapter.verify(&stmt, &tampered_proof);
    assert!(result.is_err(), "wrong session_id must be rejected");
}
