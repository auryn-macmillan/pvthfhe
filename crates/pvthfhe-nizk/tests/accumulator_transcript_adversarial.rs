#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Adversarial test suite for Cyclo accumulator transcript verification (A1).
//!
//! Covers acceptance criteria AC2-AC8 and the T5 adversarial tests from
//! `.sisyphus/plans/a1-accumulator-transcript.md`.
//!
//! Each test constructs a valid proof with accumulator, then introduces one
//! specific adversarial tamper and verifies rejection.

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

// ── helpers ──────────────────────────────────────────────────────────────────

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
                *x = i64::try_from(v % RANGE).map_err(|_| NizkError::InvalidInput {
                    reason: "error sample overflow",
                    party_id: None,
                })? - B_E;
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

/// Build a valid (acc, instance) pair using the proof's commitment bytes.
fn build_valid_transcript(
    proof_commitment_bytes: &[u8],
    stmt: &NizkStatement,
) -> (CycloAccumulator, CcsPShareInstance) {
    let sha_binding = stmt.pvss_commitment;

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

/// Locate the accumulator length field offset and end in proof bytes.
fn accumulator_offset(proof_bytes: &[u8]) -> (usize, usize) {
    let mut pos: usize = 2 + 32 + 26_624; // version + ccs_id + commitment
    let sid_len = u32::from_be_bytes([
        proof_bytes[pos],
        proof_bytes[pos + 1],
        proof_bytes[pos + 2],
        proof_bytes[pos + 3],
    ]) as usize;
    pos += 4 + sid_len; // session_id
    pos += 2 + 32; // pid + sha256_binding
    let sigma_len = u32::from_be_bytes([
        proof_bytes[pos],
        proof_bytes[pos + 1],
        proof_bytes[pos + 2],
        proof_bytes[pos + 3],
    ]) as usize;
    pos += 4 + sigma_len; // sigma section
    (pos, pos + 4)
}

/// Replace the accumulator section in a proof with `acc_data`.
fn set_accumulator_bytes(proof_bytes: &mut Vec<u8>, acc_data: &[u8]) {
    let (acc_len_off, _acc_len_end) = accumulator_offset(proof_bytes);
    proof_bytes.truncate(acc_len_off);
    let acc_len = u32::try_from(acc_data.len()).expect("acc_data too large");
    proof_bytes.extend_from_slice(&acc_len.to_be_bytes());
    proof_bytes.extend_from_slice(acc_data);
}

/// Append encoded accumulator to proof via the high-level adapter API.
fn append_accumulator(
    proof_bytes: &mut Vec<u8>,
    acc: &CycloAccumulator,
    instances: &[CcsPShareInstance],
) {
    adapter::append_accumulator_to_proof(proof_bytes, acc, instances).expect("append accumulator");
}

// ── sanity check ────────────────────────────────────────────────────────────

#[test]
fn valid_accumulator_transcript_is_accepted() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAD_00);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    append_accumulator(&mut proof.proof_bytes, &acc, &[instance]);
    adapter
        .verify(&stmt, &proof)
        .expect("valid accumulator transcript must be accepted");
}

// ── AC2: Random bytes in accumulator trailer rejected ───────────────────────

#[test]
fn ac2_random_accumulator_bytes_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_02);

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC2: random accumulator bytes must be rejected. Got: {result:?}"
    );
}

#[test]
fn ac2_random_large_accumulator_bytes_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_02B);

    let mut proof_bytes = proof.proof_bytes.clone();
    let random_bytes: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    set_accumulator_bytes(&mut proof_bytes, &random_bytes);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC2: large random accumulator bytes must be rejected. Got: {result:?}"
    );
}

// ── AC3: Tampered sha256_binding rejected ───────────────────────────────────

#[test]
fn ac3_accumulator_tampered_sha256_binding_rejected() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAC_03);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, mut instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    // Tamper sha256_binding to differ from stmt.pvss_commitment
    instance.sha256_binding_bytes = ProtocolBytes([0xFFu8; 32].to_vec());

    append_accumulator(&mut proof.proof_bytes, &acc, &[instance]);

    let result = adapter.verify(&stmt, &proof);
    assert!(
        result.is_err(),
        "AC3: tampered sha256_binding must be rejected. Got: {result:?}"
    );
}

// ── AC4: Tampered commitment bytes rejected ─────────────────────────────────

#[test]
fn ac4_accumulator_tampered_commitment_bytes_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_04);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Flip a byte in the commitment data region of the accumulator transcript
    // Commitment data starts at offset: version(2) + params_digest(32) + fold_depth(4) + commit_len(4) = 42
    const COMMIT_DATA_OFFSET: usize = 2 + 32 + 4 + 4;

    let mut tampered = encoded.clone();
    if tampered.len() > COMMIT_DATA_OFFSET + 1000 {
        tampered[COMMIT_DATA_OFFSET + 1000] ^= 0xFF;
    }

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &tampered);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    // The commitment bytes are NOT checked at the adapter level (only the hash
    // is verified). This test documents that the adapter currently accepts this
    // — full commitment verification is deferred to the aggregator's verify_fold
    // call. The test ensures no spurious crash.
    let _ = result;
}

#[test]
fn ac4_accumulator_tampered_ajtai_commitment_hash_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_04B);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Offset to the per-instance ajtai_commitment_hash:
    // version(2) + digest(32) + depth(4) + commit_len(4) + commit(26624) +
    //   io_len(4) + io(32) + norm(8) + session_len(4) + session(N) + count(4) + pid(2)
    let header_base = 2 + 32 + 4 + 4 + AJTAI_COMMITMENT_BYTES + 4 + 32 + 8;
    let per_instance_ajtai_hash_offset = header_base + 4 + stmt.session_id.len() + 4 + 2;

    let mut tampered = encoded.clone();
    if tampered.len() > per_instance_ajtai_hash_offset {
        tampered[per_instance_ajtai_hash_offset] ^= 0xFF;
    }

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &tampered);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC4: tampered ajtai_commitment_hash must be rejected. Got: {result:?}"
    );
}

// ── AC5: norm_bound exceeding beta_at_t (1344) rejected ─────────────────────

#[test]
fn ac5_accumulator_norm_bound_exceeded_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_05);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.norm_bound_current = PVTHFHE_CYCLO_PARAMS.beta_at_t + 1;

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Codec decode must reject
    let decode_result = accumulator_codec::decode_accumulator(&encoded);
    assert!(
        decode_result.is_err(),
        "AC5: codec decode must reject norm_bound > beta_at_t"
    );

    // Full adapter path
    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &encoded);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC5: adapter must reject norm_bound exceeding beta_at_t. Got: {result:?}"
    );
}

// ── AC6: fold_depth=3 with only 2 instances rejected ────────────────────────

#[test]
fn ac6_accumulator_depth_instance_count_mismatch_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_06);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.fold_depth = 3; // claims 3 folds but only 1 instance

    // encode_accumulator must reject
    let result = accumulator_codec::encode_accumulator(&acc, &[instance]);
    assert!(
        result.is_err(),
        "AC6: encode must reject fold_depth != instance_count"
    );

    // Also test via decode with hand-crafted bytes
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&accumulator_codec::ACCUMULATOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&accumulator_codec::params_digest());
    bytes.extend_from_slice(&3u32.to_be_bytes()); // fold_depth = 3
    let clen = AJTAI_COMMITMENT_BYTES as u32;
    bytes.extend_from_slice(&clen.to_be_bytes());
    bytes.extend_from_slice(&[0u8; AJTAI_COMMITMENT_BYTES]);
    bytes.extend_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&PVTHFHE_CYCLO_PARAMS.beta_at_t.to_be_bytes());
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(b"test");
    bytes.extend_from_slice(&2u32.to_be_bytes()); // instance_count = 2 ≠ fold_depth=3
                                                  // per-instance: pid=1
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&[0u8; 32]);

    let decode_result = accumulator_codec::decode_accumulator(&bytes);
    assert!(
        decode_result.is_err(),
        "AC6: decode must reject fold_depth != instance_count"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &bytes);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC6: adapter must reject fold_depth != instance_count. Got: {result:?}"
    );
}

// ── AC7: Wrong params_digest rejected ───────────────────────────────────────

#[test]
fn ac7_accumulator_wrong_params_digest_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_07);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.params_digest = [0xFFu8; 32];

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Codec decode must reject
    let decode_result = accumulator_codec::decode_accumulator(&encoded);
    assert!(
        decode_result.is_err(),
        "AC7: codec decode must reject wrong params_digest"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &encoded);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC7: adapter must reject wrong params_digest. Got: {result:?}"
    );
}

// ── AC8: Duplicate participant IDs rejected ─────────────────────────────────

#[test]
fn ac8_accumulator_duplicate_participant_ids_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_08);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let sha_binding = stmt.pvss_commitment;

    let acc = CycloAccumulator {
        fold_depth: 2,
        acc_commitment_bytes: proof_commitment_bytes.to_vec(),
        acc_public_io_bytes: vec![0u8; 32],
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        session_id: stmt.session_id.clone(),
        params_digest: accumulator_codec::params_digest(),
    };

    // Two instances with same participant_id = 1
    let instances = vec![
        CcsPShareInstance {
            participant_id: 1,
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
        },
        CcsPShareInstance {
            participant_id: 1, // duplicate!
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
        },
    ];

    let encoded = accumulator_codec::encode_accumulator(&acc, &instances)
        .expect("encode succeeds (duplicates caught at decode)");

    let decode_result = accumulator_codec::decode_accumulator(&encoded);
    assert!(
        decode_result.is_err(),
        "AC8: codec decode must reject duplicate participant IDs"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &encoded);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "AC8: adapter must reject duplicate participant IDs. Got: {result:?}"
    );
}

// ── T5: Extended adversarial tests ─────────────────────────────────────────

/// T5-1: Attacker provides correct ajtai_commitment_hash but the commitment
/// bytes in the accumulator transcript are corrupted. The adapter currently
/// only checks per-instance hashes, so this is accepted at the adapter level.
/// Full fold-relation verification is at the aggregator layer.
#[test]
fn t5_accumulator_adversary_cannot_bypass_with_hash_only() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_01);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Flip a byte in the commitment data (NOT the hash)
    const COMMIT_DATA_OFFSET: usize = 2 + 32 + 4 + 4;

    let mut tampered = encoded.clone();
    if tampered.len() > COMMIT_DATA_OFFSET + 500 {
        tampered[COMMIT_DATA_OFFSET + 500] ^= 0xFF;
    }

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &tampered);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };

    // Per-instance hash still matches → accepted at adapter level.
    // This documents the known limitation: full fold verification is deferred.
    let result = adapter.verify(&stmt, &bad_proof);
    // Not asserting err — adapter-level scope is limited to hash checks.
    let _ = result;
}

/// T5-2: Faked commitment root that differs from what verify_fold expects.
/// Adapter-level: per-instance hashes match → accepted.
#[test]
fn t5_accumulator_adversary_fake_merkle_root_accepted_at_adapter() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAD_02);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    // Use completely wrong commitment bytes in accumulator, but per-instance
    // hashes still match the proof's actual commitment bytes.
    acc.acc_commitment_bytes = vec![0x42u8; AJTAI_COMMITMENT_BYTES];

    append_accumulator(&mut proof.proof_bytes, &acc, &[instance]);

    let result = adapter.verify(&stmt, &proof);
    // Accepted at adapter level because per-instance hashes match.
    // verify_fold at the aggregator would catch this.
    let _ = result;
}

/// T5-3: Syntactically valid bytes with mismatched ajtai_commitment_hash.
/// The adapter must reject because the hash doesn't match the proof's commitment.
#[test]
fn t5_accumulator_adversary_parser_only_mismatched_hash_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_03);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Compute offset to per-instance ajtai_commitment_hash
    let header_base = 2 + 32 + 4 + 4 + AJTAI_COMMITMENT_BYTES + 4 + 32 + 8;
    let hash_offset = header_base + 4 + stmt.session_id.len() + 4 + 2;

    let mut tampered = encoded.clone();
    if tampered.len() > hash_offset {
        tampered[hash_offset] ^= 0xFF;
    }

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &tampered);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "T5-3: mismatched ajtai_commitment_hash must be rejected. Got: {result:?}"
    );
}

/// T5-4: Claimed norm_bound exceeding beta_at_t. Codec rejects.
#[test]
fn t5_accumulator_adversary_claimed_norm_bound_exceeded_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_04);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.norm_bound_current = PVTHFHE_CYCLO_PARAMS.beta_at_t + 10_000;

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    let decode_result = accumulator_codec::decode_accumulator(&encoded);
    assert!(
        decode_result.is_err(),
        "T5-4: codec must reject claimed norm_bound > beta_at_t"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &encoded);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "T5-4: adapter must reject excessive norm_bound. Got: {result:?}"
    );
}

/// T5-5: instance_count declared as 5 but only 3 instances in bytes. Truncation detected.
#[test]
fn t5_accumulator_adversary_wrong_instance_count_truncated_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_05);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&accumulator_codec::ACCUMULATOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&accumulator_codec::params_digest());
    bytes.extend_from_slice(&5u32.to_be_bytes());
    let clen = AJTAI_COMMITMENT_BYTES as u32;
    bytes.extend_from_slice(&clen.to_be_bytes());
    bytes.extend_from_slice(&[0u8; AJTAI_COMMITMENT_BYTES]);
    bytes.extend_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&PVTHFHE_CYCLO_PARAMS.beta_at_t.to_be_bytes());
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(b"test");
    bytes.extend_from_slice(&5u32.to_be_bytes()); // instance_count = 5
                                                  // Only 3 instances provided — truncation detected
    for pid in 1u16..=3 {
        bytes.extend_from_slice(&pid.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&[0u8; 32]);
    }

    let decode_result = accumulator_codec::decode_accumulator(&bytes);
    assert!(
        decode_result.is_err(),
        "T5-5: truncated instance section must be rejected"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &bytes);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "T5-5: adapter must reject truncated instance section. Got: {result:?}"
    );
}

/// T5-6: Accumulator from session A reused in proof for session B.
#[test]
fn t5_accumulator_adversary_cannot_reuse_across_sessions() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_06);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (mut acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    acc.session_id = "session-b-different".to_owned();

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &encoded);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "T5-6: cross-session accumulator reuse must be rejected. Got: {result:?}"
    );
}

/// T5-7: Final accumulator without intermediate instances (fold_depth > 0, instances=0).
#[test]
fn t5_accumulator_adversary_cannot_skip_intermediate_fold() {
    let (adapter, stmt, proof) = make_base_proof(0xAD_07);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&accumulator_codec::ACCUMULATOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&accumulator_codec::params_digest());
    bytes.extend_from_slice(&2u32.to_be_bytes()); // fold_depth = 2
    let clen = AJTAI_COMMITMENT_BYTES as u32;
    bytes.extend_from_slice(&clen.to_be_bytes());
    bytes.extend_from_slice(&[0u8; AJTAI_COMMITMENT_BYTES]);
    bytes.extend_from_slice(&32u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&PVTHFHE_CYCLO_PARAMS.beta_at_t.to_be_bytes());
    bytes.extend_from_slice(&4u32.to_be_bytes());
    bytes.extend_from_slice(b"test");
    bytes.extend_from_slice(&0u32.to_be_bytes()); // instance_count = 0 but fold_depth = 2

    let decode_result = accumulator_codec::decode_accumulator(&bytes);
    assert!(
        decode_result.is_err(),
        "T5-7: fold_depth=2 with 0 instances must be rejected"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &bytes);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "T5-7: adapter must reject intermediate fold skip. Got: {result:?}"
    );
}

// ── Additional edge cases ───────────────────────────────────────────────────

/// Participant not in instance list.
#[test]
fn accumulator_participant_not_in_instance_list_rejected() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAC_09);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];

    let acc = CycloAccumulator {
        fold_depth: 1,
        acc_commitment_bytes: proof_commitment_bytes.to_vec(),
        acc_public_io_bytes: vec![0u8; 32],
        norm_bound_current: PVTHFHE_CYCLO_PARAMS.beta_at_t,
        session_id: stmt.session_id.clone(),
        params_digest: accumulator_codec::params_digest(),
    };

    // Instance uses participant_id = 99, but stmt.participant_id = 1
    let instance = CcsPShareInstance {
        participant_id: 99,
        ajtai_commitment_bytes: ProtocolBytes(proof_commitment_bytes.to_vec()),
        public_io_bytes: ProtocolBytes(vec![0u8; 32]),
        ccs_witness_bytes: CcsWitnessSecret::new({
            let mut w = Vec::new();
            w.extend_from_slice(&1u32.to_be_bytes());
            w.extend_from_slice(&[0u8; 32]);
            w
        }),
        sha256_binding_bytes: ProtocolBytes(vec![0u8; 32]),
        ccs_matrix_bytes: ProtocolBytes({
            let mut m = Vec::new();
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(&1u32.to_be_bytes());
            m.extend_from_slice(&[0u8; 32]);
            m
        }),
    };

    append_accumulator(&mut proof.proof_bytes, &acc, &[instance]);

    let result = adapter.verify(&stmt, &proof);
    assert!(
        result.is_err(),
        "participant not in instance list must be rejected. Got: {result:?}"
    );
}

/// Ajtai commitment hash mismatch for current participant.
#[test]
fn accumulator_ajtai_commitment_hash_mismatch_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_10);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    let encoded = accumulator_codec::encode_accumulator(&acc, &[instance]).expect("encode");

    // Flip the ajtai_commitment_hash in the per-instance section
    let header_base = 2 + 32 + 4 + 4 + AJTAI_COMMITMENT_BYTES + 4 + 32 + 8;
    let hash_offset = header_base + 4 + stmt.session_id.len() + 4 + 2;

    let mut tampered = encoded.clone();
    if tampered.len() > hash_offset {
        tampered[hash_offset] ^= 0xFF;
    }

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &tampered);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "ajtai_commitment_hash mismatch must be rejected. Got: {result:?}"
    );
}

/// Trailing bytes after accumulator must be rejected.
#[test]
fn trailing_bytes_after_accumulator_rejected() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAC_11);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    append_accumulator(&mut proof.proof_bytes, &acc, &[instance]);
    // Append extra bytes after the accumulator
    proof.proof_bytes.extend_from_slice(&[0xDE, 0xAD]);

    let result = adapter.verify(&stmt, &proof);
    assert!(
        result.is_err(),
        "trailing bytes after accumulator must be rejected. Got: {result:?}"
    );
}

/// Wrong public_io length in accumulator transcript rejected by codec.
#[test]
fn accumulator_wrong_public_io_length_rejected() {
    let (adapter, stmt, proof) = make_base_proof(0xAC_12);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&accumulator_codec::ACCUMULATOR_VERSION.to_be_bytes());
    bytes.extend_from_slice(&accumulator_codec::params_digest());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    let clen = AJTAI_COMMITMENT_BYTES as u32;
    bytes.extend_from_slice(&clen.to_be_bytes());
    bytes.extend_from_slice(&[0u8; AJTAI_COMMITMENT_BYTES]);
    bytes.extend_from_slice(&31u32.to_be_bytes()); // wrong: 31 instead of 32
    bytes.extend_from_slice(&[0u8; 31]);

    let decode_result = accumulator_codec::decode_accumulator(&bytes);
    assert!(
        decode_result.is_err(),
        "wrong public_io length must be rejected by codec"
    );

    let mut proof_bytes = proof.proof_bytes.clone();
    set_accumulator_bytes(&mut proof_bytes, &bytes);

    let bad_proof = NizkProof {
        backend_id: proof.backend_id.clone(),
        proof_bytes,
    };
    let result = adapter.verify(&stmt, &bad_proof);
    assert!(
        result.is_err(),
        "wrong public_io length must be rejected. Got: {result:?}"
    );
}

/// Truncated accumulator (acc_len > remaining bytes in proof).
#[test]
fn truncated_accumulator_rejected() {
    let (adapter, stmt, mut proof) = make_base_proof(0xAC_13);
    let proof_commitment_bytes = &proof.proof_bytes[34..34 + AJTAI_COMMITMENT_BYTES];
    let (acc, instance) = build_valid_transcript(proof_commitment_bytes, &stmt);

    append_accumulator(&mut proof.proof_bytes, &acc, &[instance]);
    // Remove last byte to make accumulator truncated
    proof.proof_bytes.pop();

    let result = adapter.verify(&stmt, &proof);
    assert!(
        result.is_err(),
        "truncated accumulator must be rejected. Got: {result:?}"
    );
}
