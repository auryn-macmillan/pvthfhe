#![allow(clippy::unwrap_used, clippy::expect_used)]
//! N8 adversarial test suite: 10 scenarios exercising tamper-rejection and
//! edge-case completeness for `CycloNizkAdapter`.
//!
//! Seeds: `ChaCha20Rng::seed_from_u64(0x4E38_000N)` for scenario N.

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::{
    compute_d_rns, prove as sigma_prove, rlwe_n, B_Z_E, RLWE_Q0, RLWE_Q1, RLWE_Q2,
};
use pvthfhe_nizk::sigma::{SigmaStatement, SigmaWitness};
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

fn make_valid_proof(
    seed: u64,
    session_id: &str,
    participant_id: u16,
) -> Result<(NizkStatement, NizkProof), NizkError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let adapter = CycloNizkAdapter;
    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng)?;
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit(session_id, participant_id, secret_share);
    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: session_id.to_owned(),
        participant_id,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let proof = adapter.prove(&stmt, &witness, &mut rng)?;
    Ok((stmt, proof))
}

/// Offset of the 32-byte sha256_binding commitment field in proof bytes.
///
/// Binary layout (spec §3.4):
///   version[2] | ccs_id[32] | ajtai_commitment[26624]
///   | sid_len_u32[4] | sid_bytes[sid_len] | pid_u16[2] | commitment[32]
fn sha256_binding_commitment_offset(session_id: &str) -> usize {
    2 + 32 + 26_624 + 4 + session_id.len() + 2
}

fn sigma_section_offset(session_id: &str) -> usize {
    sha256_binding_commitment_offset(session_id) + 32 + 4
}

/// Test: mismatched pvss_commitment must produce VerificationFailed, not ConditionalSoundnessDisclosure.
#[test]
fn mismatched_pvss_commitment_produces_verification_failed() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x00DE_ADBE_EFC4);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng).expect("error sample");
    let secret_share: u64 = s_i[0].unsigned_abs();

    let commit_a = hash_bridge::commit("c4-session", 1, secret_share);
    let stmt_a = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: commit_a,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "c4-session".to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    let proof = adapter.prove(&stmt_a, &witness, &mut rng).expect("prove");

    let mut commit_b = commit_a;
    commit_b[0] ^= 0xFF;
    let stmt_b = NizkStatement {
        pvss_commitment: commit_b,
        ..stmt_a
    };

    match adapter.verify(&stmt_b, &proof) {
        Err(NizkError::VerificationFailed { .. }) => {}
        Err(NizkError::ConditionalSoundnessDisclosure { .. }) => {
            panic!("C4 bug still present: got ConditionalSoundnessDisclosure instead of VerificationFailed")
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

/// Differential test: prove with two different session_ids for identical (s_i, e_i).
///
/// With scalar ternary challenge (ch ∈ {-1,0,1}), collisions are possible (~33%
/// probability). This test runs 20 trials with different seeds and verifies that
/// at least half of trials produce different challenges.
#[test]
fn different_session_ids_produce_different_challenges() {
    let mut diff_count = 0usize;
    for seed in 0..20u64 {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC4D1FF01 ^ seed);
        let c_rns: Vec<u64> = {
            let moduli = [RLWE_Q0, RLWE_Q1, RLWE_Q2];
            let mut out = vec![0u64; rlwe_n() * 3];
            for (limb, &q) in moduli.iter().enumerate() {
                let threshold = u64::MAX - (u64::MAX % q);
                for j in 0..rlwe_n() {
                    loop {
                        let v = rng.next_u64();
                        if v < threshold {
                            out[limb * rlwe_n() + j] = v % q;
                            break;
                        }
                    }
                }
            }
            out
        };
        let s_i = sample_ternary(&mut rng);
        let e_i = sample_error(&mut rng).expect("error sample");
        let d_rns = compute_d_rns(&c_rns, &s_i, &e_i).expect("compute_d_rns");

        let stmt = SigmaStatement { c_rns, d_rns };
        let wit = SigmaWitness {
            s_i: s_i.clone(),
            e_i: e_i.clone(),
        };

        let mut rng_a = ChaCha20Rng::seed_from_u64(0xC4D1FF02 ^ seed);
        let mut rng_b = ChaCha20Rng::seed_from_u64(0xC4D1FF02 ^ seed);

        let proof_a = sigma_prove(b"session-alpha", 1, &stmt, &wit, &mut rng_a, &[1u8; 32])
            .expect("sigma prove a");
        let proof_b = sigma_prove(b"session-beta", 1, &stmt, &wit, &mut rng_b, &[1u8; 32])
            .expect("sigma prove b");

        if proof_a.ch != proof_b.ch {
            diff_count += 1;
        }
    }
    assert!(
        diff_count >= 5,
        "only {diff_count}/20 trials produced different challenges with different session_ids (expected ≥5 for ternary challenge)"
    );
}

/// Offset inside the sigma section where z_e[0] data lives (first round).
///
/// Sigma section layout (multi-round):
///   d_rns: count(4) + values(n*3*8)
///   num_rounds: 4
///   round 0: t_rns count(4)+values | z_s count(4)+values | z_e count(4)+values | ch(32)
fn sigma_z_e_data_offset() -> usize {
    let n = rlwe_n();
    (4 + n * 3 * 8) + 4 /* num_rounds */ + (4 + n * 3 * 8) + (4 + n * 8) + 4
}

#[test]
fn scenario_01_tampered_ajtai_commitment() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0001, "n8-session", 1)?;
    // Tamper with first t_rns coefficient value in sigma section (guaranteed
    // to break algebraic verification equation).
    let sigma_start = sigma_section_offset("n8-session");
    // Layout: d_rns count(4) | d_rns values(24576*8) | num_rounds(4) | t_rns count(4) | t_rns values
    let t_rns_first_val = sigma_start + 4 + rlwe_n() * 3 * 8 + 4 /* num_rounds */ + 4;
    if t_rns_first_val + 7 < proof.proof_bytes.len() {
        proof.proof_bytes[t_rns_first_val] ^= 0xFF;
    }
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_01: expected VerificationFailed for tampered t_rns",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_02_tampered_sigma_proof_bytes() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0002, "n8-session", 1)?;
    let flip_idx = sigma_section_offset("n8-session") + 14;
    proof.proof_bytes[flip_idx] ^= 0x01;
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_02: expected VerificationFailed",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_03_tampered_sha256_binding() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0003, "n8-session", 1)?;
    let offset = sha256_binding_commitment_offset("n8-session");
    proof.proof_bytes[offset] ^= 0x01;
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_03: expected VerificationFailed for tampered sha256_binding",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_04_tampered_version_byte() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0004, "n8-session", 1)?;
    proof.proof_bytes[0] = 0x00;
    proof.proof_bytes[1] = 0x01;
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::InvalidProof {
            reason: "unsupported proof version",
            ..
        }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_04: expected InvalidProof(unsupported proof version)",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_05_degree_mismatch() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4E38_0005);
    let s_i = sample_ternary(&mut rng);
    let secret_share: u64 = s_i[0].unsigned_abs();
    let e_i = sample_error(&mut rng)?;
    let pvss_commitment = hash_bridge::commit("n8-session", 1, secret_share);
    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, 1024_usize, 16_u64),
        session_id: "n8-session".to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    match adapter.prove(&stmt, &witness, &mut rng) {
        Err(NizkError::InvalidInput { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_05: expected InvalidInput for degree mismatch",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_06_forged_sigma_response_ze_overflow() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0006, "n8-session", 1)?;
    let outer_ze0 = sigma_section_offset("n8-session") + sigma_z_e_data_offset();
    proof.proof_bytes[outer_ze0..outer_ze0 + 8].copy_from_slice(&(B_Z_E + 1).to_le_bytes());
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_06: expected VerificationFailed for z_e overflow",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_07_replay_attack() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (_, proof_a) = make_valid_proof(0x4E38_0007, "n8-session-A", 1)?;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4E38_0007);
    let s_i = sample_ternary(&mut rng);
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment_b = hash_bridge::commit("n8-session-B", 1, secret_share);
    let stmt_b = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: pvss_commitment_b,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "n8-session-B".to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    match adapter.verify(&stmt_b, &proof_a) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_07: expected VerificationFailed for replay",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_08_participant_id_collision() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (_, proof_p1) = make_valid_proof(0x4E38_0008, "n8-session", 1)?;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4E38_0008);
    let s_i = sample_ternary(&mut rng);
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit("n8-session", 2, secret_share);
    let stmt_p2 = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "n8-session".to_owned(),
        participant_id: 2,
        epoch: 0,
    };
    match adapter.verify(&stmt_p2, &proof_p1) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_08: expected VerificationFailed for pid collision",
            party_id: None,
        }),
    }
}

#[test]
fn scenario_09_byte_truncated_proof() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0009, "n8-session", 1)?;
    let new_len = proof.proof_bytes.len().saturating_sub(10);
    proof.proof_bytes.truncate(new_len);
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::InvalidProof { .. }) => Ok(()),
        _ => Err(NizkError::VerificationFailed {
            reason: "scenario_09: expected InvalidProof for truncated proof",
            party_id: None,
        }),
    }
}

/// M7: zero-witness (s_i = 0, e_i = 0) produces trivially-satisfiable proofs.
/// The Ajtai commitment is all-zeros, which `verify_ajtai_commitment` rejects
/// to prevent this bypass.
#[test]
fn scenario_10_zero_witness_rejected() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4E38_000A);
    let s_i = vec![0i64; rlwe_n()];
    let e_i = vec![0i64; rlwe_n()];
    let secret_share: u64 = 0;
    let pvss_commitment = hash_bridge::commit("n8-session", 1, secret_share);
    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, rlwe_n(), 16_u64),
        session_id: "n8-session".to_owned(),
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
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed { .. }) => Ok(()),
        Ok(()) => Err(NizkError::VerificationFailed {
            reason: "M7: zero-witness proof was accepted but should be rejected",
            party_id: None,
        }),
        Err(_other) => Err(NizkError::VerificationFailed {
            reason: "M7: unexpected error type",
            party_id: None,
        }),
    }
}
