//! N8 adversarial test suite: 10 scenarios exercising tamper-rejection and
//! edge-case completeness for `CycloNizkAdapter`.
//!
//! Seeds: `ChaCha20Rng::seed_from_u64(0x4E38_000N)` for scenario N.

use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::{B_Z_E, RLWE_N};
use pvthfhe_nizk::{NizkAdapter, NizkError, NizkProof, NizkStatement, NizkWitness};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn sample_ternary(rng: &mut ChaCha20Rng) -> Vec<i64> {
    let mut s = vec![0i64; RLWE_N];
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
    let mut e = vec![0i64; RLWE_N];
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
        params: (65_537_u64, RLWE_N, 16_u64),
        session_id: session_id.to_owned(),
        participant_id,
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

/// Offset inside the sigma section where z_e[0] data lives.
///
/// Sigma section layout (spec §3.4 EXTENSION):
///   d_rns[4 + N*3*8] | t_rns[4 + N*3*8] | z_s[4 + N*8] | z_e_count[4] | z_e_data
const SIGMA_Z_E_DATA_OFFSET: usize =
    (4 + RLWE_N * 3 * 8) + (4 + RLWE_N * 3 * 8) + (4 + RLWE_N * 8) + 4;

#[test]
fn scenario_01_tampered_ajtai_commitment() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0001, "n8-session", 1)?;
    for b in proof.proof_bytes[34..42].iter_mut() {
        *b ^= 0xFF;
    }
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_01: expected VerificationFailed",
        )),
    }
}

#[test]
fn scenario_02_tampered_sigma_proof_bytes() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0002, "n8-session", 1)?;
    let flip_idx = sigma_section_offset("n8-session") + 14;
    proof.proof_bytes[flip_idx] ^= 0x01;
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_02: expected VerificationFailed",
        )),
    }
}

#[test]
fn scenario_03_tampered_sha256_binding() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0003, "n8-session", 1)?;
    let offset = sha256_binding_commitment_offset("n8-session");
    proof.proof_bytes[offset] ^= 0x01;
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::ConditionalSoundnessDisclosure("hash binding mismatch")) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_03: expected ConditionalSoundnessDisclosure(hash binding mismatch)",
        )),
    }
}

#[test]
fn scenario_04_tampered_version_byte() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0004, "n8-session", 1)?;
    proof.proof_bytes[0] = 0x00;
    proof.proof_bytes[1] = 0x02;
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::InvalidProof("unsupported proof version")) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_04: expected InvalidProof(unsupported proof version)",
        )),
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
    };
    let witness = NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };
    match adapter.prove(&stmt, &witness, &mut rng) {
        Err(NizkError::InvalidInput(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_05: expected InvalidInput for degree mismatch",
        )),
    }
}

#[test]
fn scenario_06_forged_sigma_response_ze_overflow() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0006, "n8-session", 1)?;
    let outer_ze0 = sigma_section_offset("n8-session") + SIGMA_Z_E_DATA_OFFSET;
    proof.proof_bytes[outer_ze0..outer_ze0 + 8].copy_from_slice(&(B_Z_E + 1).to_le_bytes());
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::VerificationFailed(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_06: expected VerificationFailed for z_e overflow",
        )),
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
        params: (65_537_u64, RLWE_N, 16_u64),
        session_id: "n8-session-B".to_owned(),
        participant_id: 1,
    };
    match adapter.verify(&stmt_b, &proof_a) {
        Err(NizkError::VerificationFailed(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_07: expected VerificationFailed for replay",
        )),
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
        params: (65_537_u64, RLWE_N, 16_u64),
        session_id: "n8-session".to_owned(),
        participant_id: 2,
    };
    match adapter.verify(&stmt_p2, &proof_p1) {
        Err(NizkError::VerificationFailed(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_08: expected VerificationFailed for pid collision",
        )),
    }
}

#[test]
fn scenario_09_byte_truncated_proof() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let (stmt, mut proof) = make_valid_proof(0x4E38_0009, "n8-session", 1)?;
    let new_len = proof.proof_bytes.len().saturating_sub(10);
    proof.proof_bytes.truncate(new_len);
    match adapter.verify(&stmt, &proof) {
        Err(NizkError::InvalidProof(_)) => Ok(()),
        _ => Err(NizkError::VerificationFailed(
            "scenario_09: expected InvalidProof for truncated proof",
        )),
    }
}

#[test]
fn scenario_10_zero_witness_completeness() -> Result<(), NizkError> {
    let adapter = CycloNizkAdapter;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4E38_000A);
    let s_i = vec![0i64; RLWE_N];
    let e_i = vec![0i64; RLWE_N];
    let secret_share: u64 = 0;
    let pvss_commitment = hash_bridge::commit("n8-session", 1, secret_share);
    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, RLWE_N, 16_u64),
        session_id: "n8-session".to_owned(),
        participant_id: 1,
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
