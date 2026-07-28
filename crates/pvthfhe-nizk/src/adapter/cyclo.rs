//! Cyclo-side helpers for the adapter: CCS instance derivation, Ajtai
//! commitment computation/validation, CRS seed derivation, and Cyclo
//! accumulator transcript verification (A1).

use crate::ajtai::{AjtaiCommitment, AjtaiMatrix, AjtaiParams, Rq, AJTAI_RANK, PHI, Q_COMMIT};
use crate::sigma::rlwe_n;
use crate::{NizkError, NizkStatement};

use pvthfhe_cyclo::accumulator_codec;
use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
use pvthfhe_cyclo::PVTHFHE_CYCLO_PARAMS;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

use super::ajtai_m;

pub(super) fn verify_accumulator_transcript(
    stmt: &NizkStatement,
    acc_bytes: &[u8],
    _ajtai_commitment_bytes: &[u8],
) -> Result<(), NizkError> {
    let (acc, instance_refs) = accumulator_codec::decode_accumulator(acc_bytes).map_err(|_e| {
        NizkError::VerificationFailed {
            reason: "accumulator transcript decode failed",
            party_id: Some(stmt.participant_id),
        }
    })?;

    if acc.session_id != stmt.session_id {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: session_id mismatch",
            party_id: Some(stmt.participant_id),
        });
    }

    let expected_digest = accumulator_codec::params_digest();
    if acc.params_digest != expected_digest {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: params_digest mismatch",
            party_id: Some(stmt.participant_id),
        });
    }

    if acc.norm_bound_current > PVTHFHE_CYCLO_PARAMS.beta_at_t {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: norm_bound_current exceeds beta_at_t",
            party_id: Some(stmt.participant_id),
        });
    }

    if acc.fold_depth > PVTHFHE_CYCLO_PARAMS.sequential_t {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: fold_depth exceeds sequential_t",
            party_id: Some(stmt.participant_id),
        });
    }

    if acc.acc_commitment_bytes.len() != AJTAI_COMMITMENT_BYTES {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: commitment length mismatch",
            party_id: Some(stmt.participant_id),
        });
    }

    if acc.acc_public_io_bytes.len() != 32 {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: public_io length mismatch",
            party_id: Some(stmt.participant_id),
        });
    }

    let instance_count = instance_refs.len();
    if acc.fold_depth as usize != instance_count {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: fold_depth != instance_count",
            party_id: Some(stmt.participant_id),
        });
    }

    let found_current_participant = instance_refs
        .iter()
        .any(|ir| ir.participant_id == stmt.participant_id);
    if !found_current_participant {
        return Err(NizkError::VerificationFailed {
            reason: "accumulator transcript: current participant_id not found in instance list",
            party_id: Some(stmt.participant_id),
        });
    }

    for ir in &instance_refs {
        if ir.participant_id == stmt.participant_id {
            let expected_ajtai_hash: [u8; 32] = Sha256::new()
                .chain_update(_ajtai_commitment_bytes)
                .finalize()
                .into();
            if ir.ajtai_commitment_hash != expected_ajtai_hash {
                return Err(NizkError::VerificationFailed { reason: "accumulator transcript: ajtai_commitment_hash mismatch for current participant", party_id: Some(stmt.participant_id) });
            }

            if ir.sha256_binding != stmt.pvss_commitment {
                return Err(NizkError::VerificationFailed {
                    reason:
                        "accumulator transcript: sha256_binding mismatch for current participant",
                    party_id: Some(stmt.participant_id),
                });
            }
        }
    }

    Ok(())
}

/// Derive the CCS instance identifier from the statement.
///
/// ccs_instance_id = SHA256(epoch u64 BE || session_id || participant_id u16 BE
///                          || q u64 BE || degree u64 BE || error_bound u64 BE
///                          || b"cyclo-ajtai-d2/v1")
///
/// Including all statement parameters plus epoch ensures the instance ID is unique per
/// (epoch, session, participant, parameter-set) tuple and prevents cross-epoch replay.
pub(super) fn compute_ccs_instance_id(stmt: &NizkStatement) -> Result<[u8; 32], NizkError> {
    let mut h = Sha256::new();
    h.update(stmt.epoch.to_be_bytes());
    h.update(stmt.session_id.as_bytes());
    h.update(stmt.participant_id.to_be_bytes());
    h.update(stmt.params.0.to_be_bytes());
    let degree_u64 = u64::try_from(stmt.params.1).map_err(|_| NizkError::InvalidInput {
        reason: "degree overflows u64",
        party_id: Some(stmt.participant_id),
    })?;
    h.update(degree_u64.to_be_bytes());
    h.update(stmt.params.2.to_be_bytes());
    h.update(b"cyclo-ajtai-d2/v1");
    Ok(h.finalize().into())
}

/// Expand a 32-byte seed into a uniform RLWE polynomial `c` in RNS power-basis form.
///
/// Seed derivation: `ChaCha20Rng::from_seed(ccs_instance_id)` with rejection
/// sampling per limb to avoid modular bias.
pub(super) fn expand_c_rns(seed: &[u8; 32]) -> Result<Vec<u64>, NizkError> {
    // allow-seeded-rng: Fiat-Shamir public-coin expansion; seed = SHA256-derived ccs_instance_id, so prover and verifier derive the identical challenge polynomial c
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let moduli = pvthfhe_foundations::types::rlwe_moduli();
    let n = rlwe_n();
    let mut c_rns = vec![0u64; n * moduli.len()];
    for (limb, &q) in moduli.iter().enumerate() {
        let threshold = u64::MAX - (u64::MAX % q);
        for j in 0..rlwe_n() {
            loop {
                let v = rng.next_u64();
                if v < threshold {
                    c_rns[limb * rlwe_n() + j] = v % q;
                    break;
                }
            }
        }
    }
    Ok(c_rns)
}

/// Verify the algebraic structure of a deserialized Ajtai commitment.
///
/// Checks that:
/// 1. The commitment is not all-zeros (M7: rejects s_i = 0 trivial witness)
/// 2. The commitment contains exactly AJTAI_RANK (13) ring elements
/// 3. Each element's coefficients are within the valid centred range (-Q_COMMIT/2, Q_COMMIT/2]
///
/// This is a structural validation, not a full opening check (the verifier does not
/// hold the witness s).  Combined with the sigma proof, this ensures the commitment
/// is well-formed and bound to the sigma transcript.
pub(super) fn verify_ajtai_commitment(bytes: &[u8]) -> Result<(), NizkError> {
    if bytes.len() != AJTAI_RANK * PHI * 8 {
        return Err(NizkError::InvalidProof {
            reason: "ajtai commitment: wrong byte length",
            party_id: None,
        });
    }

    // M7: reject all-zeros commitment (indicates s_i = 0 trivial witness).
    // When s_i = 0, the Ajtai commitment A*s_i = 0, enabling a cheating prover
    // to set e_i = d_i and trivially satisfy d_i = c*0 + d_i = d_i.
    if bytes.iter().all(|&b| b == 0) {
        return Err(NizkError::VerificationFailed {
            reason: "ajtai commitment: zero witness rejected (s_i = 0)",
            party_id: None,
        });
    }

    let expected_elems = AJTAI_RANK; // a = 13
    let coeffs_per_elem = PHI; // φ = 256
    let bytes_per_elem = coeffs_per_elem * 8; // 2048 bytes/element

    let half_q = (Q_COMMIT / 2) as i64;

    for (elem_idx, chunk) in bytes.chunks(bytes_per_elem).enumerate() {
        if elem_idx >= expected_elems {
            return Err(NizkError::InvalidProof {
                reason: "ajtai commitment: too many ring elements",
                party_id: None,
            });
        }
        if chunk.len() != bytes_per_elem {
            return Err(NizkError::InvalidProof {
                reason: "ajtai commitment: truncated ring element",
                party_id: None,
            });
        }
        for coeff_idx in (0..coeffs_per_elem).map(|j| j * 8) {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&chunk[coeff_idx..coeff_idx + 8]);
            let coeff = i64::from_le_bytes(buf);
            // Coefficients must be in centred range (-Q_COMMIT/2, Q_COMMIT/2]
            if coeff <= -half_q || coeff > half_q {
                return Err(NizkError::InvalidProof {
                    reason: "ajtai commitment: coefficient out of range",
                    party_id: None,
                });
            }
        }
    }

    Ok(())
}

/// Deserialize an Ajtai commitment from its canonical byte representation.
#[allow(dead_code)]
fn deserialize_ajtai_commitment(bytes: &[u8]) -> Result<AjtaiCommitment, NizkError> {
    if bytes.len() != AJTAI_RANK * PHI * 8 {
        return Err(NizkError::InvalidProof {
            reason: "ajtai commitment: wrong byte length",
            party_id: None,
        });
    }

    let mut elems = Vec::with_capacity(AJTAI_RANK);
    let coeffs_per_elem = PHI;
    let bytes_per_elem = coeffs_per_elem * 8;

    for chunk in bytes.chunks(bytes_per_elem) {
        if chunk.len() != bytes_per_elem {
            return Err(NizkError::InvalidProof {
                reason: "ajtai commitment: truncated ring element",
                party_id: None,
            });
        }
        let mut coeffs = [0i64; PHI];
        for (j, c) in coeffs.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&chunk[j * 8..(j + 1) * 8]);
            *c = i64::from_le_bytes(buf);
        }
        elems.push(Rq::new(coeffs, Q_COMMIT));
    }

    Ok(AjtaiCommitment { elems })
}

pub(super) fn ajtai_sigma_session_binding(
    session_id: &[u8],
    ajtai_bytes: &[u8],
    ciphertext_bytes: &[u8],
    decrypt_share_bytes: &[u8],
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pvthfhe_foundations::domain_tags::Tag::CycloAjtaiBinding.as_bytes());
    h.update((session_id.len() as u32).to_be_bytes());
    h.update(session_id);
    h.update((ajtai_bytes.len() as u32).to_be_bytes());
    h.update(ajtai_bytes);
    h.update((ciphertext_bytes.len() as u32).to_be_bytes());
    h.update(ciphertext_bytes);
    h.update((decrypt_share_bytes.len() as u32).to_be_bytes());
    h.update(decrypt_share_bytes);
    h.finalize().to_vec()
}

pub(super) fn serialize_ajtai_commitment(ajtai: &AjtaiCommitment) -> Vec<u8> {
    let mut out = Vec::with_capacity(AJTAI_RANK * PHI * 8);
    for elem in &ajtai.elems {
        for &c in &elem.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out
}

pub(super) fn derive_epoch_crs_seed(epoch: u64, session_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(epoch.to_be_bytes());
    h.update(pvthfhe_foundations::domain_tags::Tag::AjtaiCrs.as_bytes());
    h.update(session_id);
    h.finalize().into()
}

pub(super) fn compute_ajtai_commitment(
    crs_seed: &[u8; 32],
    s_i: &[i64],
) -> Result<AjtaiCommitment, NizkError> {
    let params = AjtaiParams::default();
    let matrix = AjtaiMatrix::from_seed(*crs_seed, &params, ajtai_m())?; // allow-seeded-rng: CRS seed is epoch-bound
    let witness_rq: Vec<Rq> = s_i
        .chunks(PHI)
        .map(|chunk| {
            let mut coeffs = [0i64; PHI];
            coeffs[..chunk.len()].copy_from_slice(chunk);
            Rq::new(coeffs, Q_COMMIT)
        })
        .collect();
    AjtaiCommitment::commit(&matrix, &witness_rq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::rlwe_n;

    /// F6 RED: ccs_instance_id must differ when epoch changes.
    /// Without epoch binding, proofs from different epochs hash to the same ccs_id.
    #[test]
    fn test_ccs_instance_id_differs_by_epoch() {
        let stmt_a = NizkStatement {
            ciphertext_bytes: vec![0u8; 32],
            decrypt_share_bytes: vec![0u8; 32],
            pvss_commitment: [0u8; 32],
            params: (65_537, rlwe_n(), 16),
            session_id: "test-f6".to_owned(),
            participant_id: 1,
            epoch: 0,
        };
        let stmt_b = NizkStatement {
            epoch: 1,
            ..stmt_a.clone()
        };

        let id_a = compute_ccs_instance_id(&stmt_a).expect("id_a");
        let id_b = compute_ccs_instance_id(&stmt_b).expect("id_b");

        assert_ne!(
            id_a, id_b,
            "F6: ccs_instance_id must differ when epoch changes. Got same id for epoch 0 and 1"
        );
    }
}
