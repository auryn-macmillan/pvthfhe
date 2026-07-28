//! Public extraction helpers: parse opaque Cyclo NIZK proof bytes back into
//! sigma statements/proofs, Ajtai commitments, and CCS witness encodings.

use crate::ajtai::{AJTAI_RANK, PHI};
use crate::sigma;
use crate::{NizkError, NizkStatement};

use super::codec::{decode_sigma_section_multi, Cursor};
use super::cyclo::{compute_ccs_instance_id, expand_c_rns};
use super::{validate_statement, PROOF_VERSION};

/// Public extraction of sigma proof internals from opaque proof bytes.
///
/// Returns `(d_rns, SigmaProof { t_rns, z_s, z_e, ch })` by parsing
/// the sigma section from the encoded proof.
pub fn extract_sigma_proof(proof_bytes: &[u8]) -> Result<(Vec<u64>, sigma::SigmaProof), NizkError> {
    let mut cur = Cursor::new(proof_bytes);

    let version = cur.read_u16()?;
    if version != PROOF_VERSION {
        return Err(NizkError::InvalidProof {
            reason: "unsupported proof version",
            party_id: None,
        });
    }

    cur.skip(32)?; // ccs_instance_id
    cur.skip(AJTAI_RANK * PHI * 8)?; // ajtai_commitment

    let _sid = cur.read_len_prefixed_bytes()?;
    let _pid = cur.read_u16()?;
    let _commitment: [u8; 32] =
        cur.read_exact(32)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof {
                reason: "bad sha256_binding commitment",
                party_id: None,
            })?;

    let sigma_section_len =
        usize::try_from(cur.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "sigma_section_len overflow",
            party_id: None,
        })?;
    let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();

    let (d_rns, multi_proof) = decode_sigma_section_multi(&sigma_section)?;
    let first_round = multi_proof
        .rounds
        .into_iter()
        .next()
        .ok_or(NizkError::InvalidProof {
            reason: "sigma multi-proof has zero rounds",
            party_id: None,
        })?;
    Ok((d_rns, first_round))
}

/// Public extraction of the full sigma verifier input from opaque proof bytes.
///
/// Returns `(c_rns, d_rns, SigmaProof)` where `c_rns` is the deterministic
/// statement polynomial derived from the encoded CCS instance id and `d_rns`
/// is the proof-embedded decrypt-share polynomial used by the sigma verifier.
/// Returns a `SigmaMultiProof` with all 90 parallel repetition rounds (G1 Option B).
pub fn extract_sigma_statement_and_proof(
    stmt: &NizkStatement,
    proof_bytes: &[u8],
) -> Result<(Vec<u64>, Vec<u64>, sigma::SigmaMultiProof), NizkError> {
    validate_statement(stmt)?;
    let mut cur = Cursor::new(proof_bytes);

    let version = cur.read_u16()?;
    if version != PROOF_VERSION {
        return Err(NizkError::InvalidProof {
            reason: "unsupported proof version",
            party_id: Some(stmt.participant_id),
        });
    }

    let ccs_id: [u8; 32] = cur
        .read_exact(32)?
        .try_into()
        .map_err(|_| NizkError::InvalidProof {
            reason: "bad ccs_instance_id",
            party_id: Some(stmt.participant_id),
        })?;
    let expected_ccs_id = compute_ccs_instance_id(stmt)?;
    if ccs_id != expected_ccs_id {
        return Err(NizkError::VerificationFailed {
            reason: "ccs_instance_id mismatch",
            party_id: Some(stmt.participant_id),
        });
    }

    cur.skip(AJTAI_RANK * PHI * 8)?; // ajtai_commitment
    let _sid = cur.read_len_prefixed_bytes()?;
    let _pid = cur.read_u16()?;
    let _commitment: [u8; 32] =
        cur.read_exact(32)?
            .try_into()
            .map_err(|_| NizkError::InvalidProof {
                reason: "bad sha256_binding commitment",
                party_id: Some(stmt.participant_id),
            })?;

    let sigma_section_len =
        usize::try_from(cur.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "sigma_section_len overflow",
            party_id: Some(stmt.participant_id),
        })?;
    let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();
    let (d_rns, sigma_multi) = decode_sigma_section_multi(&sigma_section)?;
    let c_rns = expand_c_rns(&ccs_id)?;

    Ok((c_rns, d_rns, sigma_multi))
}

/// Extract the Ajtai commitment bytes from a serialized proof.
///
/// The Ajtai commitment is at offset (2 + 32 = 34) after version + ccs_instance_id,
/// and is exactly 26,624 bytes (13 ring elements × 256 coeffs × 8 bytes).
pub fn extract_ajtai_commitment_from_proof(proof_bytes: &[u8]) -> Result<Vec<u8>, NizkError> {
    const AJTAI_OFFSET: usize = 2 + 32; // version(u16 BE) + ccs_instance_id([u8; 32])
    const AJTAI_LEN: usize = AJTAI_RANK * PHI * 8;
    if proof_bytes.len() < AJTAI_OFFSET + AJTAI_LEN {
        return Err(NizkError::InvalidProof {
            reason: "proof too short for Ajtai commitment",
            party_id: None,
        });
    }
    Ok(proof_bytes[AJTAI_OFFSET..AJTAI_OFFSET + AJTAI_LEN].to_vec())
}

/// Extract CCS witness bytes from a serialized proof.
///
/// Encodes the d_rns polynomial (embedded in the sigma proof section) as
/// a CCS witness in Fr format, suitable for `ccs_encode::check_satisfiability`.
/// Falls back to empty witness on parse failure (the satisfiability check at
/// the fold layer independently validates the sigma proof via adapter::verify).
pub fn extract_ccs_witness_from_proof(proof_bytes: &[u8]) -> Result<Vec<u8>, NizkError> {
    let mut cur = Cursor::new(proof_bytes);

    let version = cur.read_u16()?;
    if version != PROOF_VERSION {
        return Err(NizkError::InvalidProof {
            reason: "unsupported proof version",
            party_id: None,
        });
    }

    cur.skip(32)?; // ccs_instance_id
    cur.skip(AJTAI_RANK * PHI * 8)?; // ajtai_commitment
    let _ = cur.read_len_prefixed_bytes()?; // session_id
    let _ = cur.read_u16()?; // participant_id
    cur.skip(32)?; // sha256_binding

    let sigma_section_len =
        usize::try_from(cur.read_u32()?).map_err(|_| NizkError::InvalidProof {
            reason: "sigma_section_len overflow",
            party_id: None,
        })?;
    let sigma_section = cur.read_exact(sigma_section_len)?.to_vec();

    let (d_rns, _sigma_multi) = decode_sigma_section_multi(&sigma_section)?;

    // Encode d_rns coefficients as Fr elements (1-based counter format
    // expected by ccs_encode::parse_witness).
    let num_vars = d_rns.len();
    let mut out = Vec::with_capacity(4 + num_vars * 32);
    out.extend_from_slice(&(num_vars as u32).to_be_bytes());
    for &val in &d_rns {
        // pad u64 to 32-byte Fr LE encoding
        let mut fr_bytes = [0u8; 32];
        fr_bytes[..8].copy_from_slice(&val.to_le_bytes());
        out.extend_from_slice(&fr_bytes);
    }
    Ok(out)
}
