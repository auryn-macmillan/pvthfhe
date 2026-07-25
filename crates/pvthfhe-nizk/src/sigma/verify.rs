//! Verifier side of the RLWE sigma protocol (single-round and parallel repetition).

use crate::NizkError;

use super::challenge::{derive_challenge_from_commitment, derive_transcript_commitment};
use super::sample::rns_add_scalar_mul;
use super::{
    int_poly_to_rns, num_rns_limbs, poly_mul_rq, rlwe_context, rlwe_n, rns_add, SigmaMultiProof,
    SigmaProof, SigmaStatement, B_Z_E, B_Z_S,
};

/// Verify a sigma proof against a statement.
///
/// `session_id` and `participant_id` must match those used during [`super::prove`].
///
/// Returns Ok(()) iff the algebraic equation holds and response norms are within bounds.
pub fn verify(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    d_commitment: &[u8; 32],
) -> Result<(), NizkError> {
    verify_scalar(session_id, participant_id, stmt, proof, d_commitment)
}

/// Verify a scalar-challenge sigma proof against a statement.
///
/// This is the canonical verifier for the v2 protocol where the Fiat-Shamir
/// challenge is a single ternary scalar `ch ∈ {-1, 0, 1}`.  The algebraic check
/// remains `c*z_s + z_e = t + ch*d_i` over `R_Q`; only `ch*d_i` is scalar
/// coefficient-wise multiplication rather than polynomial multiplication.
pub fn verify_scalar(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    d_commitment: &[u8; 32],
) -> Result<(), NizkError> {
    verify_scalar_round(session_id, participant_id, stmt, proof, d_commitment, 0)
}

/// Internal round-aware verifier used by [`verify_multi`].
fn verify_scalar_round(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    d_commitment: &[u8; 32],
    round_index: usize,
) -> Result<(), NizkError> {
    let n = rlwe_n();
    let rns_len = n * num_rns_limbs();
    if stmt.c_rns.len() != rns_len || stmt.d_rns.len() != rns_len {
        return Err(NizkError::InvalidInput {
            reason: "statement RNS lengths must be L*N",
            party_id: None,
        });
    }
    if proof.t_rns.len() != rns_len {
        return Err(NizkError::InvalidInput {
            reason: "proof t_rns length must be L*N",
            party_id: None,
        });
    }
    if proof.z_s.len() != n || proof.z_e.len() != n {
        return Err(NizkError::InvalidInput {
            reason: "proof polynomial lengths must be N",
            party_id: None,
        });
    }
    if proof.ch != -1 && proof.ch != 0 && proof.ch != 1 {
        return Err(NizkError::InvalidInput {
            reason: "challenge must be -1, 0, or 1",
            party_id: None,
        });
    }

    let ctx = rlwe_context()?;

    let transcript_commitment =
        derive_transcript_commitment(&proof.t_rns, &stmt.c_rns, &stmt.d_rns);
    let expected_ch = derive_challenge_from_commitment(
        &transcript_commitment,
        session_id,
        participant_id,
        round_index,
        d_commitment,
    )?;
    // Constant-time comparison for challenge
    let ch_match = (proof.ch ^ expected_ch) == 0;
    if !ch_match {
        return Err(NizkError::VerificationFailed {
            reason: "challenge mismatch",
            party_id: None,
        });
    }

    let max_ze = proof.z_e.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_ze > B_Z_E {
        return Err(NizkError::VerificationFailed {
            reason: "z_e norm bound exceeded",
            party_id: None,
        });
    }
    let max_zs = proof.z_s.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_zs > B_Z_S {
        return Err(NizkError::VerificationFailed {
            reason: "z_s norm bound exceeded",
            party_id: None,
        });
    }

    let z_s_rns = int_poly_to_rns(&proof.z_s, ctx)?;
    let z_e_rns = int_poly_to_rns(&proof.z_e, ctx)?;
    let c_zs_rns = poly_mul_rq(&stmt.c_rns, &z_s_rns, ctx)?;
    let lhs_rns = rns_add(&c_zs_rns, &z_e_rns, ctx)?;

    // ch·d_i: element-wise scalar multiplication (ch ∈ {-1,0,1})
    let rhs_rns = rns_add_scalar_mul(&proof.t_rns, proof.ch, &stmt.d_rns, ctx)?;

    if lhs_rns != rhs_rns {
        return Err(NizkError::VerificationFailed {
            reason: "algebraic equation c*z_s + z_e != t + ch*d_i",
            party_id: None,
        });
    }

    Ok(())
}

/// Verify a multi-round sigma proof against a statement.
///
/// Returns Ok(()) iff ALL k independent rounds pass algebraic and norm checks.
/// Each round's challenge is independently re-derived with round-index binding
/// to prevent cross-round replay. Soundness error = (2/3)^num_rounds where
/// num_rounds = proof.rounds.len().
pub fn verify_multi(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    proof: &SigmaMultiProof,
    d_commitment: &[u8; 32],
) -> Result<(), NizkError> {
    if proof.rounds.is_empty() {
        return Err(NizkError::VerificationFailed {
            reason: "sigma multi-proof must have at least one round",
            party_id: None,
        });
    }
    for (i, round_proof) in proof.rounds.iter().enumerate() {
        verify_scalar_round(
            session_id,
            participant_id,
            stmt,
            round_proof,
            d_commitment,
            i,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::rlwe_n;

    /// F1 RED: verify_multi must reject an empty rounds list.
    /// A SigmaMultiProof with zero rounds passes vacuously without this guard.
    #[test]
    fn test_verify_multi_rejects_empty_rounds() {
        let empty_proof = SigmaMultiProof { rounds: vec![] };
        let stmt = SigmaStatement {
            c_rns: vec![0u64; rlwe_n() * num_rns_limbs()],
            d_rns: vec![0u64; rlwe_n() * num_rns_limbs()],
        };
        let result = verify_multi(b"test", 0, &stmt, &empty_proof, &[0u8; 32]);
        assert!(
            result.is_err(),
            "F1: verify_multi must reject SigmaMultiProof with zero rounds"
        );
    }
}
