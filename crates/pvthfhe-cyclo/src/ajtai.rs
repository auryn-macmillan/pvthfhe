//! Ajtai commitment scheme over `R_{q_commit}`.
//!
//! Provides binding commitments to short witness vectors in the cyclotomic
//! ring `Z_q[X]/(X^256+1)`. The commitment matrix `A ∈ R_q^{m×n}` is derived
//! deterministically from a seed stored in [`AjtaiParams`].

use crate::ring::{
    bytes_to_rqpoly, ntt_mul, ring_add_poly, rqpoly_to_bytes, RqPoly, PHI_COMMIT, Q_COMMIT,
};
use crate::CycloError;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Parameters for the Ajtai commitment scheme over `R_q`.
///
/// The commitment matrix `A ∈ R_q^{m×n}` is derived deterministically from
/// [`seed`](Self::seed) using a ChaCha20 PRNG.
#[derive(Clone, Debug)]
pub struct AjtaiParams {
    /// Number of rows (commitment vector length).
    pub m: usize,
    /// Number of columns (witness vector length).
    pub n: usize,
    /// Commitment modulus `q_commit`.
    pub q_commit: u64,
    /// 32-byte seed for deterministic matrix generation.
    pub seed: [u8; 32],
}

/// An Ajtai commitment: the vector `c = A·w ∈ R_q^m`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AjtaiCommitment {
    /// Commitment vector of `m` ring elements.
    pub commitment: Vec<RqPoly>,
}

fn generate_matrix(params: &AjtaiParams) -> Vec<Vec<RqPoly>> {
    let mut rng = ChaCha20Rng::from_seed(params.seed); // allow-seeded-rng: deterministic Ajtai matrix generation from CRS seed
    let mut matrix = Vec::with_capacity(params.m);
    for _row in 0..params.m {
        let mut row = Vec::with_capacity(params.n);
        for _col in 0..params.n {
            let coeffs: Vec<u64> = (0..PHI_COMMIT).map(|_| rng.next_u64() % Q_COMMIT).collect();
            row.push(RqPoly(coeffs));
        }
        matrix.push(row);
    }
    matrix
}

/// Produces an Ajtai commitment `c = A·w` where `A` is the
/// deterministically-generated commitment matrix.
///
/// The `rng` parameter is retained for interface compatibility; the matrix
/// is always derived from [`AjtaiParams::seed`].
pub fn commit(
    params: &AjtaiParams,
    witness: &[RqPoly],
    _rng: &mut dyn RngCore,
) -> Result<AjtaiCommitment, CycloError> {
    if witness.len() != params.n {
        return Err(CycloError::InvalidInstance(
            "witness length must equal params.n",
        ));
    }

    let matrix = generate_matrix(params);
    let mut commitment = Vec::with_capacity(params.m);

    for row in &matrix {
        let mut acc = RqPoly::zero();
        for (j, wj) in witness.iter().enumerate() {
            let prod = ntt_mul(&row[j], wj)?;
            acc = ring_add_poly(&acc, &prod);
        }
        commitment.push(acc);
    }

    Ok(AjtaiCommitment { commitment })
}

/// Verifies that a commitment was produced from the given witness.
///
/// Recomputes `A·w` from the deterministic matrix and checks element-wise
/// equality against the stored commitment vector.
pub fn verify(params: &AjtaiParams, commitment: &AjtaiCommitment, witness: &[RqPoly]) -> bool {
    if commitment.commitment.len() != params.m {
        return false;
    }
    if witness.len() != params.n {
        return false;
    }

    let matrix = generate_matrix(params);

    for (i, row) in matrix.iter().enumerate() {
        let mut acc = RqPoly::zero();
        for (j, wj) in witness.iter().enumerate() {
            let Ok(prod) = ntt_mul(&row[j], wj) else {
                return false;
            };
            acc = ring_add_poly(&acc, &prod);
        }
        if acc != commitment.commitment[i] {
            return false;
        }
    }

    true
}

/// Serialises an [`AjtaiCommitment`] to raw bytes (concatenated u64-LE
/// polynomials).
pub fn encode_commitment(c: &AjtaiCommitment) -> Vec<u8> {
    let mut out = Vec::with_capacity(c.commitment.len() * PHI_COMMIT * 8);
    for poly in &c.commitment {
        out.extend_from_slice(&rqpoly_to_bytes(poly));
    }
    out
}

/// Deserialises an [`AjtaiCommitment`] from raw bytes.
///
/// `m` must match the number of ring elements encoded in `data`.
pub fn decode_commitment(data: &[u8], m: usize) -> Result<AjtaiCommitment, CycloError> {
    let per_poly = PHI_COMMIT * 8;
    let expected_len = m * per_poly;
    if data.len() != expected_len {
        return Err(CycloError::InvalidInstance(
            "commitment wire bytes have wrong length",
        ));
    }

    let commitment: Vec<RqPoly> = data.chunks(per_poly).map(bytes_to_rqpoly).collect();

    Ok(AjtaiCommitment { commitment })
}
