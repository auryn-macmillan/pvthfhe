//! Ring abstraction for the NIFS fold engine.
//!
//! The [`FoldRing`] trait captures the operations that the LatticeFold+
//! NIFS prover/verifier requires from the underlying ring.  Both the
//! existing N=256 commitment ring (`RqPoly` from `crate::ring`) and the
//! new per-channel rings (`pvthfhe_rings::FheMathRing`) implement it,
//! enabling the fold engine to be generic over ring types.

use crate::CycloError;

/// Trait for ring operations used by the NIFS fold engine.
pub trait FoldRing {
    /// The concrete polynomial type for this ring.
    type Poly: Clone + PartialEq;

    /// Ring degree N (power of two).
    fn degree(&self) -> usize;

    /// Ring modulus q.
    fn modulus(&self) -> u64;

    /// Zero polynomial.
    fn zero(&self) -> Self::Poly;

    /// Add two ring elements.
    fn add_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError>;

    /// Subtract `b` from `a`.
    fn sub_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError>;

    /// Multiply two ring elements.
    fn mul_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError>;

    /// L-infinity norm (max absolute centered coefficient).
    fn linf_norm(&self, a: &Self::Poly) -> u64;

    /// Decompose a ring element into balanced base-B limbs.
    fn decompose(&self, a: &Self::Poly, base: u64, limb_count: usize) -> Vec<Self::Poly>;

    /// Recompose from balanced base-B limbs.
    fn recompose(&self, limbs: &[Self::Poly], base: u64) -> Result<Self::Poly, CycloError>;

    /// Serialize coefficient data to bytes for Fiat-Shamir hashing.
    fn poly_to_bytes(&self, a: &Self::Poly) -> Vec<u8>;
}

// ── Generic NIFS fold step ─────────────────────────────────────────────────

/// Generic NIFS fold step over any [`FoldRing`] implementation.
///
/// Core logic: given an accumulator `(acc_commitment, acc_witness)` and a new
/// instance `(inst_commitment, inst_witness)`, compute the Fiat-Shamir challenge
/// from the accumulator commitment hash, then produce the folded accumulator:
///
/// ```text
/// challenge = H(acc_commitment || instance_commitment) mod 3  →  {−1, 0, 1}
/// new_witness = acc_witness + challenge * inst_witness
/// new_commitment = acc_commitment + challenge * inst_commitment
/// ```
///
/// The ternary challenge is derived via rejection sampling from SHA-256 output,
/// matching the Cyclo ternary challenge distribution (Cyclo ePrint 2026/359 §5.5).
pub fn fold_one_generic<R: FoldRing>(
    ring: &R,
    acc_commitment: &R::Poly,
    acc_witness: &R::Poly,
    inst_commitment: &R::Poly,
    inst_witness: &R::Poly,
) -> Result<(R::Poly, R::Poly), CycloError> {
    // Derive challenge from accumulator commitment via ring-provided serialization
    let acc_bytes = ring.poly_to_bytes(acc_commitment);
    let inst_bytes = ring.poly_to_bytes(inst_commitment);

    let challenge = ternary_challenge_from_hashes(&acc_bytes, &inst_bytes);

    match challenge {
        0 => Ok((acc_commitment.clone(), acc_witness.clone())),
        -1 => {
            // new = acc - inst
            let new_commitment = ring.sub_poly(acc_commitment, inst_commitment)?;
            let new_witness = ring.sub_poly(acc_witness, inst_witness)?;
            Ok((new_commitment, new_witness))
        }
        1 => {
            // new = acc + inst
            let new_commitment = ring.add_poly(acc_commitment, inst_commitment)?;
            let new_witness = ring.add_poly(acc_witness, inst_witness)?;
            Ok((new_commitment, new_witness))
        }
        _ => unreachable!(),
    }
}

/// Derive a ternary challenge from two byte slices via SHA-256 + rejection sampling.
fn ternary_challenge_from_hashes(a: &[u8], b: &[u8]) -> i8 {
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::new()
        .chain_update(a)
        .chain_update(b)
        .finalize()
        .into();
    for &byte in &hash {
        if let Some(ch) = crate::fiat_shamir::uniform_ternary(byte) {
            return ch;
        }
    }
    0
}

// ── Implementation for the existing N=256 commitment ring ──────────────────

/// Zero-sized wrapper for the N=256 commitment ring (global NTT context).
///
/// The existing ring module (`crate::ring`) uses free functions and a global
/// singleton context.  This wrapper provides the `FoldRing` interface.
pub struct Cyclo256Ring;

impl FoldRing for Cyclo256Ring {
    type Poly = crate::ring::RqPoly;

    fn degree(&self) -> usize {
        crate::ring::PHI_COMMIT
    }

    fn modulus(&self) -> u64 {
        crate::ring::Q_COMMIT
    }

    fn zero(&self) -> Self::Poly {
        crate::ring::RqPoly::zero()
    }

    fn add_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError> {
        Ok(crate::ring::ring_add_poly(a, b))
    }

    fn sub_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError> {
        // a - b = a + (-1) * b (mod q)
        let neg_one = (crate::ring::Q_COMMIT - 1) as u128;
        let neg_b = crate::ring::scalar_mul(b, neg_one);
        Ok(crate::ring::ring_add_poly(a, &neg_b))
    }

    fn mul_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError> {
        crate::ring::ntt_mul(a, b)
    }

    fn linf_norm(&self, a: &Self::Poly) -> u64 {
        crate::ring::norm_inf(a)
    }

    fn decompose(&self, a: &Self::Poly, base: u64, limb_count: usize) -> Vec<Self::Poly> {
        let coeffs = &a.0;
        let shift_bits = base.trailing_zeros() as u32;
        let mask = base - 1;
        (0..limb_count)
            .map(|k| {
                let shift = k as u32 * shift_bits;
                let limb_coeffs: Vec<u64> = coeffs.iter().map(|&c| (c >> shift) & mask).collect();
                crate::ring::RqPoly(limb_coeffs)
            })
            .collect()
    }

    fn recompose(&self, limbs: &[Self::Poly], base: u64) -> Result<Self::Poly, CycloError> {
        let degree = self.degree();
        let shift_bits = base.trailing_zeros() as u32;
        let mut result = vec![0u64; degree];
        for (k, limb) in limbs.iter().enumerate() {
            let shift = k as u32 * shift_bits;
            for (i, &c) in limb.0.iter().enumerate() {
                result[i] = result[i].wrapping_add(c << shift);
            }
        }
        Ok(crate::ring::RqPoly(result))
    }

    fn poly_to_bytes(&self, a: &Self::Poly) -> Vec<u8> {
        crate::ring::rqpoly_to_bytes(a)
    }
}

// ── Implementation for per-channel rings (pvthfhe-rings) ────────────────────

impl FoldRing for pvthfhe_rings::FheMathRing {
    type Poly = pvthfhe_rings::RqPoly;

    fn degree(&self) -> usize {
        self.degree()
    }

    fn modulus(&self) -> u64 {
        self.modulus()
    }

    fn zero(&self) -> Self::Poly {
        pvthfhe_rings::RqPoly::zero(self.degree())
    }

    fn add_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError> {
        Ok(self.add(a, b))
    }

    fn sub_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError> {
        Ok(self.sub(a, b))
    }

    fn mul_poly(&self, a: &Self::Poly, b: &Self::Poly) -> Result<Self::Poly, CycloError> {
        Ok(self.mul(a, b))
    }

    fn linf_norm(&self, a: &Self::Poly) -> u64 {
        self.linf_norm(a)
    }

    fn decompose(&self, a: &Self::Poly, base: u64, limb_count: usize) -> Vec<Self::Poly> {
        let shift_bits = base.trailing_zeros() as u32;
        let mask = base - 1;
        (0..limb_count)
            .map(|k| {
                let shift = k as u32 * shift_bits;
                let limb_coeffs: Vec<u64> = a.coeffs.iter().map(|&c| (c >> shift) & mask).collect();
                pvthfhe_rings::RqPoly {
                    coeffs: limb_coeffs,
                    degree: self.degree(),
                }
            })
            .collect()
    }

    fn recompose(&self, limbs: &[Self::Poly], base: u64) -> Result<Self::Poly, CycloError> {
        let degree = self.degree();
        let shift_bits = base.trailing_zeros() as u32;
        let mut result = vec![0u64; degree];
        for (k, limb) in limbs.iter().enumerate() {
            let shift = k as u32 * shift_bits;
            for (i, &c) in limb.coeffs.iter().enumerate() {
                result[i] = result[i].wrapping_add(c << shift);
            }
        }
        Ok(pvthfhe_rings::RqPoly {
            coeffs: result,
            degree,
        })
    }

    fn poly_to_bytes(&self, a: &Self::Poly) -> Vec<u8> {
        a.coeffs.iter().flat_map(|c| c.to_le_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_ring_add_sub_roundtrip() {
        let ring = Cyclo256Ring;
        let a = ring.zero();
        let b = ring.zero();
        let sum = ring.add_poly(&a, &b).unwrap();
        let diff = ring.sub_poly(&sum, &b).unwrap();
        assert_eq!(diff, a);
    }

    #[test]
    fn fold_ring_decompose_recompose_roundtrip() {
        let ring = Cyclo256Ring;
        let degree = ring.degree();
        let coeffs: Vec<u64> = (0..degree).map(|i| i as u64).collect();
        let a = crate::ring::RqPoly(coeffs);
        let limbs = ring.decompose(&a, 1 << 16, 4);
        let back = ring.recompose(&limbs, 1 << 16).unwrap();
        assert_eq!(a, back);
    }
}
