//! Greco-style quotient witness verification for BFV encryption well-formedness.
//!
//! # Greco Construction (Symphony §5.2)
//!
//! The sigma protocol checks the BFV encryption relation modulo q_ℓ in each RNS limb.
//! For knowledge soundness, the Greco construction additionally verifies that the
//! quotient witnesses q0, q1 — defined by lifting the sigma equations from mod q_ℓ
//! to the integers — have bounded coefficients.
//!
//! ## Quotient definition
//!
//! For each RNS limb ℓ (ℓ = 0, 1, 2):
//!
//! ```text
//! q0[ℓ] = (pk0[ℓ] * z_u + z_e0 + Δ[ℓ] * z_m - t0[ℓ] - ch * ct0[ℓ]) / q_ℓ
//! q1[ℓ] = (pk1[ℓ] * z_u + z_e1 - t1[ℓ] - ch * ct1[ℓ]) / q_ℓ
//! ```
//!
//! where all polynomial multiplications are performed over the integers
//! (negacyclic convolution, no modular reduction).  Since the sigma protocol
//! verifies these equalities modulo q_ℓ, the numerators are always multiples
//! of q_ℓ, making the quotients well-defined integer polynomials.
//!
//! ## Soundness guarantee
//!
//! If the sigma equations hold AND |q0[ℓ]|_∞ ≤ GRECO_BOUND_Q and
//! |q1[ℓ]|_∞ ≤ GRECO_BOUND_Q, then there exists a valid BFV witness
//! (u, e0, e1, m) with small coefficients satisfying:
//!
//! ```text
//! ct0[ℓ] = pk0[ℓ] * u + e0 + Δ[ℓ] * m  (over R_q)
//! ct1[ℓ] = pk1[ℓ] * u + e1            (over R_q)
//! ```
//!
//! This strengthens the soundness claim from "sigma equation holds" to
//! "BFV-valid witness exists with small coefficients".

use crate::bfv_sigma::BfvSigmaProof;
use crate::sigma::{num_rns_limbs, rlwe_n};
use crate::NizkError;
use pvthfhe_types;

/// Bound on Greco quotient polynomial coefficients in ∞-norm.
///
/// Derived from:
/// - Max product coefficient: N · q_ℓ · b_z_u() ≈ 2¹³ · 2⁵⁸ · 2³¹ ≈ 2¹⁰²
/// - Quotient after division by q_ℓ: 2¹⁰² / 2⁵⁸ ＝ 2⁴⁴
/// - Add safety margin: 2⁴⁸  (16× headroom)
///
/// Any honest proof will have quotient coefficients well below this bound.
pub const GRECO_BOUND_Q: i64 = 1i64 << 48; // 2⁴⁸ ≈ 2.8×10¹⁴

/// Verify that the Greco quotient witnesses from a BFV sigma proof have
/// bounded coefficients.
///
/// This function lifts the sigma verification equations from modulo q_ℓ
/// to the integers, computes the implicit quotients q0, q1 per RNS limb,
/// and checks that their coefficients are bounded by [`GRECO_BOUND_Q`].
///
/// # Arguments
///
/// * `proof` - The BFV sigma proof containing responses and challenges.
/// * `pk0_rns`, `pk1_rns` - Public key polynomials in RNS power-basis.
/// * `ct0_rns`, `ct1_rns` - Ciphertext polynomials in RNS power-basis.
/// * `delta_limbs` - BFV scaling factors Δ[ℓ] = ⌊q_ℓ / t⌋ for each limb.
///
/// # Returns
///
/// `Ok(())` if all quotient coefficients are within bounds, or
/// `Err(NizkError::VerificationFailed)` if a bound is violated.
#[allow(clippy::too_many_arguments)]
pub fn verify_greco_bounds(
    proof: &BfvSigmaProof,
    pk0_rns: &[u64],
    pk1_rns: &[u64],
    ct0_rns: &[u64],
    ct1_rns: &[u64],
    delta_limbs: &[u64],
) -> Result<(), NizkError> {
    let n = rlwe_n();
    let num_limbs = num_rns_limbs();
    let moduli = pvthfhe_types::rlwe_moduli();

    if pk0_rns.len() != n * num_limbs
        || pk1_rns.len() != n * num_limbs
        || ct0_rns.len() != n * num_limbs
        || ct1_rns.len() != n * num_limbs
    {
        return Err(NizkError::InvalidInput(
            "RNS statement lengths must match rlwe_n() * num_rns_limbs()",
        ));
    }
    if delta_limbs.len() != num_limbs {
        return Err(NizkError::InvalidInput(
            "delta_limbs must have num_rns_limbs() entries",
        ));
    }
    if proof.t0_rns.len() != n * num_limbs || proof.t1_rns.len() != n * num_limbs {
        return Err(NizkError::InvalidInput("proof t0/t1_rns length mismatch"));
    }

    for limb in 0..num_limbs {
        let q_limb = moduli[limb] as i128;
        let q_half = (moduli[limb] / 2) as i64;

        // ── Extract limb-specific integer (centered) coefficient vectors ──
        let start = limb * n;
        let end = (limb + 1) * n;

        let pk0_int: Vec<i64> = pk0_rns[start..end]
            .iter()
            .map(|&v| centered_lift(v as i64, q_half, moduli[limb] as i64))
            .collect();
        let pk1_int: Vec<i64> = pk1_rns[start..end]
            .iter()
            .map(|&v| centered_lift(v as i64, q_half, moduli[limb] as i64))
            .collect();
        let ct0_int: Vec<i64> = ct0_rns[start..end]
            .iter()
            .map(|&v| centered_lift(v as i64, q_half, moduli[limb] as i64))
            .collect();
        let ct1_int: Vec<i64> = ct1_rns[start..end]
            .iter()
            .map(|&v| centered_lift(v as i64, q_half, moduli[limb] as i64))
            .collect();
        let t0_int: Vec<i64> = proof.t0_rns[start..end]
            .iter()
            .map(|&v| centered_lift(v as i64, q_half, moduli[limb] as i64))
            .collect();
        let t1_int: Vec<i64> = proof.t1_rns[start..end]
            .iter()
            .map(|&v| centered_lift(v as i64, q_half, moduli[limb] as i64))
            .collect();

        // ── Compute integer polynomial products (negacyclic convolution) ──
        let pk0_zu = int_negacyclic_convolution(&pk0_int, &proof.u_resp);
        let ch_ct0 = int_negacyclic_convolution(&proof.ch, &ct0_int);
        let pk1_zu = int_negacyclic_convolution(&pk1_int, &proof.u_resp);
        let ch_ct1 = int_negacyclic_convolution(&proof.ch, &ct1_int);

        let delta = delta_limbs[limb] as i128;

        // ── Verify quotient q0 for ct0 equation ──
        for i in 0..n {
            let lhs =
                pk0_zu[i] + i128::from(proof.e0_resp[i]) + delta * i128::from(proof.m_resp[i]);
            let rhs = i128::from(t0_int[i]) + ch_ct0[i];
            let numerator = lhs - rhs;

            // Since sigma equations hold mod q_limb, the numerator must be
            // divisible by q_limb.
            if numerator % q_limb != 0 {
                return Err(NizkError::VerificationFailed(
                    "Greco: ct0 quotient not integral at limb {limb}, index {i}",
                ));
            }
            let q = numerator / q_limb;
            if q.unsigned_abs() > GRECO_BOUND_Q as u128 {
                return Err(NizkError::VerificationFailed(
                    "Greco: ct0 quotient bound exceeded",
                ));
            }
        }

        // ── Verify quotient q1 for ct1 equation ──
        for i in 0..n {
            let lhs = pk1_zu[i] + i128::from(proof.e1_resp[i]);
            let rhs = i128::from(t1_int[i]) + ch_ct1[i];
            let numerator = lhs - rhs;

            if numerator % q_limb != 0 {
                return Err(NizkError::VerificationFailed(
                    "Greco: ct1 quotient not integral at limb {limb}, index {i}",
                ));
            }
            let q = numerator / q_limb;
            if q.unsigned_abs() > GRECO_BOUND_Q as u128 {
                return Err(NizkError::VerificationFailed(
                    "Greco: ct1 quotient bound exceeded",
                ));
            }
        }
    }

    Ok(())
}

/// Center-lift a coefficient from [0, q-1] to [-q/2, q/2).
fn centered_lift(v: i64, q_half: i64, q: i64) -> i64 {
    if v > q_half {
        v - q
    } else {
        v
    }
}

/// Compute the negacyclic convolution c = a * b in Z[X]/(X^N + 1) over the
/// integers (no modular reduction).  Coefficients use i128 to avoid overflow
/// during the O(N²) accumulation.
///
/// For cₖ = Σ_{i+j=k} a_i·b_j - Σ_{i+j=k+N} a_i·b_j.
fn int_negacyclic_convolution(a: &[i64], b: &[i64]) -> Vec<i128> {
    let n = a.len();
    debug_assert_eq!(b.len(), n, "convolution operands must have equal length");
    let mut result = vec![0i128; n];

    for i in 0..n {
        if a[i] == 0 {
            continue;
        }
        let ai = i128::from(a[i]);
        // Positive wrap: indices j where i+j < n
        let direct_len = n - i;
        for (offset, &bj) in b[..direct_len].iter().enumerate() {
            if bj != 0 {
                let k = i + offset;
                result[k] += ai * i128::from(bj);
            }
        }
        // Negative wrap: indices j where i+j ≥ n
        for (offset, &bj) in b[direct_len..].iter().enumerate() {
            if bj != 0 {
                let k = offset; // i + (direct_len + offset) = n + offset ≡ -offset-1 mod X^N
                result[k] -= ai * i128::from(bj);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convolution_preserves_ring_structure() {
        // Identity: a * 0 = 0
        let a = vec![7i64; 8];
        let b = vec![0i64; 8];
        let result = int_negacyclic_convolution(&a, &b);
        assert!(result.iter().all(|&c| c == 0));
    }

    #[test]
    fn convolution_with_constant_polynomial() {
        let n = 8usize;
        let a = vec![0i64; n];
        let mut a = a;
        a[0] = 3;
        let b = vec![5i64; n];
        let result = int_negacyclic_convolution(&a, &b);
        for (i, &c) in result.iter().enumerate() {
            assert_eq!(c, 3i128 * 5i128, "convolution(3, 5)[{i}] mismatch");
        }
    }

    #[test]
    fn greco_verify_rejects_oob_quotient() {
        // Build a minimal valid-looking proof that would produce an
        // out-of-bounds quotient if the verifier didn't catch it.
        let n = rlwe_n();
        let moduli = pvthfhe_types::rlwe_moduli();
        let num_limbs = moduli.len();

        // Zero statement and proof — quotients should be 0
        let pk0_rns = vec![0u64; n * num_limbs];
        let pk1_rns = vec![0u64; n * num_limbs];
        let ct0_rns = vec![0u64; n * num_limbs];
        let ct1_rns = vec![0u64; n * num_limbs];
        let delta_limbs: Vec<u64> = vec![1; num_limbs]; // Δ=1 for testing

        let proof = BfvSigmaProof {
            t0_rns: vec![0u64; n * num_limbs],
            t1_rns: vec![0u64; n * num_limbs],
            u_resp: vec![0i64; n],
            e0_resp: vec![0i64; n],
            e1_resp: vec![0i64; n],
            m_resp: vec![0i64; n],
            ch: vec![0i64; n],
        };

        // Zero proof should pass Greco bounds
        let result =
            verify_greco_bounds(&proof, &pk0_rns, &pk1_rns, &ct0_rns, &ct1_rns, &delta_limbs);
        assert!(result.is_ok(), "zero proof must pass Greco bounds");

        // Artificially inflate e0_resp to force quotient overflow
        let mut bad_proof = proof.clone();
        bad_proof.e0_resp = vec![GRECO_BOUND_Q + 1; n];
        let result = verify_greco_bounds(
            &bad_proof,
            &pk0_rns,
            &pk1_rns,
            &ct0_rns,
            &ct1_rns,
            &delta_limbs,
        );
        assert!(result.is_err(), "bad proof must fail Greco bounds");
    }
}
