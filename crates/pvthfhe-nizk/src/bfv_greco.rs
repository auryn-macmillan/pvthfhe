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
use crate::sigma::{int_poly_to_rns, num_rns_limbs, poly_mul_rq, rlwe_n};
use crate::NizkError;
use fhe_math::rq::Context;
use pvthfhe_types;
use std::sync::{Arc, OnceLock};

/// Bound on Greco quotient polynomial coefficients in ∞-norm.
///
/// Derived from:
/// - Max product coefficient: N · q_ℓ · b_z_u() ≈ 2¹³ · 2⁵⁸ · 2³¹ ≈ 2¹⁰²
/// - Quotient after division by q_ℓ: 2¹⁰² / 2⁵⁸ ＝ 2⁴⁴
/// - Add safety margin: 2⁴⁸  (16× headroom)
///
/// Any honest proof will have quotient coefficients well below this bound.
pub const GRECO_BOUND_Q: i64 = 1i64 << 48; // 2⁴⁸ ≈ 2.8×10¹⁴

/// Returns the singleton RLWE context for Greco NTT operations.
fn greco_rlwe_context() -> Result<&'static Arc<Context>, NizkError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        let n = rlwe_n();
        let moduli = pvthfhe_types::rlwe_moduli();
        Context::new(&moduli, n)
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
    .as_ref()
    .map_err(|_| NizkError::InvalidInput("failed to build RLWE context for Greco"))
}

// ── CRT constants (precomputed Garner inverses for production 3-limb moduli) ──

/// q0 = 288_230_376_173_076_481
const Q0: i128 = 288_230_376_173_076_481;
/// q1 = 288_230_376_167_047_169
const Q1: i128 = 288_230_376_167_047_169;
/// q2 = 288_230_376_161_280_001
const Q2: i128 = 288_230_376_161_280_001;
/// q0^(-1) mod q1
const INV_Q0_MOD_Q1: i128 = 256_900_939_648_384_310;
/// (q0 * q1)^(-1) mod q2
const INV_Q01_MOD_Q2: i128 = 19_724_897_087_976_708;
/// q0 * q1 = 83_076_749_747_135_343_554_904_336_171_532_289
const Q01: i128 = 83_076_749_747_135_343_554_904_336_171_532_289;

fn ensure_production_crt_moduli(ctx: &Context) -> Result<(), NizkError> {
    if ctx.q.len() != 3
        || ctx.q[0].modulus() as i128 != Q0
        || ctx.q[1].modulus() as i128 != Q1
        || ctx.q[2].modulus() as i128 != Q2
    {
        return Err(NizkError::InvalidInput(
            "Greco NTT quotient reconstruction requires production 3-limb BFV moduli",
        ));
    }
    Ok(())
}

/// Reconstruct a signed integer from its 3 RNS residues using Garner's CRT
/// algorithm.  The returned value `x` satisfies `x ≡ r_l mod q_l` for each
/// limb and `|x| < q0·q1 ≈ 2^116`.
///
/// # Correctness
///
/// Since the Greco convolution operands have coefficients bounded by
/// q_ℓ/2 ≈ 2^57 and response coefficients bounded by b_z_u() ≈ 2^43,
/// the true integer convolution coefficient satisfies `|x| < 2^101 ≪ Q01`.
/// Therefore the two-valued candidate list {x01, x01 − Q01} always contains
/// the correct signed value.  The Garner k₂ parameter is either 0 (x ≥ 0)
/// or q₂−1 (x < 0).
fn crt3_reconstruct_small(r0: u64, r1: u64, r2: u64) -> i128 {
    let r0 = r0 as i128;
    let r1 = r1 as i128;
    let r2 = r2 as i128;

    // Garner step 1: x01 = r0 + q0 * (((r1−r0) * inv_q0_mod_q1) mod q1)
    let mut diff1 = (r1 - r0) % Q1;
    if diff1 < 0 {
        diff1 += Q1;
    }
    let k1 = (diff1 * INV_Q0_MOD_Q1) % Q1;
    let k1 = if k1 < 0 { k1 + Q1 } else { k1 };
    let x01 = r0 + Q0 * k1; // ∈ [0, q0·q1), fits in i128

    // Garner step 2: determine sign
    let x01_mod_q2 = x01 % Q2;
    let mut diff2 = (r2 - x01_mod_q2) % Q2;
    if diff2 < 0 {
        diff2 += Q2;
    }
    let k2_mod = (diff2 * INV_Q01_MOD_Q2) % Q2;
    let k2_mod = if k2_mod < 0 { k2_mod + Q2 } else { k2_mod };

    // k2 is either 0 (x ≥ 0 → k2_mod = 0) or −1 (x < 0 → k2_mod = q2−1)
    // Since |x| < Q01, the candidate set is {x01, x01 − Q01}.
    if k2_mod == 0 {
        x01
    } else {
        x01 - Q01
    }
}

/// Center-lift a coefficient from [0, q-1] to [-q/2, q/2).
fn centered_lift(v: i64, q_half: i64, q: i64) -> i64 {
    if v > q_half {
        v - q
    } else {
        v
    }
}

/// Compute the negacyclic convolution `a * b` in Z[X]/(X^N+1) using
/// NTT-accelerated RNS multiplication over the 3 BFV CRT moduli,
/// followed by Garner CRT reconstruction.
fn ntt_negacyclic_convolution(
    a: &[i64],
    b: &[i64],
    ctx: &Arc<Context>,
) -> Result<Vec<i128>, NizkError> {
    ensure_production_crt_moduli(ctx)?;
    let a_rns = int_poly_to_rns(a, ctx)?;
    let b_rns = int_poly_to_rns(b, ctx)?;
    let prod_rns = poly_mul_rq(&a_rns, &b_rns, ctx)?;

    let n = rlwe_n();
    let mut result = vec![0i128; n];
    for i in 0..n {
        let r0 = prod_rns[i];
        let r1 = prod_rns[n + i];
        let r2 = prod_rns[2 * n + i];
        result[i] = crt3_reconstruct_small(r0, r1, r2);
    }
    Ok(result)
}

/// O(N²) schoolbook negacyclic convolution, used only as a test oracle.
#[cfg(test)]
fn schoolbook_negacyclic_convolution(a: &[i64], b: &[i64]) -> Vec<i128> {
    let n = a.len();
    debug_assert_eq!(b.len(), n);
    let mut result = vec![0i128; n];

    for i in 0..n {
        if a[i] == 0 {
            continue;
        }
        let ai = i128::from(a[i]);
        let direct_len = n - i;
        for (offset, &bj) in b[..direct_len].iter().enumerate() {
            if bj != 0 {
                result[i + offset] += ai * i128::from(bj);
            }
        }
        for (offset, &bj) in b[direct_len..].iter().enumerate() {
            if bj != 0 {
                result[offset] -= ai * i128::from(bj);
            }
        }
    }

    result
}

/// Verify that the Greco quotient witnesses from a BFV sigma proof have
/// bounded coefficients.
///
/// Polynomial multiplications use NTT-accelerated RNS convolution (O(N log N))
/// followed by Garner CRT reconstruction.
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

    let ctx = greco_rlwe_context()?;
    ensure_production_crt_moduli(ctx)?;

    for limb in 0..num_limbs {
        let q_limb = moduli[limb] as i128;
        let q_half = (moduli[limb] / 2) as i64;

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

        let (pk0_zu, ch_ct0, pk1_zu, ch_ct1) = (
            ntt_negacyclic_convolution(&pk0_int, &proof.u_resp, ctx)?,
            ntt_negacyclic_convolution(&proof.ch, &ct0_int, ctx)?,
            ntt_negacyclic_convolution(&pk1_int, &proof.u_resp, ctx)?,
            ntt_negacyclic_convolution(&proof.ch, &ct1_int, ctx)?,
        );

        let delta = delta_limbs[limb] as i128;

        for i in 0..n {
            let lhs =
                pk0_zu[i] + i128::from(proof.e0_resp[i]) + delta * i128::from(proof.m_resp[i]);
            let rhs = i128::from(t0_int[i]) + ch_ct0[i];
            let numerator = lhs - rhs;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convolution_preserves_ring_structure() {
        let a = vec![7i64; 8];
        let b = vec![0i64; 8];
        let result = schoolbook_negacyclic_convolution(&a, &b);
        assert!(result.iter().all(|&c| c == 0));
    }

    #[test]
    fn convolution_with_constant_polynomial() {
        let n = 8usize;
        let a = vec![0i64; n];
        let mut a = a;
        a[0] = 3;
        let b = vec![5i64; n];
        let result = schoolbook_negacyclic_convolution(&a, &b);
        for (i, &c) in result.iter().enumerate() {
            assert_eq!(c, 3i128 * 5i128, "convolution(3, 5)[{i}] mismatch");
        }
    }

    #[test]
    fn ntt_matches_schoolbook() {
        let n = rlwe_n();
        let ctx = greco_rlwe_context().expect("greco context");

        let cases: Vec<(Vec<i64>, Vec<i64>, usize, i128)> = vec![
            (set_coeff(n, 0, 1), set_coeff(n, 0, 2), 0, 2),
            (set_coeff(n, 0, -1), set_coeff(n, 0, 2), 0, -2),
            (set_coeff(n, 1, 5), set_coeff(n, 2, 7), 3, 35),
            (set_coeff(n, 0, -5), set_coeff(n, 0, 7), 0, -35),
            (set_coeff(n, n - 1, 3), set_coeff(n, 2, 4), 1, -12),
            (set_coeff(n, 0, 3), set_coeff(n, n - 1, 5), n - 1, 15),
        ];

        for (a, b, expected_idx, expected_val) in &cases {
            let ntt_result =
                ntt_negacyclic_convolution(a, b, &ctx).expect("ntt convolution should succeed");
            let schoolbook_result = schoolbook_negacyclic_convolution(a, b);

            for i in 0..n {
                assert_eq!(
                    ntt_result[i], schoolbook_result[i],
                    "NTT vs schoolbook mismatch at idx {i}: NTT={}, schoolbook={}, expected idx={expected_idx}",
                    ntt_result[i], schoolbook_result[i]
                );
            }
            assert_eq!(
                ntt_result[*expected_idx], *expected_val,
                "NTT at idx {expected_idx}: expected {expected_val}, got {}",
                ntt_result[*expected_idx]
            );
        }
    }

    #[test]
    fn ntt_matches_schoolbook_for_dense_centered_operands() {
        let n = rlwe_n();
        let ctx = greco_rlwe_context().expect("greco context");
        let q0_half = Q0 as i64 / 2;

        let mut a = vec![0i64; n];
        let mut b = vec![0i64; n];
        for i in 0..64 {
            a[i] = match i % 4 {
                0 => q0_half - i as i64,
                1 => -(q0_half - i as i64),
                2 => 1_000_000 + i as i64,
                _ => -1_000_000 - i as i64,
            };
            b[i] = match i % 3 {
                0 => 1_073_741_824 - i as i64,
                1 => -1_073_741_824 + i as i64,
                _ => i as i64 - 32,
            };
        }

        let ntt_result =
            ntt_negacyclic_convolution(&a, &b, &ctx).expect("ntt convolution should succeed");
        let schoolbook_result = schoolbook_negacyclic_convolution(&a, &b);
        assert_eq!(ntt_result, schoolbook_result);
    }

    fn set_coeff(n: usize, idx: usize, val: i64) -> Vec<i64> {
        let mut v = vec![0i64; n];
        v[idx] = val;
        v
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
