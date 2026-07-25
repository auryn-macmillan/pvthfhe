//! Schnorr-style sigma protocol over the active parameter preset RLWE ring.
//!
//! # Ring
//! R_Q = Z_Q\[X\]/(X^N+1), Q = ∏ q_i (L RNS limbs).
//! Polynomial arithmetic uses the fhe-math NTT backend.
//!
//! # Relation
//! Statement: (c, d_i) in R_Q^2.
//! Witness:   (s_i, e_i) with norm_inf(s_i) <= 1 (ternary), norm_inf(e_i) <= SIGMA_B_E = 16.
//! Relation:  d_i = c * s_i + e_i  (mod Q).
//!
//! # Challenge Space
//! Scalar ternary ch in {-1, 0, 1} derived via Fiat-Shamir (Poseidon over BN254
//! with SHA-256 field compression). The challenge space size is ~2^254 (stronger
//! than the old binary-poly 2^8192 for soundness but makes in-circuit verification
//! tractable: NTT with constant twiddle factors = zero R1CS multiplications).
//!
//! Masking bound B_Y = 2^14.
//! z_s = y_s + ch * s_i  (element-wise scalar); bound B_Z_S = 2^15.
//! z_e = y_e + ch * e_i  (element-wise scalar); bound B_Z_E = 2^15.
//! Rejection sampling (Lyubashevsky 2009) ensures ZK at these tight bounds.

mod challenge;
mod prove;
mod sample;
mod verify;

pub use challenge::{
    derive_challenge_from_commitment, derive_transcript_commitment, uniform_ternary,
};
pub use prove::{prove, prove_multi};
pub use sample::{
    compute_jl_entries, compute_jl_projection, compute_raw_jl_sum, l2_squared, sample_bounded,
};
pub use verify::{verify, verify_multi, verify_scalar};

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

use crate::NizkError;

/// First RNS prime q_0 (58-bit, q ≡ 1 mod 2N).
pub const RLWE_Q0: u64 = 288_230_376_173_076_481;
/// Second RNS prime q_1 (58-bit, q ≡ 1 mod 2N).
pub const RLWE_Q1: u64 = 288_230_376_167_047_169;
/// Third RNS prime q_2 (58-bit, q ≡ 1 mod 2N).
pub const RLWE_Q2: u64 = 288_230_376_161_280_001;

/// RLWE polynomial degree N (delegates to active preset).
pub fn rlwe_n() -> usize {
    pvthfhe_foundations::types::rlwe_n()
}

/// Return the number of RNS limbs from the active preset.
pub fn num_rns_limbs() -> usize {
    pvthfhe_foundations::types::rlwe_moduli().len()
}
/// Error bound B_e: norm_inf(e_i) <= SIGMA_B_E.
pub const SIGMA_B_E: i64 = 16;
/// Masking bound B_Y for y_s and y_e per-coefficient.
/// Reduced from 2^30 to 2^14 for tight verifier bounds compatible with M-SIS reduction.
pub const B_Y: i64 = 16_384; // 2^14

/// Rejection sampling constant (Lyubashevsky 2009).
/// Higher M reduces rejection probability but loosens the ZK guarantee.
pub const REJECTION_M: f64 = 1.0;

/// Verifier norm bound for z_e: 2 * B_Y (tight per-coefficient ∞-norm).
pub const B_Z_E: i64 = 131_072;

/// Verifier norm bound for z_s (per-coefficient ∞-norm).
/// 2^17 (8σ with σ = B_Y = 2^14). Captures Gaussian tail with negligible
/// rejection probability. Extracted M-SIS witness norm ≤ 2^18 << q^46
/// (Ajtai λ₁), so the reduction remains valid with enormous headroom.
pub const B_Z_S: i64 = 131_072;

/// Number of parallel repetitions for the sigma protocol.
/// Soundness error = (2/3)^SIGMA_REPETITIONS.
/// - 1   → ~1.58 bits of soundness (backward compatible)
/// - 10  → ~15.8 bits
/// - 45  → ~71.2 bits
/// - 90  → ~142.4 bits (2^-128 target)
/// - 128 → ~202.7 bits (conservative)
///
/// DEFAULTS TO 90 for production soundness (~2^-142 ≈ 2^-128 target).
/// The CycloNizkAdapter uses single-round prove/verify (not multi-round by default).
/// Full per-coefficient norm enforcement in-circuit is feasible for k ≤ 10
/// (~5M constraints); k ≥ 90 requires T4 JL projection
/// (see .sisyphus/plans/symphony-adoption.md §T4).
pub const SIGMA_REPETITIONS: usize = 90;

/// Johnson-Lindenstrauss projection dimension.
pub const JL_PROJECTION_DIM: usize = 64;

fn rlwe_context() -> Result<&'static Arc<Context>, NizkError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        let n = rlwe_n();
        let moduli = pvthfhe_foundations::types::rlwe_moduli();
        Context::new(&moduli, n)
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
    .as_ref()
    .map_err(|_| NizkError::InvalidInput {
        reason: "failed to build RLWE context",
        party_id: None,
    })
}

/// Public statement for the RLWE sigma protocol.
///
/// Represents the claim: there exist (s_i, e_i) with small norms
/// such that d_i = c * s_i + e_i (mod Q).
#[derive(Clone, Debug)]
pub struct SigmaStatement {
    /// Public polynomial c in R_Q (RNS power-basis, length = 3*N = 24576).
    pub c_rns: Vec<u64>,
    /// Public polynomial d_i in R_Q (RNS power-basis, length = 3*N = 24576).
    pub d_rns: Vec<u64>,
}

/// Prover witness for the RLWE sigma protocol.
#[derive(Clone, Debug)]
pub struct SigmaWitness {
    /// Secret key share s_i in {-1, 0, 1}^N (ternary, length N).
    pub s_i: Vec<i64>,
    /// Error term e_i with norm_inf(e_i) <= SIGMA_B_E = 16 (length N).
    pub e_i: Vec<i64>,
}

/// Sigma proof for the RLWE relation.
#[derive(Clone, Debug)]
pub struct SigmaProof {
    /// Commitment t = c*y_s + y_e in R_Q (RNS power-basis, length = 3*N).
    pub t_rns: Vec<u64>,
    /// Response z_s = y_s + ch*s_i over Z^N (integer coefficients, length N).
    pub z_s: Vec<i64>,
    /// Response z_e = y_e + ch*e_i over Z^N (integer coefficients, length N).
    pub z_e: Vec<i64>,
    /// Fiat-Shamir challenge ch in {-1, 0, 1} (single ternary scalar).
    pub ch: i64,
}

/// Multi-round sigma proof: k independent parallel repetitions.
///
/// Each round's challenge is independently derived via Fiat-Shamir with
/// round-index binding. The per-round `SigmaProof` entries share the same
/// witness (s_i, e_i) but have different masking vectors (y_s, y_e) and
/// consequently different challenges and responses.
#[derive(Clone, Debug)]
pub struct SigmaMultiProof {
    /// Per-round proofs. Length equals SIGMA_REPETITIONS.
    pub rounds: Vec<SigmaProof>,
}

/// Compute d_i = c * s_i + e_i mod Q, returning RNS power-basis form.
///
/// Used in test setup to derive the statement from a witness.
pub fn compute_d_rns(c_rns: &[u64], s_i: &[i64], e_i: &[i64]) -> Result<Vec<u64>, NizkError> {
    let n = rlwe_n();
    let rns_len = n * num_rns_limbs();
    if c_rns.len() != rns_len {
        return Err(NizkError::InvalidInput {
            reason: "c_rns length must be L*N",
            party_id: None,
        });
    }
    if s_i.len() != n || e_i.len() != n {
        return Err(NizkError::InvalidInput {
            reason: "s_i and e_i must have length N",
            party_id: None,
        });
    }
    let ctx = rlwe_context()?;
    let s_rns = int_poly_to_rns(s_i, ctx)?;
    let e_rns = int_poly_to_rns(e_i, ctx)?;
    let cs_rns = poly_mul_rq(c_rns, &s_rns, ctx)?;
    rns_add(&cs_rns, &e_rns, ctx)
}

/// Compute the secret-key binding hash that links a NIZK proof to a party's
/// registered secret key share via the deterministic share polynomial `d_rns`.
///
/// `sk_binding = Sha256(d_rns || participant_id || session_id)`, domain-separated
/// with `pvthfhe-sk-binding/v1`.  The verifier can reconstruct this hash from
/// the proof-embedded `d_rns` and check it against the DKG registry.
pub fn compute_sk_binding(d_rns: &[u64], participant_id: u32, session_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pvthfhe_foundations::domain_tags::Tag::SigmaSkBinding.as_bytes());
    for limb in d_rns {
        hasher.update(limb.to_le_bytes());
    }
    hasher.update(participant_id.to_le_bytes());
    hasher.update(session_id);
    hasher.finalize().into()
}

/// Convert integer polynomial coefficients to RNS power-basis representation.
pub fn int_poly_to_rns(coeffs: &[i64], ctx: &Arc<Context>) -> Result<Vec<u64>, NizkError> {
    let n = coeffs.len();
    let l = ctx.q.len();
    let mut out = vec![0u64; n * l];
    for (limb, modulus) in ctx.q.iter().enumerate() {
        let qi = i64::try_from(modulus.modulus()).map_err(|_| NizkError::InvalidInput {
            reason: "modulus too large for i64",
            party_id: None,
        })?;
        for (j, &c) in coeffs.iter().enumerate() {
            let r = c.rem_euclid(qi);
            out[limb * n + j] = u64::try_from(r).map_err(|_| NizkError::InvalidInput {
                reason: "rem_euclid result out of u64 range",
                party_id: None,
            })?;
        }
    }
    Ok(out)
}

/// Multiply two polynomials in RNS power-basis representation over R_Q.
///
/// # Trust Assumption (G7)
///
/// NTT correctness is assumed from the `fhe-math` backend. The polynomial
/// multiplication converts to NTT domain, multiplies pointwise, and converts
/// back. Native NTT bugs in `fhe-math` could produce valid-looking sigma proofs
/// for invalid computations.
///
/// The Schwarz-Zippel evaluation path (`compute_sigma_sz_data`) sidesteps NTT
/// in-circuit by evaluating polynomials at random points. However, the native
/// proof generation and verification still use NTT for RNS arithmetic.
pub fn poly_mul_rq(
    a_rns: &[u64],
    b_rns: &[u64],
    ctx: &Arc<Context>,
) -> Result<Vec<u64>, NizkError> {
    let mut pa = Poly::try_convert_from(a_rns.to_vec(), ctx, false, Representation::PowerBasis)
        .map_err(|_| NizkError::InvalidInput {
            reason: "Poly convert failed for a",
            party_id: None,
        })?;
    let mut pb = Poly::try_convert_from(b_rns.to_vec(), ctx, false, Representation::PowerBasis)
        .map_err(|_| NizkError::InvalidInput {
            reason: "Poly convert failed for b",
            party_id: None,
        })?;
    pa.change_representation(Representation::Ntt);
    pb.change_representation(Representation::Ntt);
    let mut product = &pa * &pb;
    product.change_representation(Representation::PowerBasis);
    Ok(Vec::<u64>::from(&product))
}

/// Add two polynomials in RNS power-basis representation per-limb mod q_limb.
pub fn rns_add(a: &[u64], b: &[u64], ctx: &Arc<Context>) -> Result<Vec<u64>, NizkError> {
    let n = rlwe_n();
    let expected = n * ctx.q.len();
    if a.len() != expected || b.len() != expected {
        return Err(NizkError::InvalidInput {
            reason: "rns_add: length mismatch",
            party_id: None,
        });
    }
    let mut out = vec![0u64; a.len()];
    for (limb, modulus) in ctx.q.iter().enumerate() {
        let q = modulus.modulus();
        for j in 0..n {
            let idx = limb * n + j;
            out[idx] = (a[idx] + b[idx]) % q;
        }
    }
    Ok(out)
}

/// Multiply two integer-coefficient polynomials in R_Q, recovering integer coefficients.
pub fn poly_mul_rq_to_int(
    a_int: &[i64],
    b_int: &[i64],
    ctx: &Arc<Context>,
) -> Result<Vec<i64>, NizkError> {
    let n = rlwe_n();
    let a_rns = int_poly_to_rns(a_int, ctx)?;
    let b_rns = int_poly_to_rns(b_int, ctx)?;
    let prod_rns = poly_mul_rq(&a_rns, &b_rns, ctx)?;
    let q0 = i64::try_from(ctx.q[0].modulus()).map_err(|_| NizkError::InvalidInput {
        reason: "q0 too large for i64",
        party_id: None,
    })?;
    let mut result = vec![0i64; n];
    for j in 0..n {
        let c = i64::try_from(prod_rns[j]).map_err(|_| NizkError::InvalidInput {
            reason: "prod coeff out of i64 range",
            party_id: None,
        })?;
        result[j] = if c > q0 / 2 { c - q0 } else { c };
    }
    Ok(result)
}

/// Compute NTT-domain compressor witness data from sigma proof values.
///
/// Returns per-limb Fr vectors for the NTT-domain sigma equation check:
///   `NTT(c)[k] * NTT(z_s)[k] + NTT(z_e)[k] = NTT(t)[k] + ch * NTT(d_i)[k]`
///
/// Caller typically takes the first `SIGMA_VERIFY_COEFFS` coefficients for the in-circuit check.
#[allow(clippy::type_complexity)]
pub fn compute_sigma_ntt_data(
    c_rns: &[u64],
    d_rns: &[u64],
    proof: &SigmaProof,
) -> Result<
    (
        Vec<Vec<Fr>>, // z_s_ntt: L limbs × N
        Vec<Vec<Fr>>, // z_e_ntt: L limbs × N
        Vec<Vec<Fr>>, // t_ntt: L limbs × N
        Vec<Vec<Fr>>, // d_i_ntt: L limbs × N
        Vec<Vec<Fr>>, // c_ntt: L limbs × N
        Vec<i64>,     // z_s_power (raw integer coeffs)
        Vec<i64>,     // z_e_power (raw integer coeffs)
        Fr,           // ch as Fr
    ),
    NizkError,
> {
    use fhe_math::rq::{Poly, Representation};

    let ctx = rlwe_context()?;
    let n = rlwe_n();
    let l = num_rns_limbs();

    let ntt_rns_slice = |rns: &[u64], limb: usize| -> Result<Vec<Fr>, NizkError> {
        let start = limb * n;
        let end = start + n;
        if rns.len() < end {
            return Ok(vec![Fr::zero(); n]);
        }
        let slice = &rns[start..end];
        let mut full_rns = vec![0u64; n * l];
        full_rns[limb * n..(limb + 1) * n].copy_from_slice(slice);
        let mut poly = Poly::try_convert_from(full_rns, ctx, false, Representation::PowerBasis)
            .map_err(|_| NizkError::InvalidInput {
                reason: "poly convert failed",
                party_id: None,
            })?;
        poly.change_representation(Representation::Ntt);
        let ntt_full: Vec<u64> = Vec::from(&poly);
        Ok(ntt_full
            .iter()
            .skip(limb * n)
            .take(n)
            .map(|&v| Fr::from(v))
            .collect())
    };

    let mut z_s_ntt = Vec::with_capacity(l);
    let mut z_e_ntt = Vec::with_capacity(l);
    let mut t_ntt = Vec::with_capacity(l);
    let mut d_i_ntt = Vec::with_capacity(l);
    let mut c_ntt = Vec::with_capacity(l);

    let z_s_rns = int_poly_to_rns(&proof.z_s, ctx)?;
    let z_e_rns = int_poly_to_rns(&proof.z_e, ctx)?;

    for limb in 0..l {
        let z_s_ntt_limb = ntt_rns_slice(&z_s_rns, limb)?;
        let z_e_ntt_limb = ntt_rns_slice(&z_e_rns, limb)?;
        let t_ntt_limb = ntt_rns_slice(&proof.t_rns, limb)?;
        let d_i_ntt_limb = ntt_rns_slice(d_rns, limb)?;
        let c_ntt_limb = ntt_rns_slice(c_rns, limb)?;

        z_s_ntt.push(z_s_ntt_limb);
        z_e_ntt.push(z_e_ntt_limb);
        t_ntt.push(t_ntt_limb);
        d_i_ntt.push(d_i_ntt_limb);
        c_ntt.push(c_ntt_limb);
    }

    let ch_fr = match proof.ch {
        -1 => -Fr::one(),
        0 => Fr::zero(),
        1 => Fr::one(),
        _ => {
            return Err(NizkError::InvalidInput {
                reason: "challenge must be -1, 0, or 1",
                party_id: None,
            })
        }
    };

    Ok((
        z_s_ntt,
        z_e_ntt,
        t_ntt,
        d_i_ntt,
        c_ntt,
        proof.z_s.clone(),
        proof.z_e.clone(),
        ch_fr,
    ))
}

/// Evaluate polynomial (given as coefficient slice) at point x using
/// Horner's method. Returns the result mod q.
pub fn poly_eval_mod(coeffs: &[i64], x: u64, q: u64) -> u64 {
    let mut result: i128 = 0;
    for &c in coeffs.iter().rev() {
        result = ((result * x as i128) + c as i128).rem_euclid(q as i128);
    }
    result as u64
}

/// Compute a single S-Z gamma point with a per-point domain separator.
///
/// Hashes ALL evaluated polynomials (t_rns, c_rns, d_rns, z_s, z_e) plus challenge,
/// session/party binding and a unique label to derive an independent 64-bit gamma.
fn compute_one_gamma(
    proof: &SigmaProof,
    session_id: &[u8],
    party_id: u32,
    label: &[u8],
    c_rns: &[u64],
    d_rns: &[u64],
    prev_gammas: &[u64],
) -> u64 {
    let mut h = Sha256::new();
    h.update(pvthfhe_foundations::domain_tags::Tag::SigmaSzGamma.as_bytes());
    h.update(label);
    h.update(session_id);
    h.update(party_id.to_le_bytes());
    h.update(proof.ch.to_le_bytes());
    for &v in &proof.t_rns {
        h.update(v.to_le_bytes());
    }
    for &v in c_rns {
        h.update(v.to_le_bytes());
    }
    for &v in d_rns {
        h.update(v.to_le_bytes());
    }
    for &v in &proof.z_s {
        h.update(v.to_le_bytes());
    }
    for &v in &proof.z_e {
        h.update(v.to_le_bytes());
    }
    for &v in prev_gammas {
        h.update(v.to_le_bytes());
    }
    let digest = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

/// Compute 3 independent Schwartz-Zippel challenge points gamma[0..2] from the sigma
/// proof transcript using Fiat-Shamir (prover cannot choose gamma).
///
/// Returns [gamma0, gamma1, gamma2] — three independently-derived 64-bit challenge
/// points for 3-point S-Z evaluation achieving ~2^-135 composite soundness.
///
/// Each gamma is derived independently with per-point domain separators so no two
/// points share a hash prefix.  All evaluated polynomials (t_rns, c_rns, d_rns,
/// z_s, z_e) and the challenge ch are bound into every derivation.
pub fn compute_sz_gamma(
    proof: &SigmaProof,
    session_id: &[u8],
    party_id: u32,
    c_rns: &[u64],
    d_rns: &[u64],
) -> [u64; 3] {
    let gamma0 = compute_one_gamma(proof, session_id, party_id, b"gamma0", c_rns, d_rns, &[]);
    let gamma1 = compute_one_gamma(
        proof,
        session_id,
        party_id,
        b"gamma1",
        c_rns,
        d_rns,
        &[gamma0],
    );
    let gamma2 = compute_one_gamma(
        proof,
        session_id,
        party_id,
        b"gamma2",
        c_rns,
        d_rns,
        &[gamma0, gamma1],
    );
    [gamma0, gamma1, gamma2]
}

/// Compute Schwartz-Zippel 3-point evaluation data for the compressor witness.
///
/// Evaluates each of the five polynomials (c, z_s, z_e, t, d_i) at 3 independent
/// Fiat-Shamir-derived gamma points per RNS limb, and precomputes the
/// modulus-reduction quotient r1 so the in-circuit check is a single
/// equality constraint per (limb, eval_idx) pair.
///
/// Result type for [`compute_sigma_sz_data`].
#[allow(clippy::type_complexity)]
pub type SigmaSzData = (
    [u64; 3],
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
);

/// Compute Schwartz-Zippel 3-point evaluation data for the compressor witness.
///
/// Evaluates each of the five polynomials (c, z_s, z_e, t, d_i) at 3 independent
/// Fiat-Shamir-derived gamma points per RNS limb, and precomputes the
/// modulus-reduction quotient r1 so the in-circuit check is a single
/// equality constraint per (limb, eval_idx) pair.
///
/// Returns (gamma[3], c_eval, zs_eval, ze_eval, t_eval, di_eval, r1_eval)
/// where each eval vector has 3*L entries in eval-major order:
/// [γ0_l0, γ0_l1, γ0_l2, γ1_l0, γ1_l1, γ1_l2, γ2_l0, γ2_l1, γ2_l2].
pub fn compute_sigma_sz_data(
    c_rns: &[u64],
    d_rns: &[u64],
    proof: &SigmaProof,
    session_id: &[u8],
    party_id: u32,
) -> SigmaSzData {
    let n = rlwe_n();
    let moduli = pvthfhe_foundations::types::rlwe_moduli();
    let gammas = compute_sz_gamma(proof, session_id, party_id, c_rns, d_rns);

    let total_entries = 3 * moduli.len();
    let mut sz_c_eval = Vec::with_capacity(total_entries);
    let mut sz_zs_eval = Vec::with_capacity(total_entries);
    let mut sz_ze_eval = Vec::with_capacity(total_entries);
    let mut sz_t_eval = Vec::with_capacity(total_entries);
    let mut sz_di_eval = Vec::with_capacity(total_entries);
    let mut sz_r1_eval = Vec::with_capacity(total_entries);

    for &gamma in &gammas {
        for limb in 0..moduli.len() {
            let q = moduli[limb];

            // Extract power-basis coefficients from RNS arrays.
            let c_coeffs: Vec<i64> = c_rns[limb * n..(limb + 1) * n]
                .iter()
                .map(|&v| (v % q) as i64)
                .collect();
            let d_coeffs: Vec<i64> = d_rns[limb * n..(limb + 1) * n]
                .iter()
                .map(|&v| (v % q) as i64)
                .collect();
            let t_coeffs: Vec<i64> = proof.t_rns[limb * n..(limb + 1) * n]
                .iter()
                .map(|&v| (v % q) as i64)
                .collect();

            // z_s and z_e are signed integer coefficients; reduce to [0, q) for
            // polynomial evaluation.
            let zs_coeffs: Vec<i64> = proof
                .z_s
                .iter()
                .map(|&v| {
                    let rem = (v as i128).rem_euclid(q as i128);
                    i64::try_from(rem).unwrap_or(0)
                })
                .collect();
            let ze_coeffs: Vec<i64> = proof
                .z_e
                .iter()
                .map(|&v| {
                    let rem = (v as i128).rem_euclid(q as i128);
                    i64::try_from(rem).unwrap_or(0)
                })
                .collect();

            let c_val = poly_eval_mod(&c_coeffs, gamma, q);
            let zs_val = poly_eval_mod(&zs_coeffs, gamma, q);
            let ze_val = poly_eval_mod(&ze_coeffs, gamma, q);
            let t_val = poly_eval_mod(&t_coeffs, gamma, q);
            let di_val = poly_eval_mod(&d_coeffs, gamma, q);

            // r1 = (c(gamma)*z_s(gamma) + z_e(gamma) - t(gamma) - ch*d_i(gamma)) / Q
            let ch_val = proof.ch as i128;
            let lhs = c_val as i128 * zs_val as i128 + ze_val as i128
                - t_val as i128
                - ch_val * di_val as i128;
            let r1 = lhs.div_euclid(q as i128).unsigned_abs() as u64;

            sz_c_eval.push(c_val);
            sz_zs_eval.push(zs_val);
            sz_ze_eval.push(ze_val);
            sz_t_eval.push(t_val);
            sz_di_eval.push(di_val);
            sz_r1_eval.push(r1);
        }
    }

    (
        gammas, sz_c_eval, sz_zs_eval, sz_ze_eval, sz_t_eval, sz_di_eval, sz_r1_eval,
    )
}
