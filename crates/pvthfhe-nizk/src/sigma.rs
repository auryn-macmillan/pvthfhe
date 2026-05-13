//! Schnorr-style sigma protocol over the PVTHFHE production RLWE ring.
//!
//! # Ring
//! R_Q = Z_Q\[X\]/(X^8192+1), Q = q_0 * q_1 * q_2 (3 RNS limbs, log2(Q) ~= 174).
//! Polynomial arithmetic uses the fhe-math NTT backend.
//!
//! # Relation
//! Statement: (c, d_i) in R_Q^2.
//! Witness:   (s_i, e_i) with norm_inf(s_i) <= 1 (ternary), norm_inf(e_i) <= SIGMA_B_E = 16.
//! Relation:  d_i = c * s_i + e_i  (mod Q).
//!
//! # Challenge Space
//! Binary polynomial ch in {0,1}^N derived via Fiat-Shamir (SHA-256 over serialized
//! Binary-challenge special-soundness is conditional on an unproven joint extractor
//! (P1 OPEN). The 2^{-N} figure is the challenge-space size, not a proven knowledge error.
//!
//! # Response Bounds
//! Masking bound B_Y = 2^30.
//! z_s = y_s + ch * s_i  (integer poly); bound B_Z_S = B_Y + N.
//! z_e = y_e + ch * e_i  (integer poly); bound B_Z_E = B_Y + N * SIGMA_B_E.
//! Both fit in i64 since B_Z_E < 2^31 << 2^63.

use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use rand_core::RngCore;
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

use crate::fiat_shamir::Transcript;
use crate::NizkError;

/// RLWE polynomial degree N = 8192.
pub const RLWE_N: usize = 8192;
/// First RNS prime q_0 (58-bit, q ≡ 1 mod 2N).
pub const RLWE_Q0: u64 = 288_230_376_173_076_481;
/// Second RNS prime q_1 (58-bit, q ≡ 1 mod 2N).
pub const RLWE_Q1: u64 = 288_230_376_167_047_169;
/// Third RNS prime q_2 (58-bit, q ≡ 1 mod 2N).
pub const RLWE_Q2: u64 = 288_230_376_161_280_001;
/// Error bound B_e: norm_inf(e_i) <= SIGMA_B_E.
pub const SIGMA_B_E: i64 = 16;
/// Masking bound B_Y for y_s and y_e per-coefficient.
pub const B_Y: i64 = 1_073_741_824; // 2^30
/// N as i64, used in bound expressions.
const N_I64: i64 = 8192_i64;
/// Verifier norm bound for z_e: B_Y + N * SIGMA_B_E.
pub const B_Z_E: i64 = B_Y + N_I64 * SIGMA_B_E;
/// Verifier norm bound for z_s: B_Y + N.
pub const B_Z_S: i64 = B_Y + N_I64;

const MODULI: [u64; 3] = [RLWE_Q0, RLWE_Q1, RLWE_Q2];
const RNS_LEN: usize = RLWE_N * 3;

fn rlwe_context() -> Result<&'static Arc<Context>, NizkError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        Context::new(&MODULI, RLWE_N)
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
    .as_ref()
    .map_err(|_| NizkError::InvalidInput("failed to build RLWE context"))
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
    /// Fiat-Shamir challenge ch in {0,1}^N (binary poly, length N).
    pub ch: Vec<i64>,
}

/// Compute d_i = c * s_i + e_i mod Q, returning RNS power-basis form.
///
/// Used in test setup to derive the statement from a witness.
pub fn compute_d_rns(c_rns: &[u64], s_i: &[i64], e_i: &[i64]) -> Result<Vec<u64>, NizkError> {
    if c_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput("c_rns length must be 3*N"));
    }
    if s_i.len() != RLWE_N || e_i.len() != RLWE_N {
        return Err(NizkError::InvalidInput("s_i and e_i must have length N"));
    }
    let ctx = rlwe_context()?;
    let s_rns = int_poly_to_rns(s_i, ctx)?;
    let e_rns = int_poly_to_rns(e_i, ctx)?;
    let cs_rns = poly_mul_rq(c_rns, &s_rns, ctx)?;
    rns_add(&cs_rns, &e_rns, ctx)
}

/// Produce a sigma proof for statement (c, d_i) and witness (s_i, e_i).
///
/// `session_id` and `participant_id` are bound into the Fiat-Shamir transcript
/// via the locked domain separator from [`crate::fiat_shamir::Transcript`].
pub fn prove(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    wit: &SigmaWitness,
    pvss_commitment: &[u8; 32],
    rng: &mut dyn RngCore,
) -> Result<SigmaProof, NizkError> {
    if stmt.c_rns.len() != RNS_LEN || stmt.d_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput("statement RNS lengths must be 3*N"));
    }
    if wit.s_i.len() != RLWE_N || wit.e_i.len() != RLWE_N {
        return Err(NizkError::InvalidInput(
            "witness polynomials must have length N",
        ));
    }
    let ctx = rlwe_context()?;

    let y_s = sample_bounded(rng, RLWE_N, B_Y)?;
    let y_e = sample_bounded(rng, RLWE_N, B_Y)?;

    let y_s_rns = int_poly_to_rns(&y_s, ctx)?;
    let y_e_rns = int_poly_to_rns(&y_e, ctx)?;
    let c_ys_rns = poly_mul_rq(&stmt.c_rns, &y_s_rns, ctx)?;
    let t_rns = rns_add(&c_ys_rns, &y_e_rns, ctx)?;

    let ch = derive_challenge(
        session_id,
        participant_id,
        &t_rns,
        &stmt.c_rns,
        &stmt.d_rns,
        pvss_commitment,
    );

    let ch_si = poly_mul_rq_to_int(&ch, &wit.s_i, ctx)?;
    let ch_ei = poly_mul_rq_to_int(&ch, &wit.e_i, ctx)?;

    let z_s: Vec<i64> = y_s.iter().zip(ch_si.iter()).map(|(&a, &b)| a + b).collect();
    let z_e: Vec<i64> = y_e.iter().zip(ch_ei.iter()).map(|(&a, &b)| a + b).collect();

    Ok(SigmaProof {
        t_rns,
        z_s,
        z_e,
        ch,
    })
}

/// Verify a sigma proof against a statement.
///
/// `session_id` and `participant_id` must match those used during [`prove`].
///
/// Returns Ok(()) iff the algebraic equation holds and response norms are within bounds.
pub fn verify(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    proof: &SigmaProof,
    pvss_commitment: &[u8; 32],
) -> Result<(), NizkError> {
    if stmt.c_rns.len() != RNS_LEN || stmt.d_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput("statement RNS lengths must be 3*N"));
    }
    if proof.t_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput("proof t_rns length must be 3*N"));
    }
    if proof.z_s.len() != RLWE_N || proof.z_e.len() != RLWE_N || proof.ch.len() != RLWE_N {
        return Err(NizkError::InvalidInput(
            "proof polynomial lengths must be N",
        ));
    }
    let ctx = rlwe_context()?;

    let expected_ch = derive_challenge(
        session_id,
        participant_id,
        &proof.t_rns,
        &stmt.c_rns,
        &stmt.d_rns,
        pvss_commitment,
    );
    let expected_ch_bytes: Vec<u8> = expected_ch.iter().flat_map(|x| x.to_le_bytes()).collect();
    let proof_ch_bytes: Vec<u8> = proof.ch.iter().flat_map(|x| x.to_le_bytes()).collect();
    if !bool::from(
        expected_ch_bytes
            .as_slice()
            .ct_eq(proof_ch_bytes.as_slice()),
    ) {
        return Err(NizkError::VerificationFailed("challenge mismatch"));
    }

    let max_ze = proof.z_e.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_ze > B_Z_E {
        return Err(NizkError::VerificationFailed("z_e norm bound exceeded"));
    }
    let max_zs = proof.z_s.iter().map(|x| x.abs()).max().unwrap_or(0);
    if max_zs > B_Z_S {
        return Err(NizkError::VerificationFailed("z_s norm bound exceeded"));
    }

    let z_s_rns = int_poly_to_rns(&proof.z_s, ctx)?;
    let z_e_rns = int_poly_to_rns(&proof.z_e, ctx)?;
    let c_zs_rns = poly_mul_rq(&stmt.c_rns, &z_s_rns, ctx)?;
    let lhs_rns = rns_add(&c_zs_rns, &z_e_rns, ctx)?;

    let ch_rns = int_poly_to_rns(&proof.ch, ctx)?;
    let ch_di_rns = poly_mul_rq(&ch_rns, &stmt.d_rns, ctx)?;
    let rhs_rns = rns_add(&proof.t_rns, &ch_di_rns, ctx)?;

    if lhs_rns != rhs_rns {
        return Err(NizkError::VerificationFailed(
            "algebraic equation c*z_s + z_e != t + ch*d_i",
        ));
    }

    Ok(())
}

/// Convert integer polynomial coefficients to RNS power-basis representation.
pub fn int_poly_to_rns(coeffs: &[i64], ctx: &Arc<Context>) -> Result<Vec<u64>, NizkError> {
    let n = coeffs.len();
    let l = ctx.q.len();
    let mut out = vec![0u64; n * l];
    for (limb, modulus) in ctx.q.iter().enumerate() {
        let qi = i64::try_from(modulus.modulus())
            .map_err(|_| NizkError::InvalidInput("modulus too large for i64"))?;
        for (j, &c) in coeffs.iter().enumerate() {
            let r = c.rem_euclid(qi);
            out[limb * n + j] = u64::try_from(r)
                .map_err(|_| NizkError::InvalidInput("rem_euclid result out of u64 range"))?;
        }
    }
    Ok(out)
}

/// Multiply two polynomials in RNS power-basis representation over R_Q.
pub fn poly_mul_rq(
    a_rns: &[u64],
    b_rns: &[u64],
    ctx: &Arc<Context>,
) -> Result<Vec<u64>, NizkError> {
    let mut pa = Poly::try_convert_from(a_rns.to_vec(), ctx, false, Representation::PowerBasis)
        .map_err(|_| NizkError::InvalidInput("Poly convert failed for a"))?;
    let mut pb = Poly::try_convert_from(b_rns.to_vec(), ctx, false, Representation::PowerBasis)
        .map_err(|_| NizkError::InvalidInput("Poly convert failed for b"))?;
    pa.change_representation(Representation::Ntt);
    pb.change_representation(Representation::Ntt);
    let mut product = &pa * &pb;
    product.change_representation(Representation::PowerBasis);
    Ok(Vec::<u64>::from(&product))
}

/// Add two polynomials in RNS power-basis representation per-limb mod q_limb.
pub fn rns_add(a: &[u64], b: &[u64], ctx: &Arc<Context>) -> Result<Vec<u64>, NizkError> {
    let expected = RLWE_N * ctx.q.len();
    if a.len() != expected || b.len() != expected {
        return Err(NizkError::InvalidInput("rns_add: length mismatch"));
    }
    let n = RLWE_N;
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
    let a_rns = int_poly_to_rns(a_int, ctx)?;
    let b_rns = int_poly_to_rns(b_int, ctx)?;
    let prod_rns = poly_mul_rq(&a_rns, &b_rns, ctx)?;
    // Recover integer coefficients via limb-0 centering.
    // Valid because |true coefficient| <= N (negacyclic convolution of binary * ternary/bounded)
    // which is far below q_0/2 ~ 2^57.
    let q0 = i64::try_from(ctx.q[0].modulus())
        .map_err(|_| NizkError::InvalidInput("q0 too large for i64"))?;
    let mut result = vec![0i64; RLWE_N];
    for j in 0..RLWE_N {
        let c = i64::try_from(prod_rns[j])
            .map_err(|_| NizkError::InvalidInput("prod coeff out of i64 range"))?;
        result[j] = if c > q0 / 2 { c - q0 } else { c };
    }
    Ok(result)
}

fn derive_challenge(
    session_id: &[u8],
    participant_id: u32,
    t_rns: &[u64],
    c_rns: &[u64],
    d_rns: &[u64],
    pvss_commitment: &[u8; 32],
) -> Vec<i64> {
    let mut ts = Transcript::new(session_id, participant_id);
    let t_bytes: Vec<u8> = t_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    ts.absorb(b"t_rns", &t_bytes);
    let c_bytes: Vec<u8> = c_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    ts.absorb(b"c_rns", &c_bytes);
    let d_bytes: Vec<u8> = d_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    ts.absorb(b"d_rns", &d_bytes);
    ts.absorb(b"pvss_commitment", pvss_commitment);
    let mut raw = [0u8; RLWE_N / 8];
    ts.challenge_bytes(b"binary_challenge", &mut raw);
    let mut bits = Vec::with_capacity(RLWE_N);
    'outer: for byte in &raw {
        for bit_pos in 0..8u32 {
            if bits.len() < RLWE_N {
                bits.push(i64::from((byte >> bit_pos) & 1u8));
            } else {
                break 'outer;
            }
        }
    }
    bits
}

/// Sample `n` coefficients uniformly from [-bound, bound] using rejection sampling.
pub fn sample_bounded(rng: &mut dyn RngCore, n: usize, bound: i64) -> Result<Vec<i64>, NizkError> {
    let range = u64::try_from(2 * bound + 1)
        .map_err(|_| NizkError::InvalidInput("bound too large for u64"))?;
    let max_multiple = (u64::MAX / range) * range;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let r = u64::from_le_bytes(bytes);
        if r < max_multiple {
            let v = i64::try_from(r % range)
                .map_err(|_| NizkError::InvalidInput("sample out of i64 range"))?;
            out.push(v - bound);
        }
    }
    Ok(out)
}
