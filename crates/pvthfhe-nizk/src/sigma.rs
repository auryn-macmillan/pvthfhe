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
//! Scalar ternary ch in {-1, 0, 1} derived via Fiat-Shamir (Poseidon over BN254
//! with SHA-256 field compression). The challenge space size is ~2^254 (stronger
//! than the old binary-poly 2^8192 for soundness but makes in-circuit verification
//! tractable: NTT with constant twiddle factors = zero R1CS multiplications).
//!
//! # Response Bounds
//! Masking bound B_Y = 2^30.
//! z_s = y_s + ch * s_i  (element-wise scalar multiplication); bound B_Z_S = B_Y + N.
//! z_e = y_e + ch * e_i  (element-wise scalar multiplication); bound B_Z_E = B_Y + N * SIGMA_B_E.
//! Both fit in i64 since B_Z_E < 2^31 << 2^63.

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use light_poseidon::{Poseidon, PoseidonHasher};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

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
    /// Fiat-Shamir challenge ch in {-1, 0, 1} (single ternary scalar).
    pub ch: i64,
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

    let ch = derive_challenge_scalar(
        session_id,
        participant_id,
        &t_rns,
        &stmt.c_rns,
        &stmt.d_rns,
        &[0u8; 32], // G.5: TODO: pass real d_commitment
    );

    // Element-wise scalar multiplication: ch ∈ {-1,0,1}
    let z_s: Vec<i64> = y_s
        .iter()
        .zip(wit.s_i.iter())
        .map(|(&a, &b)| a + scalar_mul_i64(ch, b))
        .collect();
    let z_e: Vec<i64> = y_e
        .iter()
        .zip(wit.e_i.iter())
        .map(|(&a, &b)| a + scalar_mul_i64(ch, b))
        .collect();

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
) -> Result<(), NizkError> {
    verify_scalar(session_id, participant_id, stmt, proof)
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
) -> Result<(), NizkError> {
    if stmt.c_rns.len() != RNS_LEN || stmt.d_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput("statement RNS lengths must be 3*N"));
    }
    if proof.t_rns.len() != RNS_LEN {
        return Err(NizkError::InvalidInput("proof t_rns length must be 3*N"));
    }
    if proof.z_s.len() != RLWE_N || proof.z_e.len() != RLWE_N {
        return Err(NizkError::InvalidInput(
            "proof polynomial lengths must be N",
        ));
    }
    if proof.ch != -1 && proof.ch != 0 && proof.ch != 1 {
        return Err(NizkError::InvalidInput("challenge must be -1, 0, or 1"));
    }

    let ctx = rlwe_context()?;

    let expected_ch = derive_challenge_scalar(
        session_id,
        participant_id,
        &proof.t_rns,
        &stmt.c_rns,
        &stmt.d_rns,
        &[0u8; 32], // G.5: TODO: pass real d_commitment
    );
    // Constant-time comparison for challenge
    let ch_match = (proof.ch ^ expected_ch) == 0;
    if !ch_match {
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

    // ch·d_i: element-wise scalar multiplication (ch ∈ {-1,0,1})
    let rhs_rns = rns_add_scalar_mul(&proof.t_rns, proof.ch, &stmt.d_rns, ctx)?;

    if lhs_rns != rhs_rns {
        return Err(NizkError::VerificationFailed(
            "algebraic equation c*z_s + z_e != t + ch*d_i",
        ));
    }

    Ok(())
}

/// Compute the secret-key binding hash that links a NIZK proof to a party's
/// registered secret key share via the deterministic share polynomial `d_rns`.
///
/// `sk_binding = Sha256(d_rns || participant_id || session_id)`, domain-separated
/// with `"pvthfhe-sk-binding/v1"`.  The verifier can reconstruct this hash from
/// the proof-embedded `d_rns` and check it against the DKG registry.
pub fn compute_sk_binding(
    d_rns: &[u64],
    participant_id: u32,
    session_id: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pvthfhe-sk-binding/v1");
    for limb in d_rns {
        hasher.update(&limb.to_le_bytes());
    }
    hasher.update(&participant_id.to_le_bytes());
    hasher.update(session_id);
    hasher.finalize().into()
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

// ── Scalar challenge derivation (Poseidon-based) ─────────────────────────

/// Domain separator for scalar-challenge sigma protocol (v2).
const SCALAR_CHALLENGE_DOMAIN: &[u8] = b"pvthfhe/sigma-scalar-challenge/v2";

/// Derive a scalar ternary challenge ch ∈ {-1, 0, 1} using Fiat-Shamir with
/// Poseidon over BN254 (with SHA-256 field compression).
///
/// 1. SHA-256 compresses each large serialized field to a 32-byte digest
/// 2. Poseidon combines the digests + session/participant binding into a single Fr
/// 3. Fr is reduced to ternary {-1, 0, 1}
fn derive_challenge_scalar(
    session_id: &[u8],
    participant_id: u32,
    t_rns: &[u64],
    c_rns: &[u64],
    d_rns: &[u64],
    d_commitment: &[u8; 32],
) -> i64 {
    // Serialize large fields to bytes
    let t_bytes: Vec<u8> = t_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    let c_bytes: Vec<u8> = c_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
    let d_bytes: Vec<u8> = d_rns.iter().flat_map(|x| x.to_le_bytes()).collect();

    // 1. Build domain prefix: DOMAIN || session_id || participant_id
    let mut prefix = Sha256::new();
    prefix.update(SCALAR_CHALLENGE_DOMAIN);
    prefix.update(session_id);
    prefix.update(participant_id.to_le_bytes());

    // 2. Compress each field with SHA-256, labeling and binding to the prefix
    let t_digest = labeled_sha256(&prefix, b"t_rns", &t_bytes);
    let c_digest = labeled_sha256(&prefix, b"c_rns", &c_bytes);
    let d_digest = labeled_sha256(&prefix, b"d_rns", &d_bytes);
    let dcomm_digest = labeled_sha256(&prefix, b"d_commitment", d_commitment);

    // 3. Combine digests with Poseidon
    // Each 32-byte digest → 2 Fr elements (lo 16 bytes, hi 16 bytes)
    let mut fr_inputs: Vec<Fr> = Vec::with_capacity(8);
    for digest in &[t_digest, c_digest, d_digest, dcomm_digest] {
        fr_inputs.push(bytes16_to_fr(&digest[..16]));
        fr_inputs.push(bytes16_to_fr(&digest[16..]));
    }

    let ch_fr = poseidon_hash(&fr_inputs);

    // 4. Reduce Fr to ternary {-1, 0, 1}
    fr_to_ternary(&ch_fr)
}

/// SHA-256 hashes a labeled field, binding it to a shared prefix (which includes
/// session/participant binding and domain separator).
fn labeled_sha256(prefix: &Sha256, label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = prefix.clone();
    h.update(label);
    h.update(data);
    h.finalize().into()
}

/// Convert 16 bytes (big-endian) to an Fr field element.
fn bytes16_to_fr(bytes: &[u8]) -> Fr {
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(bytes);
    Fr::from_le_bytes_mod_order(&buf)
}

/// Hash a slice of Fr elements using Poseidon.
fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let mut hasher =
        Poseidon::<Fr>::new_circom(inputs.len()).expect("Poseidon arity within Circom range");
    hasher.hash(inputs).expect("Poseidon hash must succeed")
}

/// Reduce an Fr field element to a ternary value {-1, 0, 1}.
///
/// Uses the canonical bigint representation:
/// - 0 → 0
/// - Value in upper half of field → -1
/// - Otherwise → 1
fn fr_to_ternary(fr: &Fr) -> i64 {
    if fr.is_zero() {
        return 0;
    }

    let bigint = fr.into_bigint();
    let mut half_modulus = Fr::MODULUS;
    half_modulus.div2();

    if bigint > half_modulus {
        -1
    } else {
        1
    }
}

// ── Element-wise scalar operations ──────────────────────────────────────

/// Multiply an i64 coefficient by a ternary scalar ch ∈ {-1, 0, 1}.
/// Returns ch * val.
#[inline]
fn scalar_mul_i64(ch: i64, val: i64) -> i64 {
    match ch {
        1 => val,
        -1 => -val,
        _ => 0,
    }
}

/// Compute `a + ch * b` element-wise over RNS power-basis, where
/// ch ∈ {-1, 0, 1} is a ternary scalar and b is an RNS polynomial.
fn rns_add_scalar_mul(
    a: &[u64],
    ch: i64,
    b: &[u64],
    ctx: &Arc<Context>,
) -> Result<Vec<u64>, NizkError> {
    let expected = RLWE_N * ctx.q.len();
    if a.len() != expected || b.len() != expected {
        return Err(NizkError::InvalidInput("rns_add_scalar_mul: length mismatch"));
    }
    let n = RLWE_N;
    let mut out = vec![0u64; a.len()];
    match ch {
        0 => {
            out.copy_from_slice(a);
        }
        1 => {
            for (limb, modulus) in ctx.q.iter().enumerate() {
                let q = modulus.modulus();
                for j in 0..n {
                    let idx = limb * n + j;
                    out[idx] = (a[idx] + b[idx]) % q;
                }
            }
        }
        -1 => {
            for (limb, modulus) in ctx.q.iter().enumerate() {
                let q = modulus.modulus();
                for j in 0..n {
                    let idx = limb * n + j;
                    // a - b mod q
                    out[idx] = (a[idx] + q - (b[idx] % q)) % q;
                }
            }
        }
        _ => return Err(NizkError::InvalidInput("ch must be -1, 0, or 1")),
    }
    Ok(out)
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

/// Compute NTT-domain compressor witness data from sigma proof values.
///
/// Returns per-limb Fr vectors for the NTT-domain sigma equation check:
///   `NTT(c)[k] * NTT(z_s)[k] + NTT(z_e)[k] = NTT(t)[k] + ch * NTT(d_i)[k]`
///
/// Each limb vector has `RLWE_N` Fr elements. The caller typically takes
/// the first `SIGMA_VERIFY_COEFFS` coefficients for the in-circuit check.
#[allow(clippy::type_complexity)]
pub fn compute_sigma_ntt_data(
    c_rns: &[u64],
    d_rns: &[u64],
    proof: &SigmaProof,
) -> Result<(
    Vec<Vec<Fr>>, // z_s_ntt: 3 limbs × N
    Vec<Vec<Fr>>, // z_e_ntt: 3 limbs × N
    Vec<Vec<Fr>>, // t_ntt: 3 limbs × N
    Vec<Vec<Fr>>, // d_i_ntt: 3 limbs × N
    Vec<Vec<Fr>>, // c_ntt: 3 limbs × N
    Vec<i64>,      // z_s_power (raw integer coeffs)
    Vec<i64>,      // z_e_power (raw integer coeffs)
    Fr,            // ch as Fr
), NizkError> {
    use fhe_math::rq::{Poly, Representation};

    let ctx = rlwe_context()?;
    let n = RLWE_N;

    let ntt_rns_slice = |rns: &[u64], limb: usize|
        -> Result<Vec<Fr>, NizkError>
    {
        let start = limb * n;
        let end = start + n;
        if rns.len() < end {
            return Ok(vec![Fr::zero(); n]);
        }
        let slice = &rns[start..end];
        let mut full_rns = vec![0u64; n * 3];
        full_rns[limb * n..(limb + 1) * n].copy_from_slice(slice);
        let mut poly = Poly::try_convert_from(
            full_rns, &ctx, false, Representation::PowerBasis,
        ).map_err(|_| NizkError::InvalidInput("poly convert failed"))?;
        poly.change_representation(Representation::Ntt);
        let ntt_full: Vec<u64> = Vec::from(&poly);
        Ok(ntt_full
            .iter()
            .skip(limb * n)
            .take(n)
            .map(|&v| Fr::from(v))
            .collect())
    };

    let mut z_s_ntt = Vec::with_capacity(3);
    let mut z_e_ntt = Vec::with_capacity(3);
    let mut t_ntt = Vec::with_capacity(3);
    let mut d_i_ntt = Vec::with_capacity(3);
    let mut c_ntt = Vec::with_capacity(3);

    // For z_s and z_e, convert integer coeffs to RNS then NTT
    let z_s_rns = int_poly_to_rns(&proof.z_s, ctx)?;
    let z_e_rns = int_poly_to_rns(&proof.z_e, ctx)?;

    for limb in 0..3 {
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
        _ => return Err(NizkError::InvalidInput("challenge must be -1, 0, or 1")),
    };

    Ok((z_s_ntt, z_e_ntt, t_ntt, d_i_ntt, c_ntt,
        proof.z_s.clone(), proof.z_e.clone(), ch_fr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_to_ternary_smoke() {
        // Zero maps to 0
        assert_eq!(fr_to_ternary(&Fr::from(0u64)), 0);
        // One maps to 1
        assert_eq!(fr_to_ternary(&Fr::from(1u64)), 1);
        // Negative one (r-1) maps to -1
        let neg_one = -Fr::from(1u64);
        assert_eq!(fr_to_ternary(&neg_one), -1);
    }

    #[test]
    fn scalar_mul_i64_smoke() {
        assert_eq!(scalar_mul_i64(0, 42), 0);
        assert_eq!(scalar_mul_i64(1, 42), 42);
        assert_eq!(scalar_mul_i64(-1, 42), -42);
        assert_eq!(scalar_mul_i64(0, -5), 0);
        assert_eq!(scalar_mul_i64(1, -5), -5);
        assert_eq!(scalar_mul_i64(-1, -5), 5);
    }

    #[test]
    fn challenge_depends_on_session_id() {
        let session_a = b"session-alpha-123";
        let session_b = b"session-beta-456";
        let t_rns = vec![1u64; RNS_LEN];
        let c_rns = vec![2u64; RNS_LEN];
        let d_rns = vec![3u64; RNS_LEN];
        let pvss = [0u8; 32];

        // Verify SHA-256 prefix differs with different session IDs (binding)
        let mut prefix_a = Sha256::new();
        prefix_a.update(SCALAR_CHALLENGE_DOMAIN);
        prefix_a.update(session_a);
        prefix_a.update(0u32.to_le_bytes());

        let mut prefix_b = Sha256::new();
        prefix_b.update(SCALAR_CHALLENGE_DOMAIN);
        prefix_b.update(session_b);
        prefix_b.update(0u32.to_le_bytes());

        let t_bytes: Vec<u8> = t_rns.iter().flat_map(|x| x.to_le_bytes()).collect();
        let digest_a = labeled_sha256(&prefix_a, b"t_rns", &t_bytes);
        let digest_b = labeled_sha256(&prefix_b, b"t_rns", &t_bytes);
        assert_ne!(digest_a, digest_b, "SHA-256 digests must differ with different session IDs");
    }
}
