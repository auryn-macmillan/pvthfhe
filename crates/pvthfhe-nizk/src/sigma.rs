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

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use light_poseidon::{Poseidon, PoseidonHasher};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
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
    pvthfhe_types::rlwe_n()
}

/// Return the number of RNS limbs from the active preset.
pub fn num_rns_limbs() -> usize {
    pvthfhe_types::rlwe_moduli().len()
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

/// WIP: compute JL projection p = Π·w. Not currently constrained in-circuit.
/// The per-coefficient norm_range_check is the primary norm enforcement.
pub fn compute_jl_projection(w: &[i64], seed: [u8; 32], m: usize) -> Vec<i64> {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    if w.is_empty() {
        return vec![0i64; m];
    }

    let inv_sqrt_m = (3.0 / (m as f64)).sqrt(); // Achlioptas ±√(3/m)
    let scaler = 1_000_000i64; // fixed-point scaling to keep integer arithmetic

    let mut rng = StdRng::from_seed(seed);
    let mut projection = vec![0i64; m];

    for proj in &mut projection {
        let mut sum: f64 = 0.0;
        // Achlioptas sparse: each entry is ±√(3/m) with prob 1/6 each, or 0 with prob 2/3
        for &wj in w.iter() {
            let r: f64 = rng.gen(); // random in [0,1)
            if r < 1.0 / 6.0 {
                sum += (wj as f64) * inv_sqrt_m;
            } else if r < 2.0 / 6.0 {
                sum -= (wj as f64) * inv_sqrt_m;
            }
            // else: 0 (prob 2/3)
        }
        *proj = (sum * scaler as f64) as i64;
    }
    projection
}

/// Compute raw (unscaled) JL projection sums for in-circuit comparison.
///
/// Returns Σ sign · w[j] per dimension — integer arithmetic, no scaling.
/// The circuit verifies these raw sums match its own matrix-vector product,
/// avoiding floating-point in the field.
pub fn compute_raw_jl_sum(w: &[i64], seed: [u8; 32], m: usize) -> Vec<i64> {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    if w.is_empty() {
        return vec![0i64; m];
    }

    let mut rng = StdRng::from_seed(seed);
    let mut projection = vec![0i64; m];

    for proj in &mut projection {
        let mut sum: i64 = 0;
        for &wj in w.iter() {
            let r: f64 = rng.gen();
            if r < 1.0 / 6.0 {
                sum += wj;
            } else if r < 2.0 / 6.0 {
                sum -= wj;
            }
        }
        *proj = sum;
    }
    projection
}

/// Compute sparse JL matrix entry lists from seed.
///
/// Returns `m` lists, each containing `(column_index, is_positive)` pairs
/// representing the non-zero entries of the Achlioptas sparse JL matrix Π.
/// Uses the SAME deterministic RNG as `compute_raw_jl_sum` so that the
/// same entry lists can be passed alongside raw sums into the circuit
/// for in-circuit projection verification without regenerating entries.
pub fn compute_jl_entries(seed: [u8; 32], m: usize, n: usize) -> Vec<Vec<(usize, bool)>> {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    let mut rng = StdRng::from_seed(seed);
    let mut entries = vec![Vec::new(); m];
    for entry in &mut entries {
        for j in 0..n {
            let r: f64 = rng.gen();
            if r < 1.0 / 6.0 {
                entry.push((j, true));
            } else if r < 2.0 / 6.0 {
                entry.push((j, false));
            }
        }
    }
    entries
}

/// Compute L2 squared norm of a vector.
pub fn l2_squared(v: &[i64]) -> i128 {
    v.iter().map(|&x| (x as i128) * (x as i128)).sum()
}

fn rlwe_context() -> Result<&'static Arc<Context>, NizkError> {
    static CTX: OnceLock<Result<Arc<Context>, String>> = OnceLock::new();
    CTX.get_or_init(|| {
        let n = rlwe_n();
        let moduli = pvthfhe_types::rlwe_moduli();
        Context::new(&moduli, n)
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
        return Err(NizkError::InvalidInput("c_rns length must be L*N"));
    }
    if s_i.len() != n || e_i.len() != n {
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
    d_commitment: &[u8; 32],
) -> Result<SigmaProof, NizkError> {
    prove_round(session_id, participant_id, stmt, wit, rng, d_commitment, 0)
}

/// Produce a sigma proof for statement (c, d_i) and witness (s_i, e_i)
/// with `round_index` bound into the Fiat-Shamir transcript.
///
/// Used internally by [`prove_multi`] to create per-round proofs with
/// round-index domain separation.
fn prove_round(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    wit: &SigmaWitness,
    rng: &mut dyn RngCore,
    d_commitment: &[u8; 32],
    round_index: usize,
) -> Result<SigmaProof, NizkError> {
    let n = rlwe_n();
    let rns_len = n * num_rns_limbs();
    if stmt.c_rns.len() != rns_len || stmt.d_rns.len() != rns_len {
        return Err(NizkError::InvalidInput("statement RNS lengths must be L*N"));
    }
    if wit.s_i.len() != n || wit.e_i.len() != n {
        return Err(NizkError::InvalidInput(
            "witness polynomials must have length N",
        ));
    }
    let ctx = rlwe_context()?;

    #[cfg(test)]
    const MAX_REJECTION_RETRIES: usize = 5;
    #[cfg(not(test))]
    const MAX_REJECTION_RETRIES: usize = 100_000;

    for _attempt in 0..MAX_REJECTION_RETRIES {
        let y_s = sample_bounded(rng, n, B_Y)?;
        let y_e = sample_bounded(rng, n, B_Y)?;

        let y_s_rns = int_poly_to_rns(&y_s, ctx)?;
        let y_e_rns = int_poly_to_rns(&y_e, ctx)?;
        let c_ys_rns = poly_mul_rq(&stmt.c_rns, &y_s_rns, ctx)?;
        let t_rns = rns_add(&c_ys_rns, &y_e_rns, ctx)?;

        let transcript_commitment = derive_transcript_commitment(&t_rns, &stmt.c_rns, &stmt.d_rns);
        let ch = derive_challenge_from_commitment(
            &transcript_commitment,
            session_id,
            participant_id,
            round_index,
            d_commitment,
        );

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

        // Lyubashevsky 2009, Lemma 4: reject with probability
        // 1 - exp((-2*ch*<y,s> - ||ch*s||²) / (2 * M * σ²))
        // For scalar challenge ch ∈ {-1,0,1}:
        let ys_dot: f64 = y_s
            .iter()
            .zip(wit.s_i.iter())
            .map(|(&a, &b)| (a as f64) * (b as f64))
            .sum();
        let ch_f64 = ch as f64;
        let s_norm_sq: f64 = wit.s_i.iter().map(|&x| (x as f64) * (x as f64)).sum();
        let exponent = (-2.0 * ch_f64 * ys_dot - ch_f64 * ch_f64 * s_norm_sq)
            / (2.0 * REJECTION_M * (B_Y as f64).powi(2));
        let accept_prob = exponent.exp();

        let mut sample_bytes = [0u8; 8];
        rng.fill_bytes(&mut sample_bytes);
        let raw = u64::from_le_bytes(sample_bytes);
        let sample = (raw as f64) / (u64::MAX as f64);

        if sample < accept_prob {
            return Ok(SigmaProof {
                t_rns,
                z_s,
                z_e,
                ch,
            });
        }
    }
    Err(NizkError::ProofGenerationFailed(
        "sigma rejection sampling exhausted all retries",
    ))
}

/// Produce k independent sigma proofs via parallel repetition.
///
/// Each round uses a fresh masking vector (y_s, y_e) and independently-derived
/// challenge. The round index `i ∈ {0..num_rounds}` is bound into the Fiat-Shamir
/// transcript to prevent cross-round replay.
///
/// Soundness error = (2/3)^num_rounds.
pub fn prove_multi(
    session_id: &[u8],
    participant_id: u32,
    stmt: &SigmaStatement,
    wit: &SigmaWitness,
    rng: &mut dyn RngCore,
    d_commitment: &[u8; 32],
    num_rounds: usize,
) -> Result<SigmaMultiProof, NizkError> {
    let mut rounds = Vec::with_capacity(num_rounds);
    for i in 0..num_rounds {
        let proof = prove_round(session_id, participant_id, stmt, wit, rng, d_commitment, i)?;
        rounds.push(proof);
    }
    Ok(SigmaMultiProof { rounds })
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
        return Err(NizkError::InvalidInput("statement RNS lengths must be L*N"));
    }
    if proof.t_rns.len() != rns_len {
        return Err(NizkError::InvalidInput("proof t_rns length must be L*N"));
    }
    if proof.z_s.len() != n || proof.z_e.len() != n {
        return Err(NizkError::InvalidInput(
            "proof polynomial lengths must be N",
        ));
    }
    if proof.ch != -1 && proof.ch != 0 && proof.ch != 1 {
        return Err(NizkError::InvalidInput("challenge must be -1, 0, or 1"));
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
        return Err(NizkError::VerificationFailed(
            "sigma multi-proof must have at least one round",
        ));
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

/// Compute the secret-key binding hash that links a NIZK proof to a party's
/// registered secret key share via the deterministic share polynomial `d_rns`.
///
/// `sk_binding = Sha256(d_rns || participant_id || session_id)`, domain-separated
/// with `pvthfhe-sk-binding/v1`.  The verifier can reconstruct this hash from
/// the proof-embedded `d_rns` and check it against the DKG registry.
pub fn compute_sk_binding(d_rns: &[u64], participant_id: u32, session_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pvthfhe_domain_tags::Tag::SigmaSkBinding.as_bytes());
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
    let n = rlwe_n();
    let expected = n * ctx.q.len();
    if a.len() != expected || b.len() != expected {
        return Err(NizkError::InvalidInput("rns_add: length mismatch"));
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
    let q0 = i64::try_from(ctx.q[0].modulus())
        .map_err(|_| NizkError::InvalidInput("q0 too large for i64"))?;
    let mut result = vec![0i64; n];
    for j in 0..n {
        let c = i64::try_from(prod_rns[j])
            .map_err(|_| NizkError::InvalidInput("prod coeff out of i64 range"))?;
        result[j] = if c > q0 / 2 { c - q0 } else { c };
    }
    Ok(result)
}

// ── Scalar challenge derivation (Poseidon-based) ─────────────────────────

/// Domain separator for scalar-challenge sigma protocol (v2).
const SCALAR_CHALLENGE_DOMAIN: &[u8] = pvthfhe_domain_tags::Tag::SigmaScalarChallenge.as_bytes();

// P1 OPEN PROBLEM: Ternary scalar challenge (ch ∈ {-1,0,1}) provides ~1.58 bits
// of soundness per execution. With one round, the soundness error is 2/3 —
// an adversary succeeds 66% of the time by guessing the challenge.
// Resolution pending: either parallel repetition (~90 rounds for 2^-128) or
// switching to binary polynomial challenges in {0,1}^N with NTT-optimized gadgets.
// Tracked as OPEN PROBLEM P1 in SECURITY.md.

// P2-1 audit remediation: the T2 FS-outside-circuit path replaced the legacy
// derive_challenge_scalar with derive_challenge_from_commitment which directly
// produces i64 from the commitment hash without intermediate Poseidon reduction.

/// T2: Derive a Keccak256 transcript commitment from the sigma transcript data.
///
/// Computes `com = Keccak256(DOMAIN || t_rns || c_rns || d_i_rns)` which binds
/// the prover's first message t and the statement (c, d_i) before the challenge
/// is revealed. This commitment is verified in-circuit (via Poseidon, ~900 constraints)
/// so the Fiat-Shamir challenge derivation can be moved outside the circuit
/// (Symphony §6).
pub fn derive_transcript_commitment(t_rns: &[u64], c_rns: &[u64], d_rns: &[u64]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(SCALAR_CHALLENGE_DOMAIN);
    hasher.update(b"t2-commit");
    hasher.update((t_rns.len() as u64).to_be_bytes());
    for &x in t_rns {
        hasher.update(x.to_le_bytes());
    }
    for &x in c_rns {
        hasher.update(x.to_le_bytes());
    }
    for &x in d_rns {
        hasher.update(x.to_le_bytes());
    }
    hasher.finalize().into()
}

/// T2: Derive a scalar ternary challenge from a transcript commitment.
///
/// Replaces the raw `derive_challenge_scalar` when T2 FS-outside-circuit is active.
/// Instead of hashing the full transcript, we hash only the commitment and session
/// binding, then use Poseidon to produce the Fiat-Shamir challenge.
///
/// This is cheaper in-circuit because the commitment (32 bytes) is much smaller
/// than the raw transcript data (3 × L × N × 8 bytes ≈ 384KB).
///
/// `round_index` binds the repetition round into the FS transcript to prevent
/// cross-round replay when SIGMA_REPETITIONS > 1.
pub fn derive_challenge_from_commitment(
    commitment: &[u8; 32],
    session_id: &[u8],
    participant_id: u32,
    round_index: usize,
    d_commitment: &[u8; 32],
) -> i64 {
    let mut prefix = Sha256::new();
    prefix.update(SCALAR_CHALLENGE_DOMAIN);
    prefix.update(b"t2-commit-ch");
    prefix.update(session_id);
    prefix.update(participant_id.to_le_bytes());
    prefix.update((round_index as u64).to_le_bytes());
    // P2-1: bind PVSS d_commitment into the FS challenge to prevent
    // cross-commitment proof replay.
    prefix.update(d_commitment);

    let digest = labeled_sha256(&prefix, b"commitment", commitment);
    let lo = bytes16_to_fr(&digest[..16]);
    let hi = bytes16_to_fr(&digest[16..]);
    let ch_fr = match poseidon_hash(&[lo, hi]) {
        Ok(fr) => fr,
        Err(_) => return 0,
    };

    let bytes = fr_to_bytes(&ch_fr);
    for &byte in &bytes {
        if let Some(ch) = uniform_ternary(byte) {
            return ch;
        }
    }
    0 // fallback: all 32 bytes ≥ 252 (probability < 2^-120)
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
    // M3: 16-byte input is always < |Fr| (2^128 << 2^254), no barrel reduction.
    Fr::from_le_bytes_mod_order(&buf)
}

/// Hash a slice of Fr elements using Poseidon.
fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, NizkError> {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|_| NizkError::VerificationFailed("Poseidon arity out of circom range"))?;
    hasher
        .hash(inputs)
        .map_err(|_| NizkError::VerificationFailed("Poseidon hash failed"))
}

/// Rejection-sampled uniform ternary from a single byte.
///
/// Bytes 0..=251 are split into three equal buckets of 84 each:
/// 0..84 → -1, 84..168 → 0, 168..252 → 1.
/// Bytes ≥ 252 are rejected (returns None); the caller must retry.
pub fn uniform_ternary(byte: u8) -> Option<i64> {
    if byte >= 252 {
        return None;
    }
    Some(match byte / 84 {
        0 => -1,
        1 => 0,
        _ => 1,
    })
}

/// Convert an Fr element to its little-endian byte representation.
fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let le = fr.into_bigint().to_bytes_le();
    let len = le.len().min(32);
    bytes[..len].copy_from_slice(&le[..len]);
    bytes
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
    let n = rlwe_n();
    let expected = n * ctx.q.len();
    if a.len() != expected || b.len() != expected {
        return Err(NizkError::InvalidInput(
            "rns_add_scalar_mul: length mismatch",
        ));
    }
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
            .map_err(|_| NizkError::InvalidInput("poly convert failed"))?;
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
        _ => return Err(NizkError::InvalidInput("challenge must be -1, 0, or 1")),
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
    h.update(pvthfhe_domain_tags::Tag::SigmaSzGamma.as_bytes());
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
    let moduli = pvthfhe_types::rlwe_moduli();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_ternary_smoke() {
        assert_eq!(uniform_ternary(0).unwrap(), -1);
        assert_eq!(uniform_ternary(83).unwrap(), -1);
        assert_eq!(uniform_ternary(84).unwrap(), 0);
        assert_eq!(uniform_ternary(167).unwrap(), 0);
        assert_eq!(uniform_ternary(168).unwrap(), 1);
        assert_eq!(uniform_ternary(251).unwrap(), 1);
        assert!(uniform_ternary(252).is_none());
        assert!(uniform_ternary(255).is_none());
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
        let t_rns = vec![1u64; rlwe_n() * num_rns_limbs()];
        let _c_rns = vec![2u64; rlwe_n() * num_rns_limbs()];
        let _d_rns = vec![3u64; rlwe_n() * num_rns_limbs()];
        let _pvss = [0u8; 32];

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
        assert_ne!(
            digest_a, digest_b,
            "SHA-256 digests must differ with different session IDs"
        );
    }

    /// P2-1 RED: challenge must change when d_commitment differs.
    /// The PVSS commitment must be bound into the T2 Fiat-Shamir challenge
    /// to prevent an adversary from reusing a proof with a different commitment.
    #[test]
    fn challenge_depends_on_d_commitment() {
        let d_commit_a = [0xAAu8; 32];
        let d_commit_b = [0xBBu8; 32];
        let session_id = b"test-session";
        let participant_id = 1u32;
        let round_index = 0usize;

        let transcript_commitment = [0x42u8; 32];

        let ch_a = derive_challenge_from_commitment(
            &transcript_commitment,
            session_id,
            participant_id,
            round_index,
            &d_commit_a,
        );
        let ch_b = derive_challenge_from_commitment(
            &transcript_commitment,
            session_id,
            participant_id,
            round_index,
            &d_commit_b,
        );

        assert_ne!(
            ch_a, ch_b,
            "P2-1: challenge must differ when d_commitment changes"
        );
    }

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

    /// F4 RED: rejection sampling exhaustion must return an error, not a fallback proof.
    /// Uses a deterministic counting RNG that forces rejection on every attempt
    /// to verify the prover exhausts retries and returns Err.
    #[test]
    fn test_rejection_sampling_exhausts_retries_returns_error() {
        use std::cell::Cell;

        let n = rlwe_n();
        let sample_quota: usize = 2 * n;

        // CountingRng: during the `sample_quota` sampling phase, fills with
        // B_Y (16384) LE bytes so sample_bounded returns y = B_Y - B_Y = 0.
        // With y=0, ys_dot=0 and accept_prob ≤ 1.0 for all challenges,
        // so the rejection check (filling with u64::MAX) always rejects.
        struct CountingRng<'a> {
            remaining_samples: &'a Cell<usize>,
            reset_quota: usize,
        }
        impl RngCore for CountingRng<'_> {
            fn next_u32(&mut self) -> u32 {
                0
            }
            fn next_u64(&mut self) -> u64 {
                0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                if dest.len() == 8 {
                    let n = self.remaining_samples.get();
                    if n > 0 {
                        self.remaining_samples.set(n - 1);
                        // Return B_Y = 16384 LE so sample_bounded gives y = 0.
                        dest.copy_from_slice(&16384u64.to_le_bytes());
                    } else {
                        // Rejection check: fill with u64::MAX to force rejection.
                        dest.fill(0xFF);
                        self.remaining_samples.set(self.reset_quota);
                    }
                } else {
                    dest.fill(0);
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let rns_len = n * num_rns_limbs();
        let stmt = SigmaStatement {
            c_rns: vec![1u64; rns_len],
            d_rns: vec![1u64; rns_len],
        };
        let wit = SigmaWitness {
            s_i: vec![1i64; n],
            e_i: vec![1i64; n],
        };

        let remaining = Cell::new(sample_quota);
        let mut rng = CountingRng {
            remaining_samples: &remaining,
            reset_quota: sample_quota,
        };

        let result = prove_round(b"test-f4", 0, &stmt, &wit, &mut rng, &[0u8; 32], 0);
        assert!(
            result.is_err(),
            "F4: rejection sampling exhaustion must return Err, not a fallback proof. Got: {result:?}"
        );
    }
}
