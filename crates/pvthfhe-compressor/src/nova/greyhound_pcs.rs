//! Greyhound: Lattice-based polynomial commitment scheme (CRYPTO 2024).
//!
//! Implements the Greyhound polynomial commitment from Ngoc Khanh Nguyen and
//! Gregor Seiler (ePrint 2024/1293). The construction is a Module-SIS-based PCS
//! with O(√N) evaluation protocol and transparent setup.
//!
//! # Construction
//!
//! The scheme works over a finite field F_q (here: the BN254 scalar field).
//! For a polynomial f ∈ F_q^{<N}[X] where N = m·r:
//!
//! - **Commit**: Apply gadget decomposition to each r-length chunk of f,
//!   compute inner commitments A·s_i = t_i, decompose t_i, then outer
//!   commitment B·t̂ = u.
//!
//! - **Open**: Three-round protocol proving f(x) = y.
//!   Round 1: prover sends v = D·ŵ where w = a^T·[s_1|...|s_r].
//!   Round 2: verifier sends challenge c.
//!   Round 3: prover sends z = [s_1|...|s_r]·c and (ŵ, t̂).
//!
//! - **Verify**: Check the linear system from Figure 4 of the paper.
//!
//! # Parameters
//!
//! All matrices (A, B, D) are derived deterministically from a 32-byte
//! seed using ChaCha20Rng, providing transparent setup (no trusted ceremony).

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha3::{Digest, Keccak256};
use std::fmt;

// ── Public Parameters ──────────────────────────────────────────────────

/// Greyhound transparent public parameters.
///
/// All matrices are derived deterministically from `ppseed`.
#[derive(Clone)]
pub struct GreyhoundParams {
    /// SIS rank (commitment output dimension).
    pub n: usize,
    /// Row-folding parameter: m ≈ √(N/d), where d=1 for field elements.
    pub m: usize,
    /// Column-folding parameter: r ≈ √(N/d), where d=1 for field elements.
    pub r: usize,
    /// Gadget base for inner commitment decomposition.
    pub b0: u64,
    /// Gadget base for outer commitment decomposition.
    pub b: u64,
    /// log_{b0}(field_modulus)
    pub delta0: usize,
    /// log_{b}(field_modulus)
    pub delta: usize,
    /// Commitment matrix A ∈ F_q^{n × (δ₀·m)}
    pub a_matrix: Vec<Vec<Fr>>,
    /// Commitment matrix B ∈ F_q^{n × (n·δ·r)}
    pub b_matrix: Vec<Vec<Fr>>,
    /// Extra commitment matrix D ∈ F_q^{n × (δ·r)}
    pub d_matrix: Vec<Vec<Fr>>,
}

impl fmt::Debug for GreyhoundParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GreyhoundParams")
            .field("n", &self.n)
            .field("m", &self.m)
            .field("r", &self.r)
            .field("b0", &self.b0)
            .field("b", &self.b)
            .field("delta0", &self.delta0)
            .field("delta", &self.delta)
            .finish_non_exhaustive()
    }
}

// ── Data Types ─────────────────────────────────────────────────────────

/// A Module-SIS commitment to a polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GreyhoundCommitment {
    /// Outer commitment u = B·t̂ ∈ F_q^n
    pub u: Vec<Fr>,
}

/// Witness (decommitment state) for a Greyhound commitment.
#[derive(Clone, Debug)]
pub struct GreyhoundWitness {
    /// Decomposed polynomial vectors s_i ∈ F_q^{δ₀·m}
    pub s: Vec<Vec<Fr>>,
    /// Inner commitment decompositions t̂_i ∈ F_q^{n·δ}
    pub t_hat: Vec<Vec<Fr>>,
    /// Inner commitments t_i ∈ F_q^n
    pub t: Vec<Vec<Fr>>,
}

/// Opening proof for polynomial evaluation.
#[derive(Clone, Debug)]
pub struct GreyhoundOpeningProof {
    /// Decomposed w vector ŵ ∈ F_q^{δ·r}
    pub w_hat: Vec<Fr>,
    /// Decomposed inner commitments t̂ ∈ F_q^{n·δ·r}
    pub t_hat: Vec<Fr>,
    /// Response vector z ∈ F_q^{δ₀·m}
    pub z: Vec<Fr>,
    /// First-round commitment v = D·ŵ ∈ F_q^n
    pub v: Vec<Fr>,
    /// Verifier challenge c ∈ F_q^r
    pub c: Vec<Fr>,
    /// Claimed evaluation value y = f(x)
    pub y: Fr,
    /// Evaluation point x
    pub x: Fr,
}

/// Greyhound polynomial commitment scheme.
pub struct GreyhoundPCS;

// ── Modular arithmetic helpers ─────────────────────────────────────────

/// Compute ⌈log_b(q)⌉, the number of base-b digits needed to represent
/// a field element value.
const fn gadget_dimension(bit_len: usize, base: u64) -> usize {
    let bits_per = bits_per_digit(base);
    (bit_len + bits_per - 1) / bits_per
}

const fn bits_per_digit(base: u64) -> usize {
    let mut b = base;
    let mut bits = 0usize;
    while b > 1 {
        b >>= 1;
        bits += 1;
    }
    bits
}

/// Decompose a field element into base-b digits (gadget decomposition).
/// Returns a vector of `delta` field elements, each in [0, b).
///
/// Uses the full big-integer representation to decompose a 254-bit field
/// element. Each digit d_i satisfies 0 ≤ d_i < b, and value = Σ d_i · b^i.
fn decompose_scalar(value: &Fr, base: u64, delta: usize) -> Vec<Fr> {
    use ark_ff::BigInt;
    let bigint: BigInt<4> = value.into_bigint();
    let limbs = bigint.as_ref();
    let mut digits = Vec::with_capacity(delta);
    let mut carry = vec![0u64; limbs.len() + 1];

    // Copy limbs into carry buffer
    for (i, &limb) in limbs.iter().enumerate() {
        carry[i] = limb;
    }

    for _ in 0..delta {
        // Divide the multi-precision number by base, remainder is the digit
        let remainder = divide_mp_by_scalar(&mut carry, base);
        digits.push(Fr::from(remainder));
    }
    digits
}

/// Divide a multi-precision integer (little-endian u64 limbs) by a scalar, returning the remainder.
/// The quotient replaces the input.
fn divide_mp_by_scalar(limbs: &mut [u64], divisor: u64) -> u64 {
    let mut remainder: u64 = 0;
    for limb in limbs.iter_mut().rev() {
        let combined = ((remainder as u128) << 64) | (*limb as u128);
        *limb = (combined / divisor as u128) as u64;
        remainder = (combined % divisor as u128) as u64;
    }
    remainder
}

/// Extract the small integer value of an Fr element known to be in {-1, 0, 1}.
fn fr_to_small_int(fr: &Fr) -> i8 {
    let bytes = fr.into_bigint().to_bytes_le();
    if bytes.iter().all(|&b| b == 0) {
        return 0;
    }
    // Check if it's one
    if fr == &Fr::one() {
        return 1;
    }
    // Check if it's minus one (large field element)
    let neg_one = -Fr::one();
    if fr == &neg_one {
        return -1;
    }
    // Fallback: try to parse as small value
    let mut val: u64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        val |= (b as u64) << (i * 8);
    }
    if val < 128 {
        val as i8
    } else {
        // Large value: treat as negative (roundtrip from signed_i64_to_fr)
        0 // conservative fallback
    }
}

/// Extract the small unsigned integer value from an Fr element.
fn fr_to_small_unsigned(fr: &Fr) -> u64 {
    let bytes = fr.into_bigint().to_bytes_le();
    let mut val: u64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        val |= (b as u64) << (i * 8);
    }
    val
}

/// Convert a signed i64 to Fr, preserving the sign.
fn signed_i64_to_fr(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from((-value) as u64)
    }
}

/// Convert an Fr element that represents a small signed integer back to i64.
/// Values near the field modulus are interpreted as negative.
fn fr_to_i64(fr: &Fr) -> i64 {
    let bytes = fr.into_bigint().to_bytes_le();
    let modulus = <Fr as PrimeField>::MODULUS;
    let modulus_bytes = modulus.to_bytes_le();
    let mut val_limbs = [0u64; 4];
    let mut mod_limbs = [0u64; 4];
    for i in 0..4 {
        val_limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap_or([0u8; 8]));
        mod_limbs[i] = u64::from_le_bytes(
            modulus_bytes[i * 8..(i + 1) * 8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
    }
    // Simple check: if fr == -Fr::from(k) for some small k, return -k
    for k in 0..1024 {
        let neg_k = if k == 0 {
            Fr::zero()
        } else {
            -Fr::from(k as u64)
        };
        if fr == &neg_k {
            return -(k as i64);
        }
    }
    // Fallback: check if small positive
    for k in 0..1024 {
        if fr == &Fr::from(k as u64) {
            return k as i64;
        }
    }
    // Final fallback: use first limb
    val_limbs[0] as i64
}

/// Reconstruct a field element from signed integer gadget digits.
/// Each digit d_i satisfies -base < d_i < base (or a small multiple for z entries).
/// Computes Σ d_i · base^i as a signed integer sum using i128, then converts to Fr.
fn recompose_scalar(digits: &[Fr], base: u64) -> Fr {
    let mut accumulator = Fr::zero();
    let mut pow = Fr::one();
    let base_fr = Fr::from(base);
    for digit in digits {
        accumulator += pow * Fr::from(fr_to_small_unsigned(digit));
        pow *= base_fr;
    }
    accumulator
}

fn recompose_signed_scalar(digits_i64: &[i64], base: u64) -> Fr {
    let mut accumulator = Fr::zero();
    let mut pow = Fr::one();
    let base_fr = Fr::from(base);
    for &d in digits_i64 {
        if d >= 0 {
            accumulator += pow * Fr::from(d as u64);
        } else {
            accumulator -= pow * Fr::from((-d) as u64);
        }
        pow *= base_fr;
    }
    accumulator
}

fn multiply_bigint_by_scalar(bi: &ark_ff::BigInt<4>, scalar: u64) -> ark_ff::BigInt<4> {
    let limbs = bi.as_ref();
    let mut result_limbs = [0u64; 4];
    let mut carry: u64 = 0;
    for (i, &limb) in limbs.iter().enumerate() {
        let prod = (limb as u128) * (scalar as u128) + (carry as u128);
        result_limbs[i] = prod as u64;
        carry = (prod >> 64) as u64;
    }
    ark_ff::BigInt::new(result_limbs)
}

/// Add two BigInt<4> values.
fn add_bigints(a: &ark_ff::BigInt<4>, b: &ark_ff::BigInt<4>) -> ark_ff::BigInt<4> {
    let a_limbs = a.as_ref();
    let b_limbs = b.as_ref();
    let mut result_limbs = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4 {
        let sum = (a_limbs[i] as u128) + (b_limbs[i] as u128) + (carry as u128);
        result_limbs[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    ark_ff::BigInt::new(result_limbs)
}

// ── Matrix generation (deterministic from seed) ────────────────────────

fn rng_from_seed(seed: &[u8; 32], domain: &[u8]) -> ChaCha20Rng {
    let mut hasher = Keccak256::new();
    hasher.update(pvthfhe_domain_tags::Tag::GreyhoundPcs.as_bytes());
    hasher.update(seed);
    hasher.update(domain);
    let derived: [u8; 32] = hasher.finalize().into();
    // allow-seeded-rng: Greyhound transparent setup uses deterministic PRNG from ppseed
    ChaCha20Rng::from_seed(derived)
}

/// Generate a uniform random Fr element from an rng.
fn random_fr(rng: &mut ChaCha20Rng) -> Fr {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Generate an n × m matrix over Fr from a seed.
fn generate_matrix(seed: &[u8; 32], domain: &[u8], rows: usize, cols: usize) -> Vec<Vec<Fr>> {
    let mut rng = rng_from_seed(seed, domain);
    let mut matrix = Vec::with_capacity(rows);
    for _ in 0..rows {
        let mut row = Vec::with_capacity(cols);
        for _ in 0..cols {
            row.push(random_fr(&mut rng));
        }
        matrix.push(row);
    }
    matrix
}

// ── Valid parameters for different polynomial degrees ──────────────────

const MODULUS_BITS: usize = 254; // BN254 scalar field ~254 bits

/// Pre-defined parameter sets for Greyhound.
///
/// | N     | m    | r    | n | b0 | δ0 | b | δ |
/// |-------|------|------|---|----|----|---|---|
/// | 2^26  | 3156 | 336  | 18| 6  | 5  | 7 | 6 |
/// | 2^28  | 6312 | 1336 | 18| 5  | 6  | 7 | 6 |
/// | 2^30  | 12625| 1329 | 18| 4  | 8  | 6 | 5 |
///
/// These are adapted from the Greyhound paper Table 4, scaled down for
/// our smaller test parameters.
#[derive(Clone, Copy, Debug)]
pub struct GreyhoundParamSet {
    pub n: usize,
    pub m: usize,
    pub r: usize,
    pub b0: u64,
    pub b: u64,
    pub delta0: usize,
    pub delta: usize,
}

impl GreyhoundParamSet {
    /// Small test parameters (N = m * r ≈ 64).
    /// Suitable for unit tests and quick verification.
    pub const fn test_small() -> Self {
        Self {
            n: 2,
            m: 8,
            r: 8,
            b0: 2,
            b: 2,
            delta0: gadget_dimension(MODULUS_BITS, 2),
            delta: gadget_dimension(MODULUS_BITS, 2),
        }
    }

    /// Medium parameters (N = m * r ≈ 256).
    pub const fn test_medium() -> Self {
        Self {
            n: 4,
            m: 16,
            r: 16,
            b0: 4,
            b: 4,
            delta0: gadget_dimension(MODULUS_BITS, 4),
            delta: gadget_dimension(MODULUS_BITS, 4),
        }
    }

    /// Parameters for N ≈ 2^10 (1024 coefficients).
    pub const fn small() -> Self {
        Self {
            n: 8,
            m: 32,
            r: 32,
            b0: 8,
            b: 8,
            delta0: gadget_dimension(MODULUS_BITS, 8),
            delta: gadget_dimension(MODULUS_BITS, 8),
        }
    }
}

// ── GreyhoundPCS implementation ────────────────────────────────────────

impl GreyhoundPCS {
    /// Generate transparent public parameters from a 32-byte seed.
    ///
    /// Uses the given parameter set to determine dimensions and gadget
    /// decomposition bases. All matrices A, B, D are derived
    /// deterministically from the seed.
    pub fn setup(ppseed: &[u8; 32], ps: &GreyhoundParamSet) -> GreyhoundParams {
        let inner_cols = ps.delta0 * ps.m; // δ₀·m
        let outer_rows = ps.n * ps.delta * ps.r; // n·δ·r
        let d_cols = ps.delta * ps.r; // δ·r

        // Generate A ∈ F_q^{n × (δ₀·m)}
        let a_matrix = generate_matrix(ppseed, b"greyhound-A", ps.n, inner_cols);
        // Generate B ∈ F_q^{n × (n·δ·r)}
        let b_matrix = generate_matrix(ppseed, b"greyhound-B", ps.n, outer_rows);
        // Generate D ∈ F_q^{n × (δ·r)}
        let d_matrix = generate_matrix(ppseed, b"greyhound-D", ps.n, d_cols);

        GreyhoundParams {
            n: ps.n,
            m: ps.m,
            r: ps.r,
            b0: ps.b0,
            b: ps.b,
            delta0: ps.delta0,
            delta: ps.delta,
            a_matrix,
            b_matrix,
            d_matrix,
        }
    }

    /// Commit to a polynomial f ∈ F_q^{<N}[X] where N = m·r.
    ///
    /// Returns (commitment, witness).
    ///
    /// # Algorithm (Figure 4, Commit):
    /// 1. Split f into r vectors f_i ∈ F_q^m (one per chunk)
    /// 2. Gadget-decompose each f_i → s_i ∈ F_q^{δ₀·m}
    /// 3. Inner commitment: t_i = A·s_i ∈ F_q^n
    /// 4. Gadget-decompose each t_i → t̂_i ∈ F_q^{n·δ}
    /// 5. Outer commitment: u = B·t̂ ∈ F_q^n (t̂ stacked from all t̂_i)
    pub fn commit(
        params: &GreyhoundParams,
        poly: &[Fr],
    ) -> Result<(GreyhoundCommitment, GreyhoundWitness), GreyhoundError> {
        let n_poly = params.m * params.r;
        if poly.len() > n_poly {
            return Err(GreyhoundError::InvalidInput(format!(
                "polynomial degree {} exceeds bound N=m·r={}",
                poly.len(),
                n_poly
            )));
        }

        // Pad to full length
        let mut padded = poly.to_vec();
        padded.resize(n_poly, Fr::zero());

        let mut s = Vec::with_capacity(params.r);
        let mut t = Vec::with_capacity(params.r);
        let mut t_hat = Vec::with_capacity(params.r);

        for i in 0..params.r {
            // Extract f_i: chunk of m coefficients
            let start = i * params.m;
            let end = start + params.m;
            let f_i = &padded[start..end];

            // Gadget decomposition: s_i = G^{-1}(f_i)
            let mut s_i = Vec::with_capacity(params.delta0 * params.m);
            for coeff in f_i {
                let digits = decompose_scalar(coeff, params.b0, params.delta0);
                s_i.extend(digits);
            }

            // Inner commitment: t_i = A·s_i
            let t_i = matrix_vector_mul(&params.a_matrix, &s_i);

            // Gadget decomposition of t_i
            let mut t_hat_i = Vec::with_capacity(params.n * params.delta);
            for coeff in &t_i {
                let digits = decompose_scalar(coeff, params.b, params.delta);
                t_hat_i.extend(digits);
            }

            s.push(s_i);
            t.push(t_i);
            t_hat.push(t_hat_i);
        }

        // Outer commitment: u = B·t̂ (t̂ is the stack of all t_hat_i)
        let t_hat_flat: Vec<Fr> = t_hat.iter().flatten().cloned().collect();
        let u = matrix_vector_mul(&params.b_matrix, &t_hat_flat);

        let witness = GreyhoundWitness { s, t_hat, t };
        Ok((GreyhoundCommitment { u }, witness))
    }

    /// Create an opening proof for polynomial evaluation at point x.
    ///
    /// This is the non-interactive version of the 3-round protocol from
    /// Figure 4 (Eval.P). Uses Fiat-Shamir to derive the challenge.
    ///
    /// Returns an OpeningProof.
    pub fn open(
        params: &GreyhoundParams,
        poly: &[Fr],
        eval_pt: &Fr,
        witness: &GreyhoundWitness,
        session_id: &str,
        prover_id: u64,
    ) -> Result<GreyhoundOpeningProof, GreyhoundError> {
        let n_poly = params.m * params.r;
        if poly.len() > n_poly {
            return Err(GreyhoundError::InvalidInput(format!(
                "polynomial degree {} exceeds bound N={}",
                poly.len(),
                n_poly
            )));
        }

        // Pad to full length
        let mut padded = poly.to_vec();
        padded.resize(n_poly, Fr::zero());

        // Compute y = f(x)
        let y = evaluate_polynomial(&padded, eval_pt);

        // Compute w_j = Σ_{k=0}^{m-1} x^k · f_{j*m+k}  for each j=0..r-1
        // This is the partial evaluation per row chunk, computed directly
        // in Fr to avoid overflow from gadget-decomposed dot products.
        let mut w_values = vec![Fr::zero(); params.r];
        for j in 0..params.r {
            let mut acc = Fr::zero();
            let mut xpow = Fr::one();
            for k in 0..params.m {
                let idx = j * params.m + k;
                if idx < padded.len() {
                    acc += xpow * padded[idx];
                }
                xpow *= eval_pt;
            }
            w_values[j] = acc;
        }

        // Compute ŵ = G^{-1}(w) (decompose each component of w)
        let mut w_hat = Vec::with_capacity(params.delta * params.r);
        for i in 0..params.r {
            let wi = w_values[i];
            let digits = decompose_scalar(&wi, params.b, params.delta);
            w_hat.extend(digits);
        }

        // First message: v = D·ŵ
        let v = matrix_vector_mul(&params.d_matrix, &w_hat);

        // ── Fiat-Shamir challenge derivation ──
        // c = H(pp || commitment || x || y || v)
        let t_hat_flat: Vec<Fr> = witness.t_hat.iter().flatten().cloned().collect();
        let u = matrix_vector_mul(&params.b_matrix, &t_hat_flat);
        // M5 (FIXED): Session and prover identity are now bound into the
        // challenge hash via the parameters threaded from the callers.
        let challenge = derive_challenge(params, &u, &v, eval_pt, &y, session_id, prover_id);
        let c: Vec<Fr> = challenge.iter().take(params.r).cloned().collect();

        // Compute z = [s_1|...|s_r] · c = sum_i c_i · s_i
        // The matrix [s_1|...|s_r] has dimensions (δ₀·m) × r
        // So z is of length δ₀·m.
        // Use i64 arithmetic to avoid modular wraparound for negative challenge values.
        let inner_dim = params.delta0 * params.m;
        let mut z_i64 = vec![0i64; inner_dim];
        for i in 0..params.r {
            if i < c.len() {
                // Convert c_i from Fr to i8 (expected to be -1, 0, or 1)
                let ci_val = fr_to_small_int(&c[i]);
                let si = &witness.s[i];
                for j in 0..inner_dim {
                    let si_val = fr_to_small_unsigned(&si[j]);
                    z_i64[j] += (ci_val as i64) * (si_val as i64);
                }
            }
        }
        // Convert z_i64 to Fr for the proof (preserving signed values)
        let mut z = vec![Fr::zero(); inner_dim];
        for j in 0..inner_dim {
            z[j] = signed_i64_to_fr(z_i64[j]);
        }

        // Verify the reconstructed w matches (for testing)
        // wᵢ = a^T·s_i for each i
        // c^T·w = a^T·z (should hold by construction)

        Ok(GreyhoundOpeningProof {
            w_hat,
            t_hat: t_hat_flat,
            z,
            v,
            c,
            y,
            x: *eval_pt,
        })
    }

    /// Verify an opening proof.
    ///
    /// Checks all the verification equations from Figure 4 (Eval.V):
    /// 1. D·ŵ = v
    /// 2. B·t̂ = u
    /// 3. b^T·G_{b,r}·ŵ = y (constant term check)
    /// 4. c^T·G_{b,r}·ŵ = a^T·z
    /// 5. (c^T ⊗ G_{b,n})·t̂ = A·z
    pub fn verify(
        params: &GreyhoundParams,
        commitment: &GreyhoundCommitment,
        eval_pt: &Fr,
        value: &Fr,
        proof: &GreyhoundOpeningProof,
        session_id: &str,
        prover_id: u64,
    ) -> Result<bool, GreyhoundError> {
        if commitment.u.len() != params.n
            || proof.v.len() != params.n
            || proof.w_hat.len() != params.delta * params.r
            || proof.t_hat.len() != params.n * params.delta * params.r
            || proof.z.len() != params.delta0 * params.m
            || proof.c.len() != params.r
        {
            return Ok(false);
        }

        // Check claimed value matches
        if proof.y != *value || proof.x != *eval_pt {
            return Ok(false);
        }

        // M5 (FIXED): Session and prover identity are bound into the
        // challenge hash via the parameters threaded from the callers.
        let expected_challenge = derive_challenge(
            params,
            &commitment.u,
            &proof.v,
            eval_pt,
            value,
            session_id,
            prover_id,
        );
        if expected_challenge != proof.c {
            return Ok(false);
        }

        if !proof.w_hat.iter().all(|digit| fr_digit_lt(digit, params.b)) {
            return Ok(false);
        }

        if !proof.t_hat.iter().all(|digit| fr_digit_lt(digit, params.b)) {
            return Ok(false);
        }

        // 1. D·ŵ = v
        let dv = matrix_vector_mul(&params.d_matrix, &proof.w_hat);
        if dv != proof.v {
            eprintln!(
                "[greyhound-verify] FAIL check1: dv={:?} v={:?}",
                dv, proof.v
            );
            return Ok(false);
        }

        // 2. B·t̂ = u
        let bu = matrix_vector_mul(&params.b_matrix, &proof.t_hat);
        if bu != commitment.u {
            eprintln!(
                "[greyhound-verify] FAIL check2: bu={:?} u={:?}",
                bu, commitment.u
            );
            return Ok(false);
        }

        // Build evaluation vectors a and b
        let b = build_evaluation_vector_b(params, eval_pt);

        // 3. b^T·G_{b,r}·ŵ = y
        //    First, reconstruct w from ŵ using gadget recomposition
        let w = recompose_w_hat(params, &proof.w_hat);
        // b^T·w = sum_i b_i * w_i
        let mut bw = Fr::zero();
        for i in 0..params.r {
            if i < b.len() && i < w.len() {
                bw += b[i] * w[i];
            }
        }
        if bw != *value {
            eprintln!("[greyhound-verify] FAIL check3: bw={:?} y={:?}", bw, value);
            return Ok(false);
        }

        // 4. c^T·G_{b,r}·ŵ = a^T·z
        //    c^T·w = a^T·z
        let mut cw = Fr::zero();
        for i in 0..params.r {
            if i < proof.c.len() && i < w.len() {
                cw += proof.c[i] * w[i];
            }
        }
        // Compute a^T·z = Σ_{k=0}^{m-1} x^k · recompose(z_block_k)
        // conv. z entries from Fr to i64 first (they may be negative from ternary challenges).
        let mut az = Fr::zero();
        let mut xpow = Fr::one();
        for k in 0..params.m {
            let start = k * params.delta0;
            let end = start + params.delta0;
            if end <= proof.z.len() {
                let z_i64_block: Vec<i64> =
                    proof.z[start..end].iter().map(|fr| fr_to_i64(fr)).collect();
                let f_k = recompose_signed_scalar(&z_i64_block, params.b0);
                az += xpow * f_k;
            }
            xpow *= eval_pt;
        }
        if cw != az {
            eprintln!("[greyhound-verify] FAIL check4: cw={:?} az={:?}", cw, az);
            return Ok(false);
        }

        // 5. (c^T ⊗ G_{b,n})·t̂ = A·z
        //    This is: sum_i c_i * G_{b,n} * t̂_i = A·z
        //    Where t̂ is organized as r blocks of n*delta elements each.
        let block_size = params.n * params.delta;
        let mut lhs = vec![Fr::zero(); params.n];
        for i in 0..params.r {
            if i < proof.c.len() {
                let ci = proof.c[i];
                let start = i * block_size;
                let end = start + block_size;
                if end <= proof.t_hat.len() {
                    let t_hat_i = &proof.t_hat[start..end];
                    // Reconstruct t_i = G_{b,n} * t̂_i
                    let t_i = recompose_t_hat_block(params, t_hat_i);
                    for j in 0..params.n {
                        lhs[j] += ci * t_i[j];
                    }
                }
            }
        }

        // A·z
        let rhs = matrix_vector_mul(&params.a_matrix, &proof.z);

        if lhs != rhs {
            eprintln!(
                "[greyhound-verify] FAIL check5: lhs={:?} rhs={:?}",
                lhs, rhs
            );
            return Ok(false);
        }

        // All checks passed
        Ok(true)
    }
}

// ── Non-interactive Greyhound convenience ──────────────────────────────

impl GreyhoundPCS {
    /// Full non-interactive commit-and-prove pipeline.
    ///
    /// Returns (commitment, opening_proof).
    pub fn commit_and_prove(
        params: &GreyhoundParams,
        poly: &[Fr],
        eval_pt: &Fr,
        session_id: &str,
        prover_id: u64,
    ) -> Result<(GreyhoundCommitment, GreyhoundOpeningProof), GreyhoundError> {
        let (commitment, witness) = Self::commit(params, poly)?;
        let proof = Self::open(params, poly, eval_pt, &witness, session_id, prover_id)?;
        Ok((commitment, proof))
    }
}

// ── Helper Functions ───────────────────────────────────────────────────

/// Multiply a matrix (n×m) by a vector (m) over Fr.
fn matrix_vector_mul(matrix: &[Vec<Fr>], vector: &[Fr]) -> Vec<Fr> {
    let rows = matrix.len();
    if rows == 0 || vector.is_empty() {
        return vec![Fr::zero(); rows];
    }
    let mut result = vec![Fr::zero(); rows];
    for (i, row) in matrix.iter().enumerate() {
        let mut sum = Fr::zero();
        let len = row.len().min(vector.len());
        for j in 0..len {
            sum += row[j] * vector[j];
        }
        result[i] = sum;
    }
    result
}

fn fr_digit_lt(fr: &Fr, bound: u64) -> bool {
    for k in 0..bound {
        if fr == &Fr::from(k) {
            return true;
        }
    }
    false
}

/// Evaluate a polynomial at a point using Horner's method.
fn evaluate_polynomial(coeffs: &[Fr], x: &Fr) -> Fr {
    let mut result = Fr::zero();
    for coeff in coeffs.iter().rev() {
        result = result * x + coeff;
    }
    result
}

/// Build the evaluation vector a for Greyhound protocol.
///
/// a^T = [1, x^d, x^{2d}, ..., x^{(m-1)d}] · G_{b0,m}
/// With d=1 for field elements.
fn build_evaluation_vector_a(params: &GreyhoundParams, x: &Fr) -> Vec<Fr> {
    // First build [1, x, x^2, ..., x^{m-1}]
    let mut powers = vec![Fr::one(); params.m];
    for i in 1..params.m {
        powers[i] = powers[i - 1] * x;
    }
    // Apply gadget matrix G_{b0,m}: each power gets decomposed
    let mut result = Vec::with_capacity(params.delta0 * params.m);
    for p in &powers {
        let digits = decompose_scalar(p, params.b0, params.delta0);
        result.extend(digits);
    }
    result
}

/// Build the evaluation vector b for Greyhound protocol.
///
/// b^T = [1, x^{md}, x^{2md}, ..., x^{(r-1)md}]
/// With d=1 for field elements.
fn build_evaluation_vector_b(params: &GreyhoundParams, x: &Fr) -> Vec<Fr> {
    let step = {
        let mut acc = Fr::one();
        for _ in 0..params.m {
            acc *= x;
        }
        acc
    }; // x^m
    let mut result = vec![Fr::one(); params.r];
    let mut power = Fr::one();
    for i in 1..params.r {
        power *= step;
        result[i] = power;
    }
    result
}

/// Compute dot products between a vector a and blocks of s.
///
/// s_stacked = [s_1 | s_2 | ... | s_r] where each s_i has length block_size.
/// Returns r dot products: [a·s_1, a·s_2, ..., a·s_r].
/// When `transpose` is true, s_stacked is treated as a matrix of shape
/// (r × block_size) stored row-major.
fn dot_product_blocks(
    a: &[Fr],
    s_stacked: &[Fr],
    num_blocks: usize,
    block_size: usize,
    _transpose: bool,
) -> Vec<Fr> {
    let mut result = vec![Fr::zero(); num_blocks];
    let a_len = a.len().min(block_size);
    for i in 0..num_blocks {
        let start = i * block_size;
        let mut sum = Fr::zero();
        for j in 0..a_len {
            let idx = start + j;
            if idx < s_stacked.len() {
                sum += a[j] * s_stacked[idx];
            }
        }
        result[i] = sum;
    }
    result
}

/// Reconstruct w ∈ F_q^r from ŵ ∈ F_q^{δ·r} using gadget recomposition.
fn recompose_w_hat(params: &GreyhoundParams, w_hat: &[Fr]) -> Vec<Fr> {
    let mut w = vec![Fr::zero(); params.r];
    for i in 0..params.r {
        let start = i * params.delta;
        let end = start + params.delta;
        if end <= w_hat.len() {
            w[i] = recompose_scalar(&w_hat[start..end], params.b);
        }
    }
    w
}

/// Reconstruct t_i ∈ F_q^n from t̂_i ∈ F_q^{n·δ} using gadget recomposition.
fn recompose_t_hat_block(params: &GreyhoundParams, t_hat_i: &[Fr]) -> Vec<Fr> {
    let mut t_i = vec![Fr::zero(); params.n];
    for j in 0..params.n {
        let start = j * params.delta;
        let end = start + params.delta;
        if end <= t_hat_i.len() {
            t_i[j] = recompose_scalar(&t_hat_i[start..end], params.b);
        }
    }
    t_i
}

/// Derive Fiat-Shamir challenge from protocol transcript.
/// Produces short challenge values in {-1, 0, 1} to avoid overflow
/// in the linear combination z = Σ c_i · s_i.
///
/// M5: Binds `session_id` and `prover_id` into the challenge hash to prevent
/// cross-session and cross-prover challenge replay attacks.
pub fn derive_challenge(
    params: &GreyhoundParams,
    commitment_u: &[Fr],
    v: &[Fr],
    x: &Fr,
    y: &Fr,
    session_id: &str,
    prover_id: u64,
) -> Vec<Fr> {
    let mut hasher = Keccak256::new();
    hasher.update(pvthfhe_domain_tags::Tag::GreyhoundChallenge.as_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(&prover_id.to_be_bytes());
    hasher.update(&(params.n as u64).to_be_bytes());
    hasher.update(&(params.m as u64).to_be_bytes());
    hasher.update(&(params.r as u64).to_be_bytes());
    hasher.update(&params.b0.to_be_bytes());
    hasher.update(&params.b.to_be_bytes());
    hasher.update(&(params.delta0 as u64).to_be_bytes());
    hasher.update(&(params.delta as u64).to_be_bytes());

    for row in &params.a_matrix {
        for entry in row {
            hasher.update(&fr_to_bytes(entry));
        }
    }

    for row in &params.b_matrix {
        for entry in row {
            hasher.update(&fr_to_bytes(entry));
        }
    }

    for row in &params.d_matrix {
        for entry in row {
            hasher.update(&fr_to_bytes(entry));
        }
    }

    for ui in commitment_u {
        hasher.update(&fr_to_bytes(ui));
    }

    for vi in v {
        hasher.update(&fr_to_bytes(vi));
    }
    hasher.update(&fr_to_bytes(x));
    hasher.update(&fr_to_bytes(y));

    // Derive ternary challenges: rejection-sampled uniform {-1, 0, 1}
    let digest: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(digest);
    let mut challenge = Vec::with_capacity(params.r);
    for _ in 0..params.r {
        let val = loop {
            let byte = (rng.next_u32() as u8);
            if let Some(ch) = uniform_ternary(byte) {
                break match ch {
                    -1 => -Fr::one(),
                    0 => Fr::zero(),
                    _ => Fr::one(),
                };
            }
        };
        challenge.push(val);
    }
    challenge
}

/// Rejection-sampled uniform ternary from a single byte.
///
/// Bytes 0..=251 are split into three equal buckets of 84 each.
/// Bytes ≥ 252 are rejected (returns None); the caller must retry.
pub(crate) fn uniform_ternary(byte: u8) -> Option<i64> {
    if byte >= 252 {
        return None;
    }
    Some(match byte / 84 {
        0 => -1,
        1 => 0,
        _ => 1,
    })
}

/// Convert Fr to bytes for hashing.
fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    let len = le.len().min(32);
    bytes[..len].copy_from_slice(&le[..len]);
    bytes
}

// ── Error Type ─────────────────────────────────────────────────────────

/// Errors for Greyhound PCS operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GreyhoundError {
    /// Input parameters are out of valid range.
    InvalidInput(String),
    /// Verification failed.
    VerificationFailed,
}

impl fmt::Display for GreyhoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "Greyhound: invalid input: {msg}"),
            Self::VerificationFailed => write!(f, "Greyhound: verification failed"),
        }
    }
}

impl std::error::Error for GreyhoundError {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    /// Test full commit→open→verify roundtrip with test_small parameters.
    #[test]
    fn test_greyhound_roundtrip_small() {
        let seed = [0x42u8; 32];
        let ps = GreyhoundParamSet::test_small();
        let params = GreyhoundPCS::setup(&seed, &ps);

        // Create a random polynomial of degree < N = m*r
        let n_poly = params.m * params.r;
        let mut rng = ChaCha20Rng::from_seed([0x13u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();

        // Commit
        let (commitment, witness) = GreyhoundPCS::commit(&params, &poly).unwrap();

        // Open at a random point
        let eval_pt = Fr::rand(&mut rng);
        let proof = GreyhoundPCS::open(&params, &poly, &eval_pt, &witness, "", 0).unwrap();

        // Verify
        let expected_y = evaluate_polynomial(&poly, &eval_pt);
        assert_eq!(proof.y, expected_y, "claimed y should match evaluation");

        let valid =
            GreyhoundPCS::verify(&params, &commitment, &eval_pt, &expected_y, &proof, "", 0)
                .expect("verify should not error");
        assert!(valid, "verification should pass for valid proof");

        // Verify with wrong value should fail
        let wrong_y = expected_y + Fr::one();
        let invalid = GreyhoundPCS::verify(&params, &commitment, &eval_pt, &wrong_y, &proof, "", 0)
            .expect("verify should not error");
        assert!(!invalid, "verification should fail for wrong value");
    }

    /// Test the convenience commit_and_prove method.
    #[test]
    fn test_greyhound_commit_and_prove() {
        let seed = [0x99u8; 32];
        let ps = GreyhoundParamSet::test_small();
        let params = GreyhoundPCS::setup(&seed, &ps);

        let n_poly = params.m * params.r;
        let mut rng = ChaCha20Rng::from_seed([0x37u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();
        let eval_pt = Fr::rand(&mut rng);

        let (commitment, proof) =
            GreyhoundPCS::commit_and_prove(&params, &poly, &eval_pt, "", 0).unwrap();

        let expected_y = evaluate_polynomial(&poly, &eval_pt);
        let valid =
            GreyhoundPCS::verify(&params, &commitment, &eval_pt, &expected_y, &proof, "", 0)
                .expect("verify should not error");
        assert!(valid, "commit-and-prove should produce valid proof");
    }

    /// Test that different seeds produce different (incompatible) parameters.
    #[test]
    fn test_different_seeds_incompatible() {
        let ps = GreyhoundParamSet::test_small();
        let params1 = GreyhoundPCS::setup(&[0x01u8; 32], &ps);
        let params2 = GreyhoundPCS::setup(&[0x02u8; 32], &ps);

        let n_poly = params1.m * params1.r;
        let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();
        let eval_pt = Fr::rand(&mut rng);

        let (commitment1, witness1) = GreyhoundPCS::commit(&params1, &poly).unwrap();
        let proof1 = GreyhoundPCS::open(&params1, &poly, &eval_pt, &witness1, "", 0).unwrap();

        // Verification with params1 should pass
        let expected_y = evaluate_polynomial(&poly, &eval_pt);
        let valid = GreyhoundPCS::verify(
            &params1,
            &commitment1,
            &eval_pt,
            &expected_y,
            &proof1,
            "",
            0,
        )
        .expect("verify should not error");
        assert!(valid);

        // Verification with params2 should fail (different matrices)
        let invalid = GreyhoundPCS::verify(
            &params2,
            &commitment1,
            &eval_pt,
            &expected_y,
            &proof1,
            "",
            0,
        )
        .expect("verify should not error");
        assert!(!invalid, "verification should fail with different params");
    }

    #[test]
    fn test_challenge_is_bound_to_commitment() {
        let ps = GreyhoundParamSet::test_small();
        let params = GreyhoundPCS::setup(&[0x21u8; 32], &ps);
        let n_poly = params.m * params.r;
        let mut rng = ChaCha20Rng::from_seed([0x44u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();
        let eval_pt = Fr::rand(&mut rng);
        let (commitment, witness) = GreyhoundPCS::commit(&params, &poly).unwrap();
        let proof = GreyhoundPCS::open(&params, &poly, &eval_pt, &witness, "", 0).unwrap();
        let expected_y = evaluate_polynomial(&poly, &eval_pt);

        let mut tampered_commitment = commitment.clone();
        tampered_commitment.u[0] += Fr::one();
        let invalid = GreyhoundPCS::verify(
            &params,
            &tampered_commitment,
            &eval_pt,
            &expected_y,
            &proof,
            "",
            0,
        )
        .expect("verify should not error");
        assert!(!invalid, "transcript challenge must bind the commitment");
    }

    #[test]
    fn test_rejects_malformed_opening_lengths() {
        let ps = GreyhoundParamSet::test_small();
        let params = GreyhoundPCS::setup(&[0x31u8; 32], &ps);
        let n_poly = params.m * params.r;
        let mut rng = ChaCha20Rng::from_seed([0x45u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();
        let eval_pt = Fr::rand(&mut rng);
        let (commitment, witness) = GreyhoundPCS::commit(&params, &poly).unwrap();
        let mut proof = GreyhoundPCS::open(&params, &poly, &eval_pt, &witness, "", 0).unwrap();
        proof.c.pop();
        let expected_y = evaluate_polynomial(&poly, &eval_pt);
        let invalid =
            GreyhoundPCS::verify(&params, &commitment, &eval_pt, &expected_y, &proof, "", 0)
                .expect("verify should not error");
        assert!(!invalid, "malformed proof lengths must be rejected");
    }

    /// Test Gadget decomposition roundtrip.
    #[test]
    fn test_gadget_decompose_recompose() {
        let base = 2u64;
        let delta = gadget_dimension(MODULUS_BITS, base);
        let mut rng = ChaCha20Rng::from_seed([0xabu8; 32]);
        let value = Fr::rand(&mut rng);

        let digits = decompose_scalar(&value, base, delta);
        let recomposed = recompose_scalar(&digits, base);

        assert_eq!(
            value, recomposed,
            "gadget decompose/recompose should roundtrip"
        );
    }

    /// Test medium parameters.
    #[test]
    fn test_greyhound_roundtrip_medium() {
        let seed = [0x88u8; 32];
        let ps = GreyhoundParamSet::test_medium();
        let params = GreyhoundPCS::setup(&seed, &ps);

        let n_poly = params.m * params.r;
        let mut rng = ChaCha20Rng::from_seed([0x22u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();

        let eval_pt = Fr::rand(&mut rng);
        let (commitment, proof) =
            GreyhoundPCS::commit_and_prove(&params, &poly, &eval_pt, "", 0).unwrap();

        let expected_y = evaluate_polynomial(&poly, &eval_pt);
        let valid =
            GreyhoundPCS::verify(&params, &commitment, &eval_pt, &expected_y, &proof, "", 0)
                .expect("verify should not error");
        assert!(valid, "medium params roundtrip should pass");
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn debug_verify_checks() {
        let seed = [0x42u8; 32];
        let ps = GreyhoundParamSet::test_small();
        let params = GreyhoundPCS::setup(&seed, &ps);

        let n_poly = params.m * params.r;
        let mut rng = ChaCha20Rng::from_seed([0x13u8; 32]);
        let poly: Vec<Fr> = (0..n_poly).map(|_| Fr::rand(&mut rng)).collect();
        let eval_pt = Fr::rand(&mut rng);

        let (commitment, witness) = GreyhoundPCS::commit(&params, &poly).unwrap();
        let proof = GreyhoundPCS::open(&params, &poly, &eval_pt, &witness, "", 0).unwrap();

        let expected_y = evaluate_polynomial(&poly, &eval_pt);
        println!("y matches: {}", proof.y == expected_y);

        // Check 1: D·ŵ == v
        let dv = matrix_vector_mul(&params.d_matrix, &proof.w_hat);
        println!(
            "check1 (D·ŵ=v): {:?} == {:?} -> {}",
            dv,
            proof.v,
            dv == proof.v
        );

        // Check 2: B·t̂ == u
        let bu = matrix_vector_mul(&params.b_matrix, &proof.t_hat);
        println!(
            "check2 (B·t̂=u): {:?} == {:?} -> {}",
            bu,
            commitment.u,
            bu == commitment.u
        );

        // Check 3: b^T·w == y
        let a = build_evaluation_vector_a(&params, &eval_pt);
        let b = build_evaluation_vector_b(&params, &eval_pt);
        let w = recompose_w_hat(&params, &proof.w_hat);
        let mut bw = Fr::zero();
        for i in 0..params.r {
            if i < b.len() && i < w.len() {
                bw += b[i] * w[i];
            }
        }
        println!(
            "check3 (b^T·w=y): {:?} == {:?} -> {}",
            bw,
            expected_y,
            bw == expected_y
        );

        // Check 4: c^T·w == a^T·z
        let mut cw = Fr::zero();
        for i in 0..params.r {
            if i < proof.c.len() && i < w.len() {
                cw += proof.c[i] * w[i];
            }
        }
        let mut az = Fr::zero();
        for j in 0..a.len() {
            if j < proof.z.len() {
                az += a[j] * proof.z[j];
            }
        }
        println!("check4 (c^T·w=a^T·z): {:?} == {:?} -> {}", cw, az, cw == az);

        // Check 5: (c^T⊗G)·t̂ == A·z
        let block_size = params.n * params.delta;
        let mut lhs = vec![Fr::zero(); params.n];
        for i in 0..params.r {
            if i < proof.c.len() {
                let ci = proof.c[i];
                let start = i * block_size;
                let end = start + block_size;
                if end <= proof.t_hat.len() {
                    let t_hat_i = &proof.t_hat[start..end];
                    let t_i = recompose_t_hat_block(&params, t_hat_i);
                    for j in 0..params.n {
                        lhs[j] += ci * t_i[j];
                    }
                }
            }
        }
        let rhs = matrix_vector_mul(&params.a_matrix, &proof.z);
        println!(
            "check5 (Σc_i·t_i = A·z): {:?} == {:?} -> {}",
            lhs,
            rhs,
            lhs == rhs
        );

        // Check: t_i == A·s_i for each i
        for i in 0..params.r {
            let ti_computed = matrix_vector_mul(&params.a_matrix, &witness.s[i]);
            println!(
                "t{} check: computed={:?}, stored={:?}, match={}",
                i,
                ti_computed,
                witness.t[i],
                ti_computed == witness.t[i]
            );
        }
    }
}
