//! Bounded sampling helpers and element-wise scalar operations for the sigma
//! protocol, plus the Johnson-Lindenstrauss projection helpers (T4).

use fhe_math::rq::Context;
use rand_core::RngCore;
use std::sync::Arc;

use crate::NizkError;

use super::rlwe_n;

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

    // allow-seeded-rng: deterministic Achlioptas JL expansion of the caller-supplied seed; prover and verifier/circuit must derive the identical matrix
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

    // allow-seeded-rng: deterministic Achlioptas JL expansion of the caller-supplied seed; prover and verifier/circuit must derive the identical matrix
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
    // allow-seeded-rng: deterministic Achlioptas JL expansion of the caller-supplied seed; prover and verifier/circuit must derive the identical matrix
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

/// Multiply an i64 coefficient by a ternary scalar ch ∈ {-1, 0, 1}.
/// Returns ch * val.
#[inline]
pub(super) fn scalar_mul_i64(ch: i64, val: i64) -> i64 {
    match ch {
        1 => val,
        -1 => -val,
        _ => 0,
    }
}

/// Compute `a + ch * b` element-wise over RNS power-basis, where
/// ch ∈ {-1, 0, 1} is a ternary scalar and b is an RNS polynomial.
pub(super) fn rns_add_scalar_mul(
    a: &[u64],
    ch: i64,
    b: &[u64],
    ctx: &Arc<Context>,
) -> Result<Vec<u64>, NizkError> {
    let n = rlwe_n();
    let expected = n * ctx.q.len();
    if a.len() != expected || b.len() != expected {
        return Err(NizkError::InvalidInput {
            reason: "rns_add_scalar_mul: length mismatch",
            party_id: None,
        });
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
        _ => {
            return Err(NizkError::InvalidInput {
                reason: "ch must be -1, 0, or 1",
                party_id: None,
            })
        }
    }
    Ok(out)
}

/// Sample `n` coefficients uniformly from [-bound, bound] using rejection sampling.
pub fn sample_bounded(rng: &mut dyn RngCore, n: usize, bound: i64) -> Result<Vec<i64>, NizkError> {
    let range = u64::try_from(2 * bound + 1).map_err(|_| NizkError::InvalidInput {
        reason: "bound too large for u64",
        party_id: None,
    })?;
    let max_multiple = (u64::MAX / range) * range;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let r = u64::from_le_bytes(bytes);
        if r < max_multiple {
            let v = i64::try_from(r % range).map_err(|_| NizkError::InvalidInput {
                reason: "sample out of i64 range",
                party_id: None,
            })?;
            out.push(v - bound);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_mul_i64_smoke() {
        assert_eq!(scalar_mul_i64(0, 42), 0);
        assert_eq!(scalar_mul_i64(1, 42), 42);
        assert_eq!(scalar_mul_i64(-1, 42), -42);
        assert_eq!(scalar_mul_i64(0, -5), 0);
        assert_eq!(scalar_mul_i64(1, -5), -5);
        assert_eq!(scalar_mul_i64(-1, -5), 5);
    }
}
