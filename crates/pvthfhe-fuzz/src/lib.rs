//! Fuzzing harnesses for PVTHFHE cryptographic primitives.
//!
//! Provides fuzzers for:
//! - Sigma protocol (honest prover roundtrip + tamper rejection)
//! - BFV sigma protocol
//! - PVSS share NIZK
//! - Nova inputs

use arbitrary::{Arbitrary, Unstructured};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::Digest;
use std::fmt;

/// The number of fuzzing iterations per test by default.
pub const FUZZ_ITERATIONS: usize = 10_000;

/// Generate a seeded RNG from arbitrary data bytes.
pub fn rng_from_bytes(bytes: &[u8]) -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"pvthfhe-fuzz-seed-v1");
    hasher.update(bytes);
    let hash = hasher.finalize();
    seed.copy_from_slice(&hash);
    ChaCha20Rng::from_seed(seed)
}

/// Generate i64 coefficients uniformly in [-bound, bound].
pub fn sample_bounded_i64(rng: &mut dyn RngCore, n: usize, bound: i64) -> Vec<i64> {
    let range = (2 * bound + 1) as u64;
    let max_multiple = (u64::MAX / range) * range;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let v = rng.next_u64();
        if v < max_multiple {
            out.push((v % range) as i64 - bound);
        }
    }
    out
}

/// Generate ternary coefficients in {-1, 0, 1}.
pub fn sample_ternary(rng: &mut dyn RngCore, n: usize) -> Vec<i64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let v = rng.next_u64() % 3;
        out.push(match v {
            0 => -1,
            1 => 0,
            _ => 1,
        });
    }
    out
}

/// Generate random bytes with length derived from rng.
pub fn arbitrary_bytes(rng: &mut dyn RngCore, max_len: usize) -> Vec<u8> {
    let len = (rng.next_u64() as usize) % (max_len + 1);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// Fuzz status for progress tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzStatus {
    Pass,
    Fail(String),
}

impl fmt::Display for FuzzStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzStatus::Pass => write!(f, "PASS"),
            FuzzStatus::Fail(msg) => write!(f, "FAIL: {msg}"),
        }
    }
}
