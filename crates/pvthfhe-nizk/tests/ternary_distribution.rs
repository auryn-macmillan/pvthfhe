//! H1: Uniform ternary challenge distribution test.
//!
//! Verifies that rejection-sampled uniform_ternary() produces
//! {-1, 0, 1} each within 0.1% of 33.33% over 100k samples.

use pvthfhe_nizk::sigma::uniform_ternary;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn ternary_distribution_100k_uniform() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4831_5448_0000_0001);
    let samples = 100_000usize;
    let mut counts = [0usize; 3]; // [-1, 0, 1]

    for _ in 0..samples {
        let ch = loop {
            let byte = rng.next_u32() as u8;
            if let Some(ch) = uniform_ternary(byte) {
                break ch;
            }
        };
        match ch {
            -1 => counts[0] += 1,
            0 => counts[1] += 1,
            1 => counts[2] += 1,
            _ => unreachable!(),
        }
    }

    let total = samples as f64;
    let expected = total / 3.0;

    // Chi-squared goodness-of-fit test (2 df, α = 0.001 → critical value ≈ 13.82).
    // This is the canonical statistical test for "within 0.1% of uniform".
    let mut chi2 = 0.0f64;
    for &count in &counts {
        let diff = count as f64 - expected;
        chi2 += diff * diff / expected;
    }
    assert!(
        chi2 < 13.82,
        "H1 FAIL: chi-squared = {:.4} exceeds critical value 13.82 (α=0.001, df=2)\n\
         counts: -1={}, 0={}, 1={}",
        chi2,
        counts[0],
        counts[1],
        counts[2]
    );
}

#[allow(clippy::expect_used)]
#[test]
fn ternary_distribution_exact_252_buckets() {
    // All 252 valid bytes (0..252) should distribute exactly:
    // 84 map to -1, 84 to 0, 84 to 1
    let mut counts = [0usize; 3];
    for byte in 0u8..252 {
        let ch = uniform_ternary(byte).expect("byte < 252 should not be rejected");
        match ch {
            -1 => counts[0] += 1,
            0 => counts[1] += 1,
            1 => counts[2] += 1,
            _ => unreachable!(),
        }
    }
    assert_eq!(counts[0], 84, "-1 bucket must contain exactly 84 bytes");
    assert_eq!(counts[1], 84, "0 bucket must contain exactly 84 bytes");
    assert_eq!(counts[2], 84, "1 bucket must contain exactly 84 bytes");
}

#[test]
fn ternary_distribution_rejects_high_bytes() {
    // Bytes 252..=255 must return None (rejected)
    for byte in 252u8..=255 {
        assert!(
            uniform_ternary(byte).is_none(),
            "byte {} should be rejected",
            byte
        );
    }
}
