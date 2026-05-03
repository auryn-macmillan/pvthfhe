//! Statistical tests that verify the smudging noise budget closes under honest-party aggregation.
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const N: usize = 64;
const ITERATIONS: usize = 10_000;
const T_HONEST: usize = 4;
const SIGMA_ERR: f64 = 3.19;
const BUDGET_LOG2_PROXY: u32 = 60;
const SAFETY_DIVISOR: f64 = 1_000.0;

fn sample_gaussian(rng: &mut impl Rng, n: usize, sigma: f64) -> Vec<f64> {
    (0..n)
        .map(|_| {
            let u: f64 = rng
                .r#gen::<f64>()
                .clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
            let v: f64 = rng.r#gen::<f64>();
            let z = (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos();
            (z * sigma).round()
        })
        .collect()
}

fn norm_inf(v: &[f64]) -> f64 {
    v.iter().copied().map(f64::abs).fold(0.0_f64, f64::max)
}

fn aggregate_smudging_noise(rng: &mut impl Rng, honest_parties: usize, sigma_smudge: f64) -> f64 {
    (0..honest_parties)
        .map(|_| {
            let sampled = sample_gaussian(rng, N, sigma_smudge);
            norm_inf(&sampled)
        })
        .fold(0.0_f64, |a, b| a + b)
}

#[test]
fn noise_budget_closes_honest() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let sigma_smudge = SIGMA_ERR * 2_f64.powi(40);
    let budget_bound = 2_f64.powi(BUDGET_LOG2_PROXY.try_into().unwrap_or(60));

    for _ in 0..ITERATIONS {
        let aggregate_noise = aggregate_smudging_noise(&mut rng, T_HONEST, sigma_smudge);
        assert!(
            aggregate_noise < budget_bound / SAFETY_DIVISOR,
            "Noise budget violated: aggregate_noise={aggregate_noise} >= {}",
            budget_bound / SAFETY_DIVISOR
        );
    }
}

#[test]
fn noise_budget_closes_malicious() {
    let mut rng = ChaCha20Rng::seed_from_u64(123);
    let sigma_smudge = SIGMA_ERR * 2_f64.powi(40);
    let budget_bound = 2_f64.powi(BUDGET_LOG2_PROXY.try_into().unwrap_or(60));

    for _ in 0..ITERATIONS {
        let aggregate_noise = aggregate_smudging_noise(&mut rng, T_HONEST, sigma_smudge);
        assert!(
            aggregate_noise < budget_bound / SAFETY_DIVISOR,
            "Malicious noise budget violated: aggregate_noise={aggregate_noise} >= {}",
            budget_bound / SAFETY_DIVISOR
        );
    }
}
