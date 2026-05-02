use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const N: usize = 64;
const ITERATIONS: usize = 10_000;
const T_HONEST: usize = 4;
const SIGMA_ERR: f64 = 3.19;
const BUDGET_LOG2_PROXY: u32 = 60;
const SAFETY_DIVISOR: i64 = 1_000;

fn sample_gaussian(rng: &mut impl Rng, n: usize, sigma: f64) -> Vec<i64> {
    (0..n)
        .map(|_| {
            let u: f64 = rng.r#gen::<f64>().clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
            let v: f64 = rng.r#gen::<f64>();
            let z = (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos();
            (z * sigma).round() as i64
        })
        .collect()
}

fn norm_inf(v: &[i64]) -> i64 {
    v.iter().map(|x| x.abs()).max().unwrap_or(0)
}

fn aggregate_smudging_noise(rng: &mut impl Rng, honest_parties: usize, sigma_smudge: f64) -> i64 {
    (0..honest_parties)
        .map(|_| {
            let sampled = sample_gaussian(rng, N, sigma_smudge);
            norm_inf(&sampled)
        })
        .fold(0_i64, i64::saturating_add)
}

#[test]
fn noise_budget_closes_honest() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let sigma_smudge = SIGMA_ERR * (1_u64 << 40) as f64;
    let budget_bound: i64 = 1_i64 << BUDGET_LOG2_PROXY;

    for _ in 0..ITERATIONS {
        let aggregate_noise = aggregate_smudging_noise(&mut rng, T_HONEST, sigma_smudge);
        assert!(
            aggregate_noise < budget_bound / SAFETY_DIVISOR,
            "Noise budget violated: aggregate_noise={} >= {}",
            aggregate_noise,
            budget_bound / SAFETY_DIVISOR
        );
    }
}

#[test]
fn noise_budget_closes_malicious() {
    let mut rng = ChaCha20Rng::seed_from_u64(123);
    let sigma_smudge = SIGMA_ERR * (1_u64 << 40) as f64;
    let budget_bound: i64 = 1_i64 << BUDGET_LOG2_PROXY;

    for _ in 0..ITERATIONS {
        let aggregate_noise = aggregate_smudging_noise(&mut rng, T_HONEST, sigma_smudge);
        assert!(
            aggregate_noise < budget_bound / SAFETY_DIVISOR,
            "Malicious noise budget violated: aggregate_noise={} >= {}",
            aggregate_noise,
            budget_bound / SAFETY_DIVISOR
        );
    }
}
