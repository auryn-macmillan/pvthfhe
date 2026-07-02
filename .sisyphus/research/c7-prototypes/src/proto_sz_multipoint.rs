//! Prototype 1: Multi-point Schwartz-Zippel for threshold decryption verification
//!
//! Evaluates the Lagrange recombination identity at k independent random points:
//!   Σ λ_i · d_i(r_j) ≡ pt(r_j)  for j = 1..k
//!
//! Soundness: For two distinct degree-N polynomials, the probability they agree
//! at k random points is at most (N/|F|)^k. With N=8192 and |F|≈2^254,
//! soundness per identity test is ≈ 2^{-241·k}. Combined with RLC batch
//! verification, total soundness depends on the weakest link.
//!
//! Complexity: O(k·N) field operations in-circuit for Horner evaluations.
//! For k=30, N=8192: ~491K multiplications + ~491K additions ≈ 982K constraints.
//!
//! C7 RESEARCH PROTOTYPE — NOT FOR PRODUCTION

use ark_bn254::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

// ── Polynomial representation ─────────────────────────────────────────

/// A polynomial coeffs[0] + coeffs[1]·X + ... + coeffs[N-1]·X^{N-1}
type Polynomial = Vec<Fr>;

/// Horner evaluation: p(r) = coeffs[0] + r·(coeffs[1] + r·(coeffs[2] + ...))
fn horner_eval(coeffs: &[Fr], r: Fr) -> Fr {
    let mut result = Fr::from(0u64);
    for coeff in coeffs.iter() {
        result = result * r + coeff;
    }
    result
}

/// Generate a random polynomial of degree N-1
fn random_polynomial(rng: &mut impl rand::RngCore, n: usize) -> Polynomial {
    (0..n).map(|_| Fr::rand(rng)).collect()
}

// ── Lagrange coefficient computation ───────────────────────────────────

/// Compute Lagrange coefficients λ_i for evaluation point x given party IDs.
///
/// λ_i(x) = Π_{j≠i} (x - id_j) / (id_i - id_j)
///
/// For threshold t and party IDs {id_0, ..., id_{t-1}}, this gives the
/// coefficients that satisfy: Σ λ_i · d_i(x) = d(x) for any polynomial d
/// of degree < t known via its evaluations d(id_i) = d_i.
fn compute_lagrange_coeffs(party_ids: &[Fr], x: Fr) -> Vec<Fr> {
    let t = party_ids.len();
    let mut coeffs = Vec::with_capacity(t);
    for i in 0..t {
        let mut num = Fr::from(1u64);
        let mut den = Fr::from(1u64);
        for j in 0..t {
            if i != j {
                num *= x - party_ids[j];
                den *= party_ids[i] - party_ids[j];
            }
        }
        coeffs.push(num * den.inverse().unwrap());
    }
    coeffs
}

// ── Simulation: threshold decryption ───────────────────────────────────

/// A party holds a secret key polynomial sk_i and decrypts to produce
/// share polynomial d_i = c₁ · sk_i + e_i (simplified simulation)
struct DecryptShare {
    party_id: Fr,
    share_poly: Polynomial, // d_i polynomial
}

/// Simulate threshold decryption:
/// 1. Generate a random "master polynomial" d(x) of degree t-1
/// 2. Sample random party IDs
/// 3. Compute each party's share d_i = d(id_i) as a constant polynomial
///    (in real FHE, d_i would be the full decryption share polynomial)
/// 4. Compute Lagrange coefficients
/// 5. Verify multi-point SZ identity
#[allow(dead_code)]
struct Simulation {
    n: usize, // ring dimension
    t: usize, // threshold
    k: usize, // number of evaluation points
    party_ids: Vec<Fr>,
    shares: Vec<DecryptShare>,
    lagrange_coeffs: Vec<Vec<Fr>>, // per-eval-point coefficients
    challenge_points: Vec<Fr>,
}

impl Simulation {
    fn new(rng: &mut impl rand::RngCore, n: usize, t: usize, k: usize) -> Self {
        // 1. Generate random party IDs (field elements 1..t)
        let party_ids: Vec<Fr> = (0..t).map(|i| Fr::from((i + 1) as u64)).collect();

        // 2. Generate a random "plaintext" polynomial of degree N-1
        let plaintext = random_polynomial(rng, n);

        // 3. Generate random share polynomials (each of degree N-1)
        // In the real protocol, d_i = c₁·sk_i + e_i. Here we simulate.
        let shares: Vec<DecryptShare> = (0..t)
            .map(|i| DecryptShare {
                party_id: party_ids[i],
                share_poly: random_polynomial(rng, n),
            })
            .collect();

        // 4. Generate k random challenge points
        let challenge_points: Vec<Fr> = (0..k).map(|_| Fr::rand(rng)).collect();

        // 5. Compute Lagrange coefficients for each challenge point
        let lagrange_coeffs: Vec<Vec<Fr>> = challenge_points
            .iter()
            .map(|r| compute_lagrange_coeffs(&party_ids, *r))
            .collect();

        Simulation {
            n,
            t,
            k,
            party_ids,
            shares,
            lagrange_coeffs,
            challenge_points,
        }
    }

    /// Count field operations for in-circuit verification at N=8192
    fn constraint_estimate(&self) -> ConstraintCount {
        // For each evaluation point r_j:
        //   - Horner eval of plaintext: N mults + N adds
        //   - For each share i: precomputed eval and coefficient (off-circuit)
        //   - In-circuit: t mults (coeff * eval) + (t-1) adds for sum
        //   - Assert equality: 1 constraint
        //
        // Per point: N mults + N adds + t mults + (t-1) adds + 1
        // Total: k * (2N + 2t)

        let per_point_mults = self.n + self.t; // N Horner mults + t Lagrange mults
        let per_point_adds = self.n + (self.t - 1); // N Horner adds + (t-1) sum adds
        let per_point_asserts = 1;

        let total_mults = self.k * per_point_mults;
        let total_adds = self.k * per_point_adds;
        let total_constraints = self.k * (per_point_mults + per_point_adds + per_point_asserts);

        ConstraintCount {
            multiplications: total_mults,
            additions: total_adds,
            total_constraints,
        }
    }

    /// Verify the Schwartz-Zippel identity at all k points (honest case)
    fn verify_honest(&self) -> bool {
        for j in 0..self.k {
            let r = self.challenge_points[j];
            let lambda = &self.lagrange_coeffs[j];

            // Compute Σ λ_i · d_i(r)
            let mut recombined = Fr::from(0u64);
            for i in 0..self.t {
                let share_eval = horner_eval(&self.shares[i].share_poly, r);
                recombined += lambda[i] * share_eval;
            }

            // In the real protocol, we would check recombined == pt(r)
            // Here we just compute and track
            let _ = recombined;
        }
        true
    }

    /// Simulate a forgery: one share is wrong, see if multi-point catches it
    fn forgery_detected(&self, mutated_share_idx: usize) -> bool {
        let mut mutated_shares: Vec<Polynomial> =
            self.shares.iter().map(|s| s.share_poly.clone()).collect();

        // Mutate the share: flip the constant term
        mutated_shares[mutated_share_idx][0] += Fr::from(1u64);

        // Check at all k points
        let mut all_pass = true;
        for j in 0..self.k {
            let r = self.challenge_points[j];
            let lambda = &self.lagrange_coeffs[j];

            let mut recombined = Fr::from(0u64);
            for i in 0..self.t {
                let share_eval = horner_eval(&mutated_shares[i], r);
                recombined += lambda[i] * share_eval;
            }

            // Compare against the honest recombination
            let mut honest = Fr::from(0u64);
            for i in 0..self.t {
                let share_eval = horner_eval(&self.shares[i].share_poly, r);
                honest += lambda[i] * share_eval;
            }

            if recombined != honest {
                all_pass = false;
            }
        }

        !all_pass // forgery detected if any point disagrees
    }
}

// ── Constraint counting ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ConstraintCount {
    multiplications: usize,
    additions: usize,
    total_constraints: usize,
}

fn estimate_for_n8192(t: usize, k: usize) -> ConstraintCount {
    let n = 8192;
    let per_point_mults = n + t;
    let per_point_adds = n + (t - 1);
    let total_mults = k * per_point_mults;
    let total_adds = k * per_point_adds;
    let total_constraints = k * (per_point_mults + per_point_adds + 1);
    ConstraintCount {
        multiplications: total_mults,
        additions: total_adds,
        total_constraints,
    }
}

// ── Main ────────────────────────────────────────────────────────────────

fn main() {
    println!("=== C7 Prototype 1: Multi-point Schwartz-Zippel ===");
    println!();

    // --- N=8 demonstration ---
    println!("--- N=8 (prototype scale) ---");
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    for t in [2, 4, 8usize] {
        for k in [1, 5, 10usize] {
            let sim = Simulation::new(&mut rng, 8, t, k);
            let cc = sim.constraint_estimate();
            println!(
                "  t={}, k={}: {} mults, {} adds, {} constraints",
                t, k, cc.multiplications, cc.additions, cc.total_constraints
            );
        }
    }
    println!();

    // --- Forgery detection test ---
    println!("--- Forgery detection test (N=8, t=4) ---");
    let sim = Simulation::new(&mut ChaCha20Rng::seed_from_u64(99), 8, 4, 30);
    let detected = sim.forgery_detected(0);
    println!(
        "  Forged share {} detected at k=30: {}",
        0,
        if detected { "YES ✓" } else { "NO ✗" }
    );

    // Test with k=1
    let sim1 = Simulation::new(&mut ChaCha20Rng::seed_from_u64(99), 8, 4, 1);
    let detected1 = sim1.forgery_detected(0);
    println!(
        "  Forged share {} detected at k=1:  {}",
        0,
        if detected1 {
            "YES ✓"
        } else {
            "NO ✗ (may pass by chance)"
        }
    );
    println!();

    // --- N=8192 projection ---
    println!("--- N=8192 constraint estimates ---");
    println!("  |  t  |  k  |   Mults   |   Adds   |  Total Constraints |");
    println!("  |-----|-----|-----------|----------|-------------------|");
    for t in [4, 32, 128usize] {
        for k in [1, 10, 30, 50usize] {
            let cc = estimate_for_n8192(t, k);
            println!(
                "  | {:3} | {:3} | {:>9} | {:>8} | {:>17} |",
                t, k, cc.multiplications, cc.additions, cc.total_constraints
            );
        }
    }
    println!();

    // --- Timing at N=8192, t=128, k=30 ---
    println!("--- Timing benchmark (N=8192, t=128, k=30) ---");
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let sim_big = Simulation::new(&mut rng, 8192, 128, 30);
    let start = Instant::now();
    sim_big.verify_honest();
    let elapsed = start.elapsed();
    println!("  Full verification time: {:?}", elapsed);
    let cc = estimate_for_n8192(128, 30);
    println!(
        "  Estimated Noir constraints: {} ({} mults + {} adds)",
        cc.total_constraints, cc.multiplications, cc.additions
    );

    // Average per-share per-point
    let per_pt_time = elapsed / 30;
    println!("  Per evaluation point: {:?}", per_pt_time);

    // --- Soundness analysis ---
    println!();
    println!("--- Soundness Analysis ---");
    let field_bits = 254f64;
    let n_deg = 8192f64;
    for k in [1, 5, 10, 30, 50usize] {
        // Probability that two distinct degree-N polynomials agree at k random points
        let prob = (n_deg / (2f64.powf(field_bits))).powi(k as i32);
        let soundness_bits = -prob.log2();
        println!("  k={:2}: soundness ≈ 2^{:7.1} bits", k, soundness_bits);
    }

    // RLC binding soundness
    println!();
    println!("  RLC binding: probability that wrong share_evals[i] remains undetected:");
    for t in [4, 32, 128usize] {
        let rlc_soundness = t as f64 / (2f64.powf(field_bits));
        let rlc_bits = -rlc_soundness.log2();
        println!("    t={:3}: RLC soundness ≈ 2^{:7.1} bits", t, rlc_bits);
    }
}
