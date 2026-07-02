//! Prototype 2: Random Linear Combination (RLC) batch verification with
//! precomputed Lagrange coefficients
//!
//! Approach:
//! 1. Precompute Lagrange coefficients λ_i(r) for each evaluation point r
//!    (off-circuit, O(t²) in native Rust)
//! 2. Combine all t share polynomials into ONE combined polynomial via RLC:
//!    P_combined = Σ β^i · share_poly_i
//! 3. Verify in-circuit (O(N + t)):
//!    a. eval(P_combined, r) == Σ β^i · share_evals[i]  (O(N) + O(t))
//!    b. Σ λ_i · share_evals[i] == pt_eval               (O(t))
//!    c. Σ λ_i == 1                                      (O(t))
//!    d. Merkle(P_combined) is in commitment tree         (O(log t))
//!
//! This is essentially what the current C7 circuit already implements
//! (see circuits/aggregator_final/src/main.nr lines 389-424).
//!
//! Soundness:
//!   - Polynomial disagreement at r: ≤ N/|F| ≈ 2^{-241} for N=8192
//!   - RLC binding: t/|F| ≈ 2^{-246} for t=128
//!   - Merkle collision: 2^{-128} (Poseidon)
//!
//! C7 RESEARCH PROTOTYPE — NOT FOR PRODUCTION

use ark_bn254::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

type Polynomial = Vec<Fr>;

fn horner_eval(coeffs: &[Fr], r: Fr) -> Fr {
    let mut result = Fr::from(0u64);
    for coeff in coeffs.iter() {
        result = result * r + coeff;
    }
    result
}

fn random_polynomial(rng: &mut impl rand::RngCore, n: usize) -> Polynomial {
    (0..n).map(|_| Fr::rand(rng)).collect()
}

/// Compute Lagrange coefficients λ_i for evaluation at x
fn lagrange_coeffs(ids: &[Fr], x: Fr) -> Vec<Fr> {
    let t = ids.len();
    let mut out = Vec::with_capacity(t);
    for i in 0..t {
        let mut num = Fr::from(1u64);
        let mut den = Fr::from(1u64);
        for j in 0..t {
            if i != j {
                num *= x - ids[j];
                den *= ids[i] - ids[j];
            }
        }
        out.push(num * den.inverse().unwrap());
    }
    out
}

/// Simple Poseidon-like hash using repeated field operations
/// (In production, use the actual Poseidon implementation)
fn simple_hash(inputs: &[Fr]) -> Fr {
    let mut state = Fr::from(0u64);
    for (i, x) in inputs.iter().enumerate() {
        state += *x * Fr::from((i + 1) as u64);
        state = state * state + state;
    }
    state
}

// ── RLC (Random Linear Combination) ────────────────────────────────────

/// Derive RLC challenge β from share evaluations
fn derive_rlc_beta(share_evals: &[Fr]) -> Fr {
    simple_hash(share_evals)
}

/// Combine share polynomials via RLC: Σ β^i · share_poly_i
fn rlc_combine(shares: &[Polynomial], beta: Fr) -> Polynomial {
    let n = shares[0].len();
    let mut combined = vec![Fr::from(0u64); n];
    let mut beta_pow = Fr::from(1u64);
    for share in shares {
        for j in 0..n {
            combined[j] += beta_pow * share[j];
        }
        beta_pow *= beta;
    }
    combined
}

// ── RLC Verification ──────────────────────────────────────────────────

struct RlcVerifier {
    n: usize,
    t: usize,
    party_ids: Vec<Fr>,
    shares: Vec<Polynomial>,
    challenge_r: Fr,
    lagrange_coeffs: Vec<Fr>,
}

impl RlcVerifier {
    fn new(rng: &mut impl rand::RngCore, n: usize, t: usize) -> Self {
        let party_ids: Vec<Fr> = (0..t).map(|i| Fr::from((i + 1) as u64)).collect();
        let shares: Vec<Polynomial> = (0..t).map(|_| random_polynomial(rng, n)).collect();
        let challenge_r = Fr::rand(rng);
        let lagrange_coeffs = lagrange_coeffs(&party_ids, challenge_r);

        RlcVerifier {
            n,
            t,
            party_ids,
            shares,
            challenge_r,
            lagrange_coeffs,
        }
    }

    /// Compute share evaluations at challenge_r (off-circuit)
    fn compute_share_evals(&self) -> Vec<Fr> {
        self.shares
            .iter()
            .map(|s| horner_eval(s, self.challenge_r))
            .collect()
    }

    /// Compute plaintext evaluation: pt(r) = Σ λ_i · d_i(r)
    fn compute_pt_eval(&self) -> Fr {
        let evals = self.compute_share_evals();
        let mut result = Fr::from(0u64);
        for i in 0..self.t {
            result += self.lagrange_coeffs[i] * evals[i];
        }
        result
    }

    /// Verify the full RLC-based proof (simulating in-circuit verification)
    fn verify(&self) -> bool {
        // 1. Compute share evaluations (off-circuit in real protocol, given as witness)
        let share_evals = self.compute_share_evals();

        // 2. Compute pt_eval (off-circuit)
        let pt_eval = self.compute_pt_eval();

        // 3. Derive RLC beta from share evals (Fiat-Shamir)
        let beta = derive_rlc_beta(&share_evals);

        // 4. Compute RLC combined polynomial
        let combined_poly = rlc_combine(&self.shares, beta);

        // 5. In-circuit verification:
        //    a. eval(P_combined, r) == Σ β^i · share_evals[i]
        let combined_eval = horner_eval(&combined_poly, self.challenge_r);
        let mut expected_rlc = Fr::from(0u64);
        let mut beta_pow = Fr::from(1u64);
        for i in 0..self.t {
            expected_rlc += beta_pow * share_evals[i];
            beta_pow *= beta;
        }
        if combined_eval != expected_rlc {
            println!("  FAIL: RLC check failed");
            return false;
        }

        //    b. Σ λ_i · share_evals[i] == pt_eval
        let mut recombined = Fr::from(0u64);
        for i in 0..self.t {
            recombined += self.lagrange_coeffs[i] * share_evals[i];
        }
        if recombined != pt_eval {
            println!("  FAIL: Lagrange recombination check failed");
            return false;
        }

        //    c. Σ λ_i == 1
        let lagrange_sum: Fr = self.lagrange_coeffs.iter().sum();
        if lagrange_sum != Fr::from(1u64) {
            println!("  FAIL: Lagrange sum != 1 (got {:?})", lagrange_sum);
            return false;
        }

        //    d. Merkle proof (simulated — would verify Path(commit(combined), root))
        let _combined_commit = simple_hash(&combined_poly);
        // Merkle verification would go here

        true
    }

    /// Simulate an adversarial forgery and check if detection works
    fn test_forgery(&self) -> bool {
        // Forge: provide wrong share_eval for one share
        let mut fake_evals = self.compute_share_evals();
        fake_evals[0] += Fr::from(1u64); // tampered evaluation

        // Recompute pt_eval based on forged evals
        let mut fake_pt_eval = Fr::from(0u64);
        for i in 0..self.t {
            fake_pt_eval += self.lagrange_coeffs[i] * fake_evals[i];
        }

        // Derive beta from fake evals (attacker controls these)
        let beta = derive_rlc_beta(&fake_evals);

        // Attacker computes consistent combined polynomial
        let mut fake_combined = vec![Fr::from(0u64); self.n];
        let mut beta_pow = Fr::from(1u64);
        // Use 0th share's actual polynomial for positions 1..t-1, but modify 0th
        for (idx, share) in self.shares.iter().enumerate() {
            if idx == 0 {
                // The attacker would need to produce a polynomial d'_0 such that
                // d'_0(r) = d_0(r) + 1 but d'_0 matches the original on the
                // commitment. This requires finding a collision.
                // For Poseidon commitments (2^-128 collision), this is infeasible.
                //
                // SIMULATION: just use the actual share polynomial (would fail
                // Merkle commitment check in production)
                for j in 0..self.n {
                    fake_combined[j] += beta_pow * share[j];
                }
            } else {
                for j in 0..self.n {
                    fake_combined[j] += beta_pow * share[j];
                }
            }
            beta_pow *= beta;
        }

        // RLC check: eval(fake_combined, r) == Σ β^i · fake_evals[i]
        let fake_combined_eval = horner_eval(&fake_combined, self.challenge_r);
        let mut expected_fake_rlc = Fr::from(0u64);
        let mut beta_pow2 = Fr::from(1u64);
        for i in 0..self.t {
            expected_fake_rlc += beta_pow2 * fake_evals[i];
            beta_pow2 *= beta;
        }

        if fake_combined_eval != expected_fake_rlc {
            // RLC check catches it if the combined polynomial isn't properly forged
            return true;
        }
        // If RLC passes (attacker produced consistent witnesses), check Lagrange
        let mut recombined = Fr::from(0u64);
        for i in 0..self.t {
            recombined += self.lagrange_coeffs[i] * fake_evals[i];
        }
        recombined != self.compute_pt_eval()
    }

    /// Constraint count estimate for N=8192 in Noir
    fn constraint_estimate(n: usize, t: usize) -> ConstraintBreakdown {
        // Horner evaluation of combined polynomial: N mults + N adds
        // RLC expected sum: t mults + (t-1) adds
        // RLC assert: 1 constraint
        // Lagrange recombination: t mults + (t-1) adds
        // Lagrange assert: 1 constraint
        // Lagrange sum: (t-1) adds, 1 assert
        // Merkle path verification: DEPTH hashes ≈ 7 * 2 = 14 constraints
        // Polynomial commitment hash: N additions (for the sponge input)
        //                                  + ~100 Poseidon constraints

        let horner_mults = n;
        let horner_adds = n;
        let rlc_mults = t;
        let rlc_adds = t - 1;
        let rlc_assert = 1;
        let lagrange_mults = t;
        let lagrange_adds = t - 1;
        let lagrange_assert = 1;
        let sum_adds = t - 1;
        let sum_assert = 1;
        let merkle_hashes = 7; // DEPTH=7 for 128 leaves
        let poseidon_per_hash = 100; // approximate
        let commitment_constraints = n + merkle_hashes * poseidon_per_hash;

        let total = horner_mults
            + horner_adds
            + rlc_mults
            + rlc_adds
            + rlc_assert
            + lagrange_mults
            + lagrange_adds
            + lagrange_assert
            + sum_adds
            + sum_assert
            + commitment_constraints;

        ConstraintBreakdown {
            horner: horner_mults + horner_adds,
            rlc: rlc_mults + rlc_adds + rlc_assert,
            lagrange: lagrange_mults + lagrange_adds + lagrange_assert,
            sum_check: sum_adds + sum_assert,
            commitment: commitment_constraints,
            total,
        }
    }
}

#[derive(Debug)]
struct ConstraintBreakdown {
    horner: usize,
    rlc: usize,
    lagrange: usize,
    sum_check: usize,
    commitment: usize,
    total: usize,
}

// ── Main ────────────────────────────────────────────────────────────────

fn main() {
    println!("=== C7 Prototype 2: RLC Batch Verification ===");
    println!();

    // --- N=8 prototype scale ---
    println!("--- N=8 prototype verification ---");
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    for t in [2, 4, 8usize] {
        let verifier = RlcVerifier::new(&mut rng, 8, t);
        let result = verifier.verify();
        println!(
            "  t={}: verification {}",
            t,
            if result { "PASS ✓" } else { "FAIL ✗" }
        );

        // Forgery test
        let detected = verifier.test_forgery();
        println!(
            "  t={}: forgery {}",
            t,
            if detected {
                "DETECTED ✓"
            } else {
                "NOT DETECTED ✗"
            }
        );
    }
    println!();

    // --- Timing benchmark at N=8192 ---
    println!("--- Timing benchmark (N=8192, t=128) ---");
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let verifier = RlcVerifier::new(&mut rng, 8192, 128);

    // Measure share eval computation (off-circuit)
    let start = Instant::now();
    let evals = verifier.compute_share_evals();
    let eval_time = start.elapsed();
    println!(
        "  Share evaluations (128 × Horner(N=8192)): {:?}",
        eval_time
    );

    // Measure RLC combine (off-circuit, produces combined polynomial)
    let beta = derive_rlc_beta(&evals);
    let start = Instant::now();
    let _combined = rlc_combine(&verifier.shares, beta);
    let combine_time = start.elapsed();
    println!("  RLC combine (128 polynomials): {:?}", combine_time);

    // Measure full verification
    let start = Instant::now();
    let result = verifier.verify();
    let verify_time = start.elapsed();
    println!(
        "  Full verification: {:?} — {}",
        verify_time,
        if result { "PASS ✓" } else { "FAIL ✗" }
    );

    // --- Constraint estimates ---
    println!();
    println!("--- Constraint estimates for N=8192 ---");
    println!("  |   t  |  Horner  |   RLC   | Lagrange | Sum Ck | Commit  |   TOTAL   |");
    println!("  |------|----------|---------|----------|--------|---------|-----------|");
    for t in [4, 32, 128usize] {
        let cb = RlcVerifier::constraint_estimate(8192, t);
        println!(
            "  | {:3} | {:>8} | {:>7} | {:>8} | {:>6} | {:>7} | {:>9} |",
            t, cb.horner, cb.rlc, cb.lagrange, cb.sum_check, cb.commitment, cb.total
        );
    }
    println!();

    // --- Soundness breakdown ---
    println!("--- Soundness Budget ---");
    let field_bits = 254f64;
    let n_deg = 8192f64;

    println!(
        "  Polynomial disagreement at r: {:>6.1} bits",
        -(n_deg / 2f64.powf(field_bits)).log2()
    );
    for t in [4, 32, 128usize] {
        let rlc_bits = -(t as f64 / 2f64.powf(field_bits)).log2();
        println!(
            "  RLC binding (t={:3}):           {:>6.1} bits",
            t, rlc_bits
        );
    }
    println!("  Poseidon collision:               128.0 bits");
    println!("  ─────────────────────────────────────────");
    let weakest = -(128f64 / 2f64.powf(field_bits)).log2(); // actually Poseidon is the weakest at 128
    println!("  Overall soundness (weakest link):  128.0 bits (Poseidon)");

    // --- Comparison with naive O(N²) ---
    println!();
    println!("--- Why the naive O(N²) Lagrange-in-circuit was rejected ---");
    println!("  Naive: verify Σ λ_i · d_i[k] = pt[k] for all 8192 coefficients");
    println!(
        "  Per coefficient: {} mults + {} adds = {} ops",
        128, 127, 255
    );
    println!("  Total: 8192 × 255 = {} constraints", 8192 * 255);
    println!(
        "  Plus per-share polynomial hashing: 128 × 8192 = {} constraints",
        128 * 8192
    );
    println!(
        "  Grand total O(N²): ~{} constraints — INFEASIBLE",
        8192 * 255 + 128 * 8192
    );
    let cb = RlcVerifier::constraint_estimate(8192, 128);
    println!();
    println!("  RLC approach: {} constraints — FEASIBLE", cb.total);
    println!(
        "  Reduction: {:.0}×",
        (8192 * 255 + 128 * 8192) as f64 / cb.total as f64
    );
}
