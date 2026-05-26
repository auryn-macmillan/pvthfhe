use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField, UniformRand, Zero};
use pvthfhe_pvss::encrypt::compute_poly_factors;
use pvthfhe_pvss::parity::generate_parity_matrix;
use pvthfhe_pvss::shamir;
use rand::thread_rng;

fn eval_poly(coeffs: &[Fr], x: &Fr) -> Fr {
    coeffs.iter().rev().fold(Fr::ZERO, |acc, c| acc * x + c)
}

fn main() {
    let n = 16usize;
    let t = 7usize;

    let mut rng = thread_rng();
    let secret = Fr::rand(&mut rng);
    let shares = shamir::split(&secret, n, t, &mut rng).unwrap();
    let share_values: Vec<Fr> = shares.iter().map(|(_, y)| *y).collect();

    // Verify recovery
    let recovered = shamir::recover(&shares[..t], t).unwrap();
    assert_eq!(recovered, secret);
    println!("Shamir recovery: OK");

    // Check finite-diff parity
    let h = generate_parity_matrix(n, t);
    println!("Parity matrix rows: {}", h.len());
    for (i, row) in h.iter().enumerate() {
        let dot: Fr = row
            .iter()
            .zip(share_values.iter())
            .map(|(&hij, &sj)| hij * sj)
            .fold(Fr::ZERO, |a, x| a + x);
        println!("  row {}: dot.is_zero() = {}", i, dot.is_zero());
        assert!(dot.is_zero(), "finite-diff parity row {} failed", i);
    }
    println!("Finite-diff parity: OK");

    // Check Schwartz-Zippel combined check via compute_poly_factors
    for r_val in [42u64, 12345u64, 99999u64] {
        let r = Fr::from(r_val);
        let factors = compute_poly_factors(n, t, r);
        let dot_product: Fr = share_values
            .iter()
            .zip(factors.iter())
            .map(|(&s, &f)| s * f)
            .fold(Fr::ZERO, |acc, x| acc + x);
        println!(
            "  r={}: dot_product.is_zero() = {}",
            r_val,
            dot_product.is_zero()
        );
        if !dot_product.is_zero() {
            println!("  FAILED! dot = {:?}", dot_product);
            // Fall through - don't assert yet, let's see what's happening
        }
    }
    println!("All checks done");
}
