#![cfg(feature = "legacy-nova")]

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField, UniformRand, Zero};
use pvthfhe_compressor::nova::{
    clear_dealer_parity_data, encode_triple, set_dealer_parity_data, DealerParityStepCircuit,
    NovaCompressor,
};
use pvthfhe_compressor::ProofCompressor;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn shamir_split(secret: &Fr, n: usize, t: usize, rng: &mut impl rand::RngCore) -> Vec<(usize, Fr)> {
    let mut coeffs = vec![*secret];
    for _ in 1..t {
        coeffs.push(Fr::rand(rng));
    }
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Fr::from(i as u64);
        let y = coeffs.iter().rev().fold(Fr::ZERO, |acc, c| acc * x + c);
        shares.push((i, y));
    }
    shares
}

fn compute_poly_factors(n: usize, t: usize, r: Fr) -> Vec<Fr> {
    let n_rows = if n > t + 1 { n - t - 1 } else { 0 };
    let mut factors = vec![Fr::ZERO; n];
    if n_rows == 0 {
        return factors;
    }
    let order = t + 1;
    let mut binom = Vec::with_capacity(order + 1);
    binom.push(Fr::from(1u64));
    for j in 0..order {
        let next =
            binom[j] * Fr::from((order - j) as u64) * Fr::from((j + 1) as u64).inverse().unwrap();
        binom.push(next);
    }
    for p in 0..n {
        let lo = if p < order { 0 } else { p - order };
        let hi = p.min(n_rows - 1);
        let mut acc = Fr::ZERO;
        let mut r_pow = r.pow(&[lo as u64]);
        for i in lo..=hi {
            let jj = p - i;
            let sign = if (order - jj) % 2 == 0 {
                Fr::ONE
            } else {
                -Fr::ONE
            };
            acc += r_pow * sign * binom[jj];
            r_pow *= r;
        }
        factors[p] = acc;
    }
    factors
}

#[test]
fn dealer_parity_circuit_roundtrip() {
    let n: usize = 16;
    let t: usize = 7;
    let mut rng = ChaCha20Rng::seed_from_u64(0xdea1e_u64);
    let secret = Fr::rand(&mut rng);
    let shares = shamir_split(&secret, n, t, &mut rng);
    let share_values: Vec<Fr> = shares.iter().map(|(_, y)| *y).collect();
    let r = Fr::from(42u64);
    let factors = compute_poly_factors(n, t, r);
    let native_dot: Fr = share_values
        .iter()
        .zip(factors.iter())
        .map(|(&s, &f)| s * f)
        .fold(Fr::ZERO, |acc, x| acc + x);
    assert!(native_dot.is_zero());
    set_dealer_parity_data(share_values.clone(), factors.clone(), Some(secret));
    let compressor = NovaCompressor::<DealerParityStepCircuit<Fr>>::new([0u8; 32], 1)
        .expect("construct compressor");
    let acc = encode_triple((Fr::ZERO, Fr::ZERO, Fr::ZERO));
    let pi = encode_triple((r, secret, Fr::from(n as u64)));
    let proof = compressor.prove(&acc, &pi).expect("prove");
    clear_dealer_parity_data();
    let ok = compressor
        .verify(&compressor.verifier_key(), &proof, &pi)
        .expect("verify");
    assert!(ok);
}
