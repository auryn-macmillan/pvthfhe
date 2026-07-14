use crate::ring::{RqPoly, Q_COMMIT};

pub fn decompose_base_B(coeffs: &[u64], b: u64, k: usize) -> Vec<Vec<u64>> {
    let mut digits = vec![vec![0u64; coeffs.len()]; k];
    for (j, &c) in coeffs.iter().enumerate() {
        let mut val = c;
        for row in digits.iter_mut().take(k) {
            row[j] = val % b;
            val /= b;
        }
    }
    digits
}

pub fn recompose_base_B(digits: &[Vec<u64>], b: u64) -> Vec<u64> {
    let len = digits.first().map_or(0, |v| v.len());
    let q = Q_COMMIT as u128;
    let b_u128 = b as u128;
    let mut result = vec![0u64; len];
    for (i, digit_vec) in digits.iter().enumerate() {
        let weight = pow_mod(b_u128, i as u32, q);
        for (j, &d) in digit_vec.iter().enumerate() {
            let term = (d as u128 * weight) % q;
            result[j] = ((result[j] as u128 + term) % q) as u64;
        }
    }
    result
}

fn pow_mod(base: u128, exp: u32, modulus: u128) -> u128 {
    if exp == 0 {
        return 1u128 % modulus;
    }
    let mut result = 1u128;
    let mut b = base % modulus;
    let mut e = exp;
    loop {
        if e & 1 == 1 {
            result = (result * b) % modulus;
        }
        e >>= 1;
        if e == 0 {
            break;
        }
        b = (b * b) % modulus;
    }
    result
}

pub fn decompose_rqpoly_base_B(poly: &RqPoly, b: u64, k: usize) -> Vec<RqPoly> {
    let digits = decompose_base_B(&poly.0, b, k);
    digits
        .into_iter()
        .map(|coeffs| RqPoly(coeffs))
        .collect()
}

pub fn recompose_rqpoly_base_B(polys: &[RqPoly], b: u64) -> RqPoly {
    let digit_vecs: Vec<Vec<u64>> = polys.iter().map(|p| p.0.clone()).collect();
    RqPoly(recompose_base_B(&digit_vecs, b))
}
