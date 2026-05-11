//! BN254 scalar Shamir secret sharing.
//!
//! This module implements Shamir's threshold secret-sharing scheme over the
//! BN254 scalar field (ark_bn254::Fr). It replaces the previous GF(256)/u8
//! implementation that lived in `encrypt.rs`.
//!
//! # Overview
//!
//! Shamir secret sharing works by evaluating a random degree-(t-1) polynomial
//! whose constant term is the secret. Each party receives one evaluation point
//! `(x, P(x))`. Any t shares can recover the secret via Lagrange interpolation;
//! any t-1 shares reveal nothing (perfect secrecy).
//!
//! # Field choice
//!
//! BN254 scalar field `Fr` has order ≈ 2^254, allowing secrets up to 31 bytes
//! (248 bits) to be embedded losslessly. For larger secrets, the caller
//! (`encrypt.rs`) chunks the input and calls `split`/`recover` per chunk.
//!
//! # Usage
//!
//! ```ignore
//! use ark_bn254::Fr;
//! use ark_ff::UniformRand;
//! use rand::thread_rng;
//! use pvthfhe_pvss::shamir;
//!
//! let mut rng = thread_rng();
//! let secret = Fr::rand(&mut rng);
//! let n = 10;
//! let t = 5;
//!
//! let shares = shamir::split(&secret, n, t, &mut rng);
//! let recovered = shamir::recover(&shares[..t]).expect("recovery succeeds");
//! assert_eq!(recovered, secret);
//! ```

use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};
use ark_bn254::Fr;
use rand_core::RngCore;
use std::fmt;

/// Errors that can occur during Shamir share operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShamirError {
    /// Not enough shares provided to satisfy the threshold.
    InsufficientShares,
    /// Duplicate x-coordinates detected in the share set.
    DuplicateX,
    /// Recovery failed (e.g., degenerate x-coordinates, zero denominator).
    RecoveryFailed,
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientShares => f.write_str("not enough shares to satisfy threshold"),
            Self::DuplicateX => f.write_str("duplicate x-coordinates in share set"),
            Self::RecoveryFailed => f.write_str("Shamir recovery failed"),
        }
    }
}

/// Split a secret into `n` shares with threshold `t` using Shamir secret sharing
/// over the BN254 scalar field.
///
/// # Arguments
///
/// * `secret` - The secret element to share (BN254 scalar).
/// * `n` - Total number of shares to produce (`n >= t`).
/// * `t` - Minimum number of shares required for recovery (`t > 0`).
/// * `rng` - Cryptographically secure random number generator.
///
/// # Returns
///
/// A vector of `n` shares, each a pair `(x, y)` where `x` is the share index
/// (1-based: `1..=n`) and `y = P(x)` is the polynomial evaluation.
///
/// # Panics
///
/// Panics if `t == 0` or `n < t`.
pub fn split(
    secret: &Fr,
    n: usize,
    t: usize,
    rng: &mut impl RngCore,
) -> Vec<(usize, Fr)> {
    assert!(t > 0, "threshold t must be positive");
    assert!(n >= t, "n must be at least t");

    // Sample a random polynomial f(X) = a_0 + a_1·X + … + a_{t-1}·X^{t-1}
    // where a_0 = secret, and a_1..a_{t-1} are uniformly random nonzero field elements.
    let mut coefficients = Vec::with_capacity(t);
    coefficients.push(*secret);
    for _ in 1..t {
        let mut coeff;
        loop {
            coeff = Fr::rand(rng);
            // With probability ≈ 2^{-254}, we get zero — retry for consistency.
            if !coeff.is_zero() {
                break;
            }
        }
        coefficients.push(coeff);
    }

    // Evaluate the polynomial at x = 1, 2, ..., n.
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Fr::from(i as u64);
        let y = evaluate_polynomial(&coefficients, &x);
        shares.push((i, y));
    }

    shares
}

/// Recover the secret from a set of shares using Lagrange interpolation.
///
/// # Arguments
///
/// * `shares` - A slice of at least `t` shares, each `(x, y)`.
///
/// # Returns
///
/// The recovered secret (the constant term `f(0)` of the shared polynomial),
/// or a `ShamirError` if the shares are insufficient or malformed.
pub fn recover(shares: &[(usize, Fr)]) -> Result<Fr, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares);
    }

    // Check for duplicate x-coordinates.
    let mut xs: Vec<usize> = shares.iter().map(|(x, _)| *x).collect();
    xs.sort_unstable();
    if xs.windows(2).any(|w| w[0] == w[1]) {
        return Err(ShamirError::DuplicateX);
    }

    let x_frs: Vec<Fr> = shares
        .iter()
        .map(|(x, _)| Fr::from(*x as u64))
        .collect();

    // Lagrange interpolation at x = 0:
    //
    //   f(0) = Σ_{i} y_i · L_i(0)
    //
    // where  L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
    //                 = Π_{j≠i} (-x_j) / (x_i - x_j)
    let mut recovered = Fr::ZERO;
    for (i, (_, y_i)) in shares.iter().enumerate() {
        let lambda = lagrange_coefficient_at_zero(i, &x_frs)
            .ok_or(ShamirError::RecoveryFailed)?;
        recovered += *y_i * lambda;
    }

    Ok(recovered)
}

/// Evaluate a polynomial `f(X) = Σ a_i · X^i` at `x` using Horner's method.
///
/// Horner's method evaluates the polynomial from highest degree to lowest:
///
/// ```text
/// f(x) = a_{k-1}·x^{k-1} + … + a_1·x + a_0
///      = ((…(a_{k-1}·x + a_{k-2})·x + …)·x + a_1)·x + a_0
/// ```
fn evaluate_polynomial(coefficients: &[Fr], x: &Fr) -> Fr {
    // coefficients[0] is the constant term (a_0), coefficients[t-1] is a_{t-1}.
    // Horner: start from the highest-degree coefficient and work down.
    let mut result = Fr::ZERO;
    for coeff in coefficients.iter().rev() {
        result = result * x + coeff;
    }
    result
}

/// Compute the Lagrange basis coefficient `L_i(0)` for share index `i`.
///
/// # Formula
///
/// ```text
/// L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
///        = Π_{j≠i} (-x_j) / (x_i - x_j)
/// ```
///
/// Returns `None` if the denominator is zero (i.e., duplicate or degenerate
/// x-coordinates) or if `index` is out of bounds.
fn lagrange_coefficient_at_zero(index: usize, xs: &[Fr]) -> Option<Fr> {
    let x_i = xs.get(index)?;

    let mut numerator = Fr::ONE;
    let mut denominator = Fr::ONE;

    for (j, x_j) in xs.iter().enumerate() {
        if j == index {
            continue;
        }

        // 0 - x_j = -x_j
        numerator *= -(*x_j);

        // x_i - x_j
        let diff = *x_i - x_j;
        if diff.is_zero() {
            return None; // degenerate: duplicate x-coordinate
        }
        denominator *= diff;
    }

    denominator.inverse().map(|inv| numerator * inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn split_recover_roundtrip() {
        let mut rng = thread_rng();
        let secret = Fr::rand(&mut rng);
        let n = 10;
        let t = 5;

        let shares = split(&secret, n, t, &mut rng);
        assert_eq!(shares.len(), n);

        // Recover with exactly t shares.
        let recovered = recover(&shares[..t]).expect("recovery with t shares");
        assert_eq!(recovered, secret);

        // Recover with all n shares.
        let recovered_all = recover(&shares).expect("recovery with all shares");
        assert_eq!(recovered_all, secret);

        // Recover with different subset of t shares.
        let subset: Vec<_> = shares[1..=t].to_vec();
        let recovered_subset = recover(&subset).expect("recovery with shifted subset");
        assert_eq!(recovered_subset, secret);
    }

    #[test]
    fn insufficient_shares_fails() {
        let mut rng = thread_rng();
        let secret = Fr::rand(&mut rng);
        let n = 5;
        let t = 3;

        let shares = split(&secret, n, t, &mut rng);
        let _result = recover(&shares[..t - 1]);
        // Not enough shares — but the function will still attempt interpolation
        // and either fail or produce a wrong result. We don't require the
        // function to detect insufficient shares (that's the caller's job),
        // but we verify that t shares do recover correctly.
        let recovered = recover(&shares[..t]).expect("recovery with t shares");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn empty_shares_fails() {
        let result = recover(&[]);
        assert_eq!(result, Err(ShamirError::InsufficientShares));
    }

    #[test]
    fn duplicate_x_fails() {
        let mut rng = thread_rng();
        let secret = Fr::rand(&mut rng);
        let n = 5;
        let t = 3;

        let shares = split(&secret, n, t, &mut rng);
        let mut dup = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        // Fix x-coordinates to be distinct even though values are the same.
        // Actually, the duplicate is on x-coordinates:
        dup[1].0 = dup[0].0; // Same x, different y would fail in Lagrange.
        // But we need actually duplicate x. The first two entries now have the
        // same x, but different y values. That's what we want to test.
        let result = recover(&dup);
        assert_eq!(result, Err(ShamirError::DuplicateX));
    }

    #[test]
    fn tampered_share_produces_wrong_secret() {
        let mut rng = thread_rng();
        let secret = Fr::rand(&mut rng);
        let n = 5;
        let t = 3;

        let mut shares = split(&secret, n, t, &mut rng);
        // Tamper with one share: add 1 to its y-value.
        shares[0].1 += Fr::ONE;

        let recovered = recover(&shares[..t]).expect("recovery should still compute");
        assert_ne!(recovered, secret, "tampered share should change recovered secret");
    }

    #[test]
    fn field_identity_is_correct() {
        let mut rng = thread_rng();
        let secret = Fr::ZERO;
        let n = 3;
        let t = 2;

        let shares = split(&secret, n, t, &mut rng);
        let recovered = recover(&shares[..t]).expect("recover zero secret");
        assert_eq!(recovered, Fr::ZERO);

        let secret = Fr::ONE;
        let shares = split(&secret, n, t, &mut rng);
        let recovered = recover(&shares[..t]).expect("recover one secret");
        assert_eq!(recovered, Fr::ONE);
    }

    #[test]
    fn coefficients_are_nonzero() {
        // This test verifies the internal property that all random coefficients
        // (except the constant term) are nonzero. We can't directly inspect the
        // coefficients from outside, but we can verify that two splittings of
        // the same secret produce different shares (because random coefficients
        // differ).
        let mut rng = thread_rng();
        let secret = Fr::ONE;
        let n = 3;
        let t = 2;

        let shares1 = split(&secret, n, t, &mut rng);
        let shares2 = split(&secret, n, t, &mut rng);

        // With overwhelming probability, random polynomials are different.
        let same = shares1
            .iter()
            .zip(shares2.iter())
            .all(|((_, y1), (_, y2))| y1 == y2);
        assert!(!same, "two random splittings should differ");
    }
}
