//! CCS adapter for the Cyclo LatticeFold+ verifier equation.
//!
//! Encodes the P1 verifier equation:
//!   c·z_s + z_e - t - c·d ≡ 0  (mod q_commit)
//! over the Cyclo commitment ring R = Z_q[X]/(X^256+1).

use ark_ff::PrimeField;

use super::ring_element::RingElement;

/// Encodes the P1 verifier equation over the Cyclo commitment ring.
///
/// The equation verified is: `c·z_s + z_e - t - c·d ≡ 0` where:
/// - `c` is a ternary challenge in {-1, 0, 1}
/// - `z_s` is the masked secret share (response term)
/// - `z_e` is the masked error share (response term)
/// - `t` is the public target commitment
/// - `d` is the public statement term
///
/// All values are ring elements in R = Z_q[X]/(X^N+1).
pub struct CycloVerifierCCS<F: PrimeField> {
    /// Ring dimension (N_commit = 256 for Cyclo)
    pub n_commit: usize,
    /// Commitment modulus q_commit (as a field element)
    pub q_commit: F,
    /// Ternary challenge: -1, 0, or 1 (as a field element)
    pub challenge: F,
}

impl<F: PrimeField> CycloVerifierCCS<F> {
    pub fn new(n_commit: usize, q_commit: F, challenge: F) -> Self {
        Self {
            n_commit,
            q_commit,
            challenge,
        }
    }

    /// Verify the P1 equation for native values (not R1CS).
    ///
    /// Returns true if `c·z_s + z_e - t - c·d ≡ 0` holds for all coefficients.
    /// Since operations are over the field F (not reduced modulo q_commit),
    /// this checks exact equality to zero.
    pub fn verify_native(
        &self,
        z_s: &RingElement<F>,
        z_e: &RingElement<F>,
        t: &RingElement<F>,
        d: &RingElement<F>,
    ) -> bool {
        let c_zs = z_s.scale(self.challenge);
        let c_d = d.scale(self.challenge);
        let lhs = c_zs.add(z_e);
        let rhs = t.add(&c_d);
        let diff = lhs.sub(&rhs);
        diff.coeffs.iter().all(|&c| c == F::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};

    type Fr = ark_bn254::Fr;

    fn fr(v: u64) -> Fr {
        Fr::from(v)
    }

    #[test]
    fn verifier_accepts_honest_witness() {
        let n = 4;
        let q = fr(1_125_899_906_842_623); // ≈ 2^50
        let challenge = fr(1);
        let verifier = CycloVerifierCCS::new(n, q, challenge);

        let s = RingElement {
            coeffs: vec![fr(1), fr(2), fr(3), fr(4)],
        };
        let e = RingElement {
            coeffs: vec![fr(1), fr(0), fr(1), fr(0)],
        };
        let c = challenge;
        let d = RingElement {
            coeffs: vec![fr(2), fr(3), fr(4), fr(5)],
        };

        let z_s = s.scale(c);
        let z_e = e.scale(c);
        let t = z_s.scale(c).add(&z_e).sub(&d.scale(c));

        assert!(verifier.verify_native(&z_s, &z_e, &t, &d));
    }

    #[test]
    fn verifier_rejects_wrong_witness() {
        let n = 4;
        let q = fr(1_125_899_906_842_623);
        let challenge = fr(1);
        let verifier = CycloVerifierCCS::new(n, q, challenge);

        let s = RingElement {
            coeffs: vec![fr(1), fr(2), fr(3), fr(4)],
        };
        let e = RingElement {
            coeffs: vec![fr(1), fr(0), fr(1), fr(0)],
        };
        let c = challenge;
        let d = RingElement {
            coeffs: vec![fr(2), fr(3), fr(4), fr(5)],
        };

        let z_s = s.scale(c);
        let z_e = e.scale(c);
        let t = z_s.scale(c).add(&z_e).sub(&d.scale(c));

        let mut tampered_z_s = z_s.clone();
        tampered_z_s.coeffs[0] += fr(1);

        assert!(!verifier.verify_native(&tampered_z_s, &z_e, &t, &d));
    }

    #[test]
    fn verifier_rejects_wrong_challenge() {
        let n = 4;
        let q = fr(1_125_899_906_842_623);
        let challenge = fr(1);
        let s = RingElement {
            coeffs: vec![fr(1), fr(2), fr(3), fr(4)],
        };
        let e = RingElement {
            coeffs: vec![fr(1), fr(0), fr(1), fr(0)],
        };
        let c = challenge;
        let d = RingElement {
            coeffs: vec![fr(2), fr(3), fr(4), fr(5)],
        };

        let z_s = s.scale(c);
        let z_e = e.scale(c);
        let t = z_s.scale(c).add(&z_e).sub(&d.scale(c));

        let wrong_verifier = CycloVerifierCCS::new(n, q, fr(0));
        assert!(!wrong_verifier.verify_native(&z_s, &z_e, &t, &d));
    }

    #[test]
    fn verifier_with_challenge_negative_one() {
        let n = 4;
        let q = fr(1_125_899_906_842_623);
        let neg_one: Fr = Fr::zero() - Fr::one();
        let verifier = CycloVerifierCCS::new(n, q, neg_one);

        let s = RingElement {
            coeffs: vec![fr(1), fr(2), fr(3), fr(4)],
        };
        let e = RingElement {
            coeffs: vec![fr(1), fr(0), fr(1), fr(0)],
        };
        let d = RingElement {
            coeffs: vec![fr(2), fr(3), fr(4), fr(5)],
        };

        let z_s = s.scale(neg_one);
        let z_e = e.scale(neg_one);
        let t = z_s.scale(neg_one).add(&z_e).sub(&d.scale(neg_one));

        assert!(verifier.verify_native(&z_s, &z_e, &t, &d));
    }

    #[test]
    fn verifier_with_challenge_zero() {
        let n = 4;
        let q = fr(1_125_899_906_842_623);
        let zero = fr(0);
        let verifier = CycloVerifierCCS::new(n, q, zero);

        let z_s = RingElement::constant(fr(42), n);
        let z_e = RingElement::constant(fr(7), n);
        let d = RingElement::constant(fr(99), n);

        let t = z_e.clone();

        assert!(verifier.verify_native(&z_s, &z_e, &t, &d));
    }
}
