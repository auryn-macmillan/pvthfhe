//! R1CS variable wrapper for Cyclo commitment ring elements.
//!
//! Provides coefficient-wise addition, subtraction, and negation
//! over ring elements in R = Z_q[X]/(X^N+1) represented as
//! vectors of FpVar<F> for use inside R1CS constraint systems.
//!
//! For the ternary challenge case (c ∈ {-1, 0, 1}), no R1CS
//! multiplications are needed — only the operations provided here.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;

/// R1CS variable wrapper for a ring element in R = Z_q[X]/(X^N+1).
///
/// Each coefficient of the polynomial is represented as an `FpVar<F>`,
/// enabling constraint generation inside Nova step circuits.
#[derive(Clone, Debug)]
pub struct RingElementVar<F: PrimeField> {
    /// Coefficients of the polynomial, from degree 0 to degree N-1.
    pub coeffs: Vec<FpVar<F>>,
}

impl<F: PrimeField> RingElementVar<F> {
    /// Creates a `RingElementVar` from a vector of coefficient variables.
    ///
    /// This is the canonical constructor for ring-element constraint
    /// representations in the Cyclo verifier R1CS encoding (M6).
    pub fn from_coeffs(coeffs: Vec<FpVar<F>>) -> Self {
        Self { coeffs }
    }

    /// Returns the number of coefficients (ring dimension N).
    pub fn n(&self) -> usize {
        self.coeffs.len()
    }

    /// Add two ring elements coefficient-wise.
    pub fn add(&self, other: &Self) -> Self {
        Self {
            coeffs: self
                .coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(a, b)| a + b)
                .collect(),
        }
    }

    /// Subtract two ring elements coefficient-wise.
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            coeffs: self
                .coeffs
                .iter()
                .zip(&other.coeffs)
                .map(|(a, b)| a - b)
                .collect(),
        }
    }

    /// Negate every coefficient of the ring element.
    pub fn negate(&self) -> Self {
        Self {
            coeffs: self
                .coeffs
                .iter()
                .map(|a| FpVar::constant(F::zero()) - a)
                .collect(),
        }
    }
}
