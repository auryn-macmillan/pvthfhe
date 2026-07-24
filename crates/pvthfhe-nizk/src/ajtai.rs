//! Ajtai commitment scheme over `R_{q_commit} = Z_{q_commit}[X]/(X^{256}+1)` —
//! NIZK-side adapter over the canonical implementation in `pvthfhe-cyclo`.
//!
//! The ring multiplication, matrix derivation, and commitment computation are
//! owned by [`pvthfhe_cyclo::ring`] and [`pvthfhe_cyclo::ajtai`] (Phase 3.2 of
//! the 2026-07-24 repo refactor). This module preserves the NIZK crate's
//! public API — centred-`i64` [`Rq`], [`AjtaiParams`]/[`AjtaiMatrix`]/
//! [`AjtaiCommitment`] with [`NizkError`] errors, the D2 digest, and the
//! witness ∞-norm bound check (which cyclo's `commit` deliberately does not
//! perform — it is enforced here by wrapping, not duplicating) — by
//! delegating. Byte-level equivalence with the former in-crate implementation
//! is pinned by `pvthfhe-aggregator/tests/primitive_equivalence.rs`.

use crate::NizkError;
use pvthfhe_cyclo::ajtai as cyclo_ajtai;
use pvthfhe_cyclo::ring::{ntt_mul, RqPoly};
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

pub use pvthfhe_cyclo::ring::{PHI_COMMIT as PHI, Q_COMMIT};

/// Ajtai commitment rank `a = 13` (number of output ring elements).
pub const AJTAI_RANK: usize = 13;

/// Witness infinity-norm bound `B = 1024`.
pub const WITNESS_BOUND: u64 = 1024;

/// An element of `R_{q_commit} = Z_{q_commit}[X]/(X^{256}+1)`.
///
/// Coefficients are stored in centred representation `(-q/2, q/2]` after
/// [`Rq::reduce`] is called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rq {
    pub(crate) coeffs: [i64; PHI],
    pub(crate) q: u64,
}

impl Rq {
    /// Constructs an `Rq` without reducing coefficients.
    pub fn new(coeffs: [i64; PHI], q: u64) -> Self {
        Self { coeffs, q }
    }

    /// Returns the additive identity in `R_q`.
    pub fn zero(q: u64) -> Self {
        Self {
            coeffs: [0_i64; PHI],
            q,
        }
    }

    /// Reduces all coefficients into the centred interval `(-q/2, q/2]`.
    ///
    /// Uses the signed-integer constant `Q_I64` for `q = Q_COMMIT`.
    /// For other moduli the caller must use `i64::try_from(q)`.
    pub fn reduce(&mut self) -> Result<(), NizkError> {
        let q = i64::try_from(self.q).map_err(|_| NizkError::InvalidInput {
            reason: "q does not fit i64",
            party_id: None,
        })?;
        for c in &mut self.coeffs {
            *c = c.rem_euclid(q);
            if *c > q / 2 {
                *c -= q;
            }
        }
        Ok(())
    }

    /// Adds two ring elements coefficient-wise and reduces modulo `q`.
    pub fn add(&self, other: &Self) -> Result<Self, NizkError> {
        debug_assert_eq!(self.q, other.q);
        let mut out = Self::zero(self.q);
        for i in 0..PHI {
            out.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        out.reduce()?;
        Ok(out)
    }

    /// Negacyclic multiplication in `Z_q[X]/(X^256+1)`.
    ///
    /// Delegates to the canonical NTT multiplication in
    /// [`pvthfhe_cyclo::ring::ntt_mul`], proven coefficient-identical to the
    /// former schoolbook implementation by the Phase-1 equivalence pins.
    pub fn mul(&self, other: &Self) -> Result<Self, NizkError> {
        debug_assert_eq!(self.q, other.q);
        let product =
            ntt_mul(&self.to_rqpoly(), &other.to_rqpoly()).map_err(|_| NizkError::InvalidInput {
                reason: "ajtai ring multiplication failed",
                party_id: None,
            })?;
        Ok(Self::from_rqpoly(&product, self.q))
    }

    /// Returns `‖self‖_∞` (maximum absolute coefficient value).
    pub fn infinity_norm(&self) -> u64 {
        self.coeffs
            .iter()
            .map(|c| c.unsigned_abs())
            .max()
            .unwrap_or(0)
    }

    /// Samples a uniformly random element of `R_q`.
    pub fn sample_uniform(rng: &mut dyn RngCore, q: u64) -> Result<Self, NizkError> {
        let mut coeffs = [0_i64; PHI];
        for c in &mut coeffs {
            let raw = rng.next_u64() % q;
            *c = i64::try_from(raw).map_err(|_| NizkError::InvalidInput {
                reason: "uniform sample out of i64 range",
                party_id: None,
            })?;
        }
        let mut el = Self { coeffs, q };
        el.reduce()?;
        Ok(el)
    }

    /// Samples a random element with coefficients uniformly in `[-B, B]`.
    pub fn sample_bounded(rng: &mut dyn RngCore, bound: u64) -> Result<Self, NizkError> {
        let range = 2_u64
            .checked_mul(bound)
            .and_then(|v| v.checked_add(1))
            .ok_or(NizkError::InvalidInput {
                reason: "bound overflow in sample_bounded",
                party_id: None,
            })?;
        let bound_i64 = i64::try_from(bound).map_err(|_| NizkError::InvalidInput {
            reason: "bound does not fit i64",
            party_id: None,
        })?;
        let mut coeffs = [0_i64; PHI];
        for c in &mut coeffs {
            let raw =
                i64::try_from(rng.next_u64() % range).map_err(|_| NizkError::InvalidInput {
                    reason: "bounded sample out of i64 range",
                    party_id: None,
                })?;
            *c = raw - bound_i64;
        }
        Ok(Self {
            coeffs,
            q: Q_COMMIT,
        })
    }

    /// Views the centred coefficients as residues in `[0, Q_COMMIT)`.
    fn to_rqpoly(&self) -> RqPoly {
        RqPoly(
            self.coeffs
                .iter()
                .map(|&c| c.rem_euclid(Q_COMMIT as i64) as u64)
                .collect(),
        )
    }

    /// Lifts residues in `[0, Q_COMMIT)` to the centred representation
    /// `(-Q_COMMIT/2, Q_COMMIT/2]`, tagging the result with modulus `q`.
    fn from_rqpoly(poly: &RqPoly, q: u64) -> Self {
        debug_assert_eq!(poly.0.len(), PHI);
        let mut coeffs = [0i64; PHI];
        for (i, &c) in poly.0.iter().enumerate() {
            coeffs[i] = if c > Q_COMMIT / 2 {
                (c as i128 - Q_COMMIT as i128) as i64
            } else {
                c as i64
            };
        }
        Self { coeffs, q }
    }
}

/// Locked parameters for the Ajtai commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AjtaiParams {
    /// Ring degree (φ = 256).
    pub phi: usize,
    /// Modulus (`Q_COMMIT`).
    pub q: u64,
    /// Commitment rank (`a = 13`).
    pub rank: usize,
    /// Witness ∞-norm bound (`B = 1024`).
    pub witness_bound: u64,
}

impl Default for AjtaiParams {
    fn default() -> Self {
        Self {
            phi: PHI,
            q: Q_COMMIT,
            rank: AJTAI_RANK,
            witness_bound: WITNESS_BOUND,
        }
    }
}

/// An `a × m` matrix of `Rq` elements derived deterministically from a seed.
///
/// The matrix entries are owned by the canonical `pvthfhe-cyclo` Ajtai
/// implementation (`ChaCha20Rng::from_seed(seed)`, row-major,
/// `next_u64() % q_commit` per coefficient); this handle carries the seed and
/// shape needed to regenerate them at commitment time.
#[derive(PartialEq, Eq)]
pub struct AjtaiMatrix {
    pub(crate) seed: [u8; 32],
    pub(crate) params: AjtaiParams,
    pub(crate) m: usize,
}

impl AjtaiMatrix {
    /// Binds the matrix to `seed` for a `params.rank × m` commitment matrix.
    ///
    /// The entries themselves are derived by the canonical cyclo
    /// implementation when a commitment is computed.
    pub fn from_seed(seed: [u8; 32], params: &AjtaiParams, m: usize) -> Result<Self, NizkError> {
        Ok(Self {
            seed,
            params: params.clone(),
            m,
        })
    }

    /// Parameters of the equivalent canonical `pvthfhe-cyclo` Ajtai instance:
    /// cyclo's `m` (rows) is this crate's commitment rank, cyclo's `n`
    /// (columns) is this crate's witness width.
    fn cyclo_params(&self) -> cyclo_ajtai::AjtaiParams {
        cyclo_ajtai::AjtaiParams {
            m: self.params.rank,
            n: self.m,
            q_commit: self.params.q,
            seed: self.seed,
        }
    }
}

/// An Ajtai commitment `C = A · s ∈ R_q^a`.
pub struct AjtaiCommitment {
    pub(crate) elems: Vec<Rq>,
}

impl AjtaiCommitment {
    /// Commits to a witness vector `s` under matrix `A`.
    ///
    /// Returns `Err` if any witness element exceeds the ∞-norm bound or if
    /// `witness.len() != matrix.m`. The bound check is enforced on the nizk
    /// side (cyclo's `commit` does not perform it); the commitment itself is
    /// computed by the canonical cyclo implementation.
    pub fn commit(matrix: &AjtaiMatrix, witness: &[Rq]) -> Result<Self, NizkError> {
        if witness.len() != matrix.m {
            return Err(NizkError::InvalidInput {
                reason: "witness length mismatch",
                party_id: None,
            });
        }
        for w in witness {
            if w.infinity_norm() > matrix.params.witness_bound {
                return Err(NizkError::InvalidInput {
                    reason: "witness exceeds norm bound",
                    party_id: None,
                });
            }
        }
        let witness_residues: Vec<RqPoly> = witness.iter().map(Rq::to_rqpoly).collect();
        // The RNG is unused by the canonical implementation (the matrix is
        // derived from the seed); a throwaway stream satisfies the signature.
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]); // allow-seeded-rng: ignored by cyclo commit; matrix derivation is seed-bound
        let commitment = cyclo_ajtai::commit(&matrix.cyclo_params(), &witness_residues, &mut rng)
            .map_err(|_| NizkError::InvalidInput {
                reason: "ajtai commit failed",
                party_id: None,
            })?;
        Ok(Self {
            elems: commitment
                .commitment
                .iter()
                .map(|p| Rq::from_rqpoly(p, matrix.params.q))
                .collect(),
        })
    }

    /// Verifies that `claimed_witness` opens this commitment.
    ///
    /// Recomputes `A · s'` and compares element-wise with the stored commitment.
    pub fn verify_open(
        &self,
        matrix: &AjtaiMatrix,
        claimed_witness: &[Rq],
    ) -> Result<(), NizkError> {
        let recomputed = Self::commit(matrix, claimed_witness)?;
        if self.elems.len() != recomputed.elems.len() {
            return Err(NizkError::VerificationFailed {
                reason: "ajtai opening mismatch",
                party_id: None,
            });
        }

        let mut matches = Choice::from(1u8);
        for (a, b) in self.elems.iter().zip(recomputed.elems.iter()) {
            if a.coeffs.len() != b.coeffs.len() {
                return Err(NizkError::VerificationFailed {
                    reason: "ajtai opening mismatch",
                    party_id: None,
                });
            }
            for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
                matches &= a_coeff.ct_eq(b_coeff);
            }
        }

        if bool::from(matches) {
            Ok(())
        } else {
            Err(NizkError::VerificationFailed {
                reason: "ajtai opening mismatch",
                party_id: None,
            })
        }
    }

    /// Returns a 32-byte SHA-256 digest of the commitment for D2 hash binding.
    ///
    /// The digest commits to all ring element coefficients in the commitment
    /// vector `C = A · s ∈ R_q^a`.
    pub fn to_d2_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(pvthfhe_foundations::domain_tags::Tag::AjtaiD2Commitment.as_bytes());
        for elem in &self.elems {
            for coeff in &elem.coeffs {
                hasher.update(coeff.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }
}
