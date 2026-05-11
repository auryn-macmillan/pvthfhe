//! Ajtai commitment scheme over `R_{q_commit} = Z_{q_commit}[X]/(X^{256}+1)`.
use crate::NizkError;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

/// `q_commit = 562_949_953_438_721`
///
/// Smallest prime ≥ 2^49 satisfying `q ≡ 1 (mod 1024)`.
/// The congruence `1 (mod 1024) = 1 (mod 4·256)` is the necessary and
/// sufficient condition for this prime to support a degree-256 NTT, making
/// the constant forward-compatible with an NTT optimisation in N4.
pub const Q_COMMIT: u64 = 562_949_953_438_721;

/// `Q_COMMIT` as i128 for schoolbook multiplication accumulators.
const Q_I128: i128 = 562_949_953_438_721_i128;

/// Cyclotomic ring degree φ = 256; elements live in `Z[X]/(X^256+1)`.
pub const PHI: usize = 256;

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
        let q = i64::try_from(self.q).map_err(|_| NizkError::InvalidInput("q does not fit i64"))?;
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

    /// Schoolbook negacyclic multiplication in `Z_q[X]/(X^256+1)`.
    ///
    /// Phase 2 (N4): will replace with NTT for O(n log n) performance.
    pub fn mul(&self, other: &Self) -> Result<Self, NizkError> {
        debug_assert_eq!(self.q, other.q);
        let mut raw = [0_i128; PHI];
        for i in 0..PHI {
            for j in 0..PHI {
                let prod = i128::from(self.coeffs[i]) * i128::from(other.coeffs[j]);
                if i + j < PHI {
                    raw[i + j] += prod;
                } else {
                    raw[i + j - PHI] -= prod;
                }
            }
        }
        let mut coeffs = [0_i64; PHI];
        for (i, r) in raw.iter().enumerate() {
            let mut v = r.rem_euclid(Q_I128);
            if v > Q_I128 / 2 {
                v -= Q_I128;
            }
            coeffs[i] = i64::try_from(v)
                .map_err(|_| NizkError::InvalidInput("mul coefficient out of i64 range"))?;
        }
        Ok(Self { coeffs, q: self.q })
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
            *c = i64::try_from(raw)
                .map_err(|_| NizkError::InvalidInput("uniform sample out of i64 range"))?;
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
            .ok_or(NizkError::InvalidInput("bound overflow in sample_bounded"))?;
        let bound_i64 =
            i64::try_from(bound).map_err(|_| NizkError::InvalidInput("bound does not fit i64"))?;
        let mut coeffs = [0_i64; PHI];
        for c in &mut coeffs {
            let raw = i64::try_from(rng.next_u64() % range)
                .map_err(|_| NizkError::InvalidInput("bounded sample out of i64 range"))?;
            *c = raw - bound_i64;
        }
        Ok(Self {
            coeffs,
            q: Q_COMMIT,
        })
    }
}

/// Locked parameters for the Ajtai commitment.
#[derive(Clone, Debug)]
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

/// An `a × m` matrix of `Rq` elements sampled deterministically from a seed.
pub struct AjtaiMatrix {
    pub(crate) rows: Vec<Vec<Rq>>,
    pub(crate) params: AjtaiParams,
    pub(crate) m: usize,
}

impl AjtaiMatrix {
    /// Constructs the matrix by sampling each entry uniformly from `R_q`
    /// using a seeded `ChaCha20Rng`.
    pub fn from_seed(seed: [u8; 32], params: &AjtaiParams, m: usize) -> Result<Self, NizkError> { // allow-seeded-rng: API surface; binding enforced at callsite
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let mut rng = ChaCha20Rng::from_seed(seed); // allow-seeded-rng: matrix sampler internal to from_seed
        let mut rows = Vec::with_capacity(params.rank);
        for _ in 0..params.rank {
            let mut row = Vec::with_capacity(m);
            for _ in 0..m {
                row.push(Rq::sample_uniform(&mut rng, params.q)?);
            }
            rows.push(row);
        }
        Ok(Self {
            rows,
            params: params.clone(),
            m,
        })
    }

    /// Returns true when every element of `self` and `other` is equal.
    pub fn eq(&self, other: &Self) -> bool {
        if self.rows.len() != other.rows.len() {
            return false;
        }
        for (row_self, row_other) in self.rows.iter().zip(other.rows.iter()) {
            if row_self.len() != row_other.len() {
                return false;
            }
            for (a, b) in row_self.iter().zip(row_other.iter()) {
                if a != b {
                    return false;
                }
            }
        }
        true
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
    /// `witness.len() != matrix.m`.
    pub fn commit(matrix: &AjtaiMatrix, witness: &[Rq]) -> Result<Self, NizkError> {
        if witness.len() != matrix.m {
            return Err(NizkError::InvalidInput("witness length mismatch"));
        }
        for w in witness {
            if w.infinity_norm() > matrix.params.witness_bound {
                return Err(NizkError::InvalidInput("witness exceeds norm bound"));
            }
        }
        let mut elems = Vec::with_capacity(matrix.params.rank);
        for row in &matrix.rows {
            let mut acc = Rq::zero(matrix.params.q);
            for (a_ij, s_j) in row.iter().zip(witness.iter()) {
                acc = acc.add(&a_ij.mul(s_j)?)?;
            }
            elems.push(acc);
        }
        Ok(Self { elems })
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
            return Err(NizkError::VerificationFailed("ajtai opening mismatch"));
        }

        let mut matches = Choice::from(1u8);
        for (a, b) in self.elems.iter().zip(recomputed.elems.iter()) {
            if a.coeffs.len() != b.coeffs.len() {
                return Err(NizkError::VerificationFailed("ajtai opening mismatch"));
            }
            for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
                matches &= a_coeff.ct_eq(b_coeff);
            }
        }

        if bool::from(matches) {
            Ok(())
        } else {
            Err(NizkError::VerificationFailed("ajtai opening mismatch"))
        }
    }

    /// Returns a 32-byte SHA-256 digest of the commitment for D2 hash binding.
    ///
    /// The digest commits to all ring element coefficients in the commitment
    /// vector `C = A · s ∈ R_q^a`.
    pub fn to_d2_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"pvthfhe-ajtai-d2-commitment-v1");
        for elem in &self.elems {
            for coeff in &elem.coeffs {
                hasher.update(coeff.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }
}
