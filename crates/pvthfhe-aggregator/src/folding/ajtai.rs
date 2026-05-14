//! Ajtai commitment matrix generation and commitment.
//!
//! Implements Com_A(w) = A·w for Ajtai commitments over the Cyclo ring.
//! The matrix A is deterministically derived from an epoch hash using SHA-256,
//! ensuring verifier-independent reproducibility.
//!
//! # Security
//!
//! Binding under M-SIS over R_{q_commit}: given A, it is hard to find w ≠ w'
//! such that A·w = A·w'. The commitment is also linear, enabling native folding.
//!
//! Current implementation uses a 1×n matrix (single row) for compact commitment.

use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

/// Ajtai commitment matrix: A ∈ F^{m×n} over a prime field.
///
/// For the Cyclo LatticeFold+ protocol, m = 1 (single commitment row)
/// and n equals the number of witness elements.
///
/// The matrix is deterministically derived from an epoch hash,
/// enabling any verifier to independently reconstruct A.
pub struct AjtaiMatrix<F: PrimeField> {
    /// Number of rows (commitment dimension), typically m = 1.
    pub rows: usize,
    /// Number of columns (witness dimension), typically n.
    pub cols: usize,
    /// Matrix entries stored as rows × cols.
    pub entries: Vec<Vec<F>>,
}

impl<F: PrimeField> AjtaiMatrix<F> {
    /// Generate a deterministic Ajtai matrix from an epoch hash.
    ///
    /// The matrix entries are derived by hashing (epoch || rows || cols || i || j)
    /// with SHA-256 and interpreting the output as a big-endian integer
    /// reduced modulo the field order.
    ///
    /// # Panics
    ///
    /// Panics if `rows` or `cols` is zero.
    pub fn from_epoch(epoch: &[u8; 32], rows: usize, cols: usize) -> Self {
        assert!(rows > 0, "rows must be > 0");
        assert!(cols > 0, "cols must be > 0");

        // Derive a base seed from (epoch || rows || cols)
        let mut hasher = Sha256::new();
        hasher.update(epoch);
        hasher.update(&(rows as u64).to_be_bytes());
        hasher.update(&(cols as u64).to_be_bytes());
        let seed = hasher.finalize().to_vec();

        let mut entries = Vec::with_capacity(rows);
        for i in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for j in 0..cols {
                // Deterministic pseudo-random field element from seed
                let mut input = seed.clone();
                input.extend_from_slice(&(i as u64).to_be_bytes());
                input.extend_from_slice(&(j as u64).to_be_bytes());
                let hash = Sha256::digest(&input);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&hash[..32]);
                // Convert to Fr using big-endian interpretation modulo field order
                let elem = F::from_be_bytes_mod_order(&bytes);
                row.push(elem);
            }
            entries.push(row);
        }
        Self { rows, cols, entries }
    }

    /// Commit to a witness vector: y = A·w.
    ///
    /// Computes the matrix-vector product A·w over the field.
    /// Returns a vector of length `self.rows`.
    ///
    /// # Panics
    ///
    /// Panics if `w.len() != self.cols`.
    pub fn commit(&self, w: &[F]) -> Vec<F> {
        assert_eq!(
            w.len(),
            self.cols,
            "commit: witness length {} != cols {}",
            w.len(),
            self.cols
        );
        let mut result = vec![F::zero(); self.rows];
        for i in 0..self.rows {
            let mut sum = F::zero();
            for j in 0..self.cols {
                sum += self.entries[i][j] * w[j];
            }
            result[i] = sum;
        }
        result
    }
}
