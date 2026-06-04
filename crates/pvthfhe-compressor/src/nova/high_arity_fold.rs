//! High-arity folding (Symphony T1 §4): batch-fold n instances into a single
//! step via random linear combination with a Fiat-Shamir-derived β vector.
//!
//! ## Design
//!
//! 1. **β derivation**: `derive_beta_vector(session_id, num_steps)` produces a
//!    vector β ∈ Frⁿ via Keccak256-based Fiat-Shamir:
//!    ```text
//!    β_k = Keccak256(session_id || k || num_steps) mod Fr.order()
//!    ```
//! 2. **Input folding**: `fold_external_inputs(inputs, β)` computes
//!    ```text
//!    folded = Σ_{k=0}^{n-1} β_k · inputs[k]
//!    ```
//!    where multiplication is component-wise on `(a, b, c)` triples over Fr.
//! 3. **Witness folding**: `fold_witnesses(witnesses, β)` computes the same
//!    linear combination over `Vec<Fr>` witness vectors.
//!
//! ## Usage
//!
//! The folded inputs and witnesses are passed to `prove_steps` which produces
//! a proof binding to the accumulated public inputs. This reduces the number of
//! proof-header entries but does NOT change the Nova IVC accumulator (the Nova
//! step circuits must be modified to consume batch-folded witness data for that).
//! This is documented as a known limitation in P2-lattice-folding.md §Task 2.

use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use sha3::{Digest, Keccak256};

use super::ExternalInputs3;

/// Configuration for high-arity folding.
#[derive(Clone, Debug)]
pub struct HighArityConfig {
    /// Number of instances to fold into one.
    pub batch_size: usize,
}

impl Default for HighArityConfig {
    fn default() -> Self {
        Self { batch_size: 128 }
    }
}

/// Derive a deterministic Fiat-Shamir β vector over Fr for folding n instances.
///
/// # Security
///
/// The β vector is derived from `session_id` (a unique session binding) and
/// the number of steps. Each β_k is independently derived via:
/// ```text
/// β_k = Keccak256(session_id || "beta" || k || num_steps) mod Fr.order()
/// ```
///
/// This ensures:
/// - **Determinism**: same session_id → same β (reproducible proofs)
/// - **Session-binding**: different session → different β
/// - **Resistance to β-manipulation**: β is fixed by the session hash, not
///   chosen by any party
pub fn derive_beta_vector(session_id: &[u8], num_steps: usize) -> Vec<Fr> {
    let num_steps_bytes = (num_steps as u64).to_be_bytes();
    let mut beta = Vec::with_capacity(num_steps);

    for k in 0..num_steps {
        let k_bytes = (k as u64).to_be_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(session_id);
        hasher.update(b"beta");
        hasher.update(k_bytes);
        hasher.update(num_steps_bytes);
        let digest: [u8; 32] = hasher.finalize().into();

        let fr = Fr::from_be_bytes_mod_order(&digest);
        beta.push(fr);
    }

    beta
}

/// Fold a slice of `ExternalInputs3<Fr>` into a single `ExternalInputs3<Fr>`
/// using linear combination with β coefficients.
///
/// ```text
/// folded = Σ_{k=0}^{n-1} β_k · inputs[k]
/// ```
///
/// Each component of the triple is multiplied by the corresponding β_k and
/// summed component-wise.
pub fn fold_external_inputs(inputs: &[ExternalInputs3<Fr>], beta: &[Fr]) -> ExternalInputs3<Fr> {
    assert_eq!(
        inputs.len(),
        beta.len(),
        "fold_external_inputs: input count {} != beta count {}",
        inputs.len(),
        beta.len()
    );

    let mut acc0 = Fr::zero();
    let mut acc1 = Fr::zero();
    let mut acc2 = Fr::zero();

    for (input, b) in inputs.iter().zip(beta.iter()) {
        acc0 += *b * input.0;
        acc1 += *b * input.1;
        acc2 += *b * input.2;
    }

    ExternalInputs3(acc0, acc1, acc2)
}

/// Fold external inputs independently per batch.
///
/// For input chunks of length at most `batch_size`, returns one folded triple per
/// chunk using the matching slice of the Fiat-Shamir β vector. This is the
/// batch primitive used by T1 high-arity folding: n original steps become
/// `ceil(n / batch_size)` folded instances rather than one duplicated folded
/// instance.
pub fn fold_external_inputs_in_batches(
    inputs: &[ExternalInputs3<Fr>],
    beta: &[Fr],
    batch_size: usize,
) -> Vec<ExternalInputs3<Fr>> {
    assert!(batch_size > 0, "batch_size must be non-zero");
    assert_eq!(
        inputs.len(),
        beta.len(),
        "fold_external_inputs_in_batches: input count {} != beta count {}",
        inputs.len(),
        beta.len()
    );

    inputs
        .chunks(batch_size)
        .zip(beta.chunks(batch_size))
        .map(|(chunk, beta_chunk)| fold_external_inputs(chunk, beta_chunk))
        .collect()
}

/// Fold a slice of witness vectors into a single witness vector using linear
/// combination with β coefficients.
///
/// ```text
/// folded[i] = Σ_{k=0}^{n-1} β_k · witnesses[k][i]
/// ```
///
/// All witness vectors must have the same length. The resulting folded witness
/// has that same length.
pub fn fold_witnesses(witnesses: &[Vec<Fr>], beta: &[Fr]) -> Vec<Fr> {
    assert_eq!(
        witnesses.len(),
        beta.len(),
        "fold_witnesses: witness count {} != beta count {}",
        witnesses.len(),
        beta.len()
    );
    if witnesses.is_empty() {
        return Vec::new();
    }

    let vec_len = witnesses[0].len();
    for (i, w) in witnesses.iter().enumerate() {
        assert_eq!(
            w.len(),
            vec_len,
            "fold_witnesses: witness[{}] has len {} != expected {}",
            i,
            w.len(),
            vec_len
        );
    }

    let mut folded = vec![Fr::zero(); vec_len];
    for (witness, b) in witnesses.iter().zip(beta.iter()) {
        for (i, val) in witness.iter().enumerate() {
            folded[i] += *b * val;
        }
    }

    folded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_beta_is_deterministic() {
        let session = b"test-session-001";
        let beta1 = derive_beta_vector(session, 16);
        let beta2 = derive_beta_vector(session, 16);
        assert_eq!(beta1, beta2);
    }

    #[test]
    fn derive_beta_differs_per_session() {
        let beta_a = derive_beta_vector(b"session-a", 8);
        let beta_b = derive_beta_vector(b"session-b", 8);
        assert_ne!(beta_a, beta_b);
    }

    #[test]
    fn derive_beta_differs_per_count() {
        let beta_8 = derive_beta_vector(b"session", 8);
        let beta_16 = derive_beta_vector(b"session", 16);
        assert_ne!(beta_8.len(), beta_16.len());
    }

    #[test]
    fn fold_external_inputs_correctness() {
        let inputs = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
        ];
        let beta = vec![Fr::from(1u64), Fr::from(1u64)];
        let folded = fold_external_inputs(&inputs, &beta);
        assert_eq!(folded.0, Fr::from(5u64));
        assert_eq!(folded.1, Fr::from(7u64));
        assert_eq!(folded.2, Fr::from(9u64));
    }

    #[test]
    fn fold_external_inputs_with_random_beta() {
        let inputs = vec![ExternalInputs3(
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
        )];
        let beta = vec![Fr::from(3u64)];
        let folded = fold_external_inputs(&inputs, &beta);
        assert_eq!(folded.0, Fr::from(3u64));
        assert_eq!(folded.1, Fr::zero());
        assert_eq!(folded.2, Fr::zero());
    }

    #[test]
    fn fold_witnesses_correctness() {
        let witnesses = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
        ];
        let beta = vec![Fr::from(1u64), Fr::from(1u64)];
        let folded = fold_witnesses(&witnesses, &beta);
        assert_eq!(folded, vec![Fr::from(4u64), Fr::from(6u64)]);
    }

    #[test]
    fn derive_beta_produces_nonzero_values() {
        let beta = derive_beta_vector(b"test", 32);
        let all_zero = beta.iter().all(|b| b.is_zero());
        assert!(!all_zero, "β vector should not be all-zero");
    }

    #[test]
    fn fold_external_inputs_in_batches_respects_batch_boundaries() {
        let inputs: Vec<_> = (1u64..=5)
            .map(|v| ExternalInputs3(Fr::from(v), Fr::from(10 * v), Fr::from(100 * v)))
            .collect();
        let beta = vec![Fr::from(1u64); inputs.len()];

        let folded = fold_external_inputs_in_batches(&inputs, &beta, 2);

        assert_eq!(folded.len(), 3);
        assert_eq!(
            (folded[0].0, folded[0].1, folded[0].2),
            (Fr::from(3u64), Fr::from(30u64), Fr::from(300u64))
        );
        assert_eq!(
            (folded[1].0, folded[1].1, folded[1].2),
            (Fr::from(7u64), Fr::from(70u64), Fr::from(700u64))
        );
        assert_eq!(
            (folded[2].0, folded[2].1, folded[2].2),
            (Fr::from(5u64), Fr::from(50u64), Fr::from(500u64))
        );
    }
}
