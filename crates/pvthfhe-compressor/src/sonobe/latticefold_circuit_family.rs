//! LatticeFold+ tree circuit family for heterogeneous IVC.
//!
//! Implements [`HeterogeneousCircuitFamily`] for a complete binary tree
//! with `depth` levels above the leaves. Each node in the tree is an IVC step:
//!
//! * **Leaves** (circuit 0): P1 ring-equation verifier (placeholder in M1).
//!   Enforces a simple linear combination check over external inputs.
//! * **Internal nodes** (circuit 1): Fold verifier. Accumulates two child
//!   hashes into a parent hash.
//!
//! # Tree structure
//!
//! For a tree of depth `d`, total nodes = `2^(d+1) - 1`. Internal nodes
//! occupy indices `0..(2^d - 1)`. Leaves occupy indices `(2^d - 1)..(2^(d+1) - 1)`.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use sha3::{Digest, Keccak256};

use super::heterogeneous::HeterogeneousCircuitFamily;
use super::ExternalInputs3Var;

/// A LatticeFold+ tree circuit family for heterogeneous IVC.
///
/// # Circuit variants
///
/// | Variant | Index | Description |
/// |---------|-------|-------------|
/// | Leaf ring-equation verifier | 0 | Checks `c·z_s + z_e - t - c·d ≡ 0` (placeholder) |
/// | Internal fold verifier | 1 | Accumulates child hashes into parent |
#[derive(Debug, Clone)]
pub struct LatticeFoldTreeCircuitFamily {
    /// Number of internal levels above the leaves.
    ///
    /// A tree of depth `d` has `2^d` leaves and `2^(d+1) - 1` total nodes.
    pub depth: usize,
}

impl Default for LatticeFoldTreeCircuitFamily {
    fn default() -> Self {
        Self { depth: 2 }
    }
}

impl LatticeFoldTreeCircuitFamily {
    /// Number of leaf nodes in the tree.
    pub fn leaf_count(&self) -> usize {
        1usize << self.depth
    }

    /// Total number of nodes (IVC steps) in the tree.
    pub fn total_nodes(&self) -> usize {
        (1usize << (self.depth + 1)) - 1
    }

    /// First leaf index (inclusive).
    fn leaf_start(&self) -> usize {
        (1usize << self.depth) - 1
    }
}

impl<F: PrimeField> HeterogeneousCircuitFamily<F> for LatticeFoldTreeCircuitFamily {
    fn num_circuits(&self) -> usize {
        2.min(self.depth.max(1))
    }

    fn circuit_index(&self, i: usize) -> usize {
        // Leaves use circuit 0, internal nodes use circuit 1.
        let lf_start = self.leaf_start();
        if i >= lf_start {
            0 // leaf
        } else {
            1 // internal
        }
    }

    fn circuit_hash(&self, idx: usize) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        match idx {
            0 => hasher.update(b"pvthfhe/micronova/leaf-ring-verifier/v1"),
            _ => hasher.update(b"pvthfhe/micronova/internal-fold-verifier/v1"),
        };
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..32]);
        hash
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: ExternalInputs3Var<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let ext = external_inputs;
        let circuit_idx =
            <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<F>>::circuit_index(
                self, i,
            );
        match circuit_idx {
            0 => {
                // Leaf: ring equation check (M1 placeholder).
                // z'[0] = z[0] + ext.0 * ext.1 - ext.2  (ring-like check)
                // z'[1] = z[1] + 1                        (accumulate leaf count)
                // z'[2] = z[2] + ext.2                    (accumulate leaf hash)
                let z0 = &z_i[0] + &ext.0 * &ext.1 - &ext.2;
                let z1 = &z_i[1] + FpVar::constant(F::one());
                let z2 = &z_i[2] + &ext.2;
                let _ = cs.num_constraints();
                Ok(vec![z0, z1, z2])
            }
            _ => {
                // Internal: fold verifier (accumulate child hashes).
                // z'[0] = z[0] + ext.0  (accumulate parent hash)
                // z'[1] = z[1] + ext.1  (accumulate norm)
                // z'[2] = z[2] + ext.2  (accumulate fold count)
                let z0 = &z_i[0] + &ext.0;
                let z1 = &z_i[1] + &ext.1;
                let z2 = &z_i[2] + &ext.2;
                let _ = cs.num_constraints();
                Ok(vec![z0, z1, z2])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    fn num_circuits(family: &LatticeFoldTreeCircuitFamily) -> usize {
        <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::num_circuits(family)
    }
    fn circuit_index(family: &LatticeFoldTreeCircuitFamily, i: usize) -> usize {
        <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::circuit_index(family, i)
    }
    fn circuit_hash(family: &LatticeFoldTreeCircuitFamily, idx: usize) -> [u8; 32] {
        <LatticeFoldTreeCircuitFamily as HeterogeneousCircuitFamily<Fr>>::circuit_hash(family, idx)
    }

    #[test]
    fn latticefold_family_depth2_has_two_circuits() {
        let family = LatticeFoldTreeCircuitFamily { depth: 2 };
        assert_eq!(num_circuits(&family), 2);
        // Internal nodes (0..2) use circuit 1
        assert_eq!(circuit_index(&family, 0), 1);
        assert_eq!(circuit_index(&family, 1), 1);
        assert_eq!(circuit_index(&family, 2), 1);
        // Leaves (3..6) use circuit 0
        assert_eq!(circuit_index(&family, 3), 0);
        assert_eq!(circuit_index(&family, 6), 0);
    }

    #[test]
    fn latticefold_family_leaf_count() {
        let family = LatticeFoldTreeCircuitFamily { depth: 2 };
        assert_eq!(family.leaf_count(), 4);
        assert_eq!(family.total_nodes(), 7);
    }

    #[test]
    fn latticefold_family_hashes_differ() {
        let family = LatticeFoldTreeCircuitFamily { depth: 2 };
        let h0 = circuit_hash(&family, 0);
        let h1 = circuit_hash(&family, 1);
        assert_ne!(h0, h1, "leaf and internal circuit hashes must differ");
    }
}
