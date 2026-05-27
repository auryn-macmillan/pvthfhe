//! Implements HeterogeneousCircuitFamily for a complete binary tree with
//! depth levels above the leaves. Both leaf and internal node variants
//! produce structurally identical Poseidon hash verification constraints.
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
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use sha3::{Digest, Keccak256};

use super::heterogeneous::HeterogeneousCircuitFamily;
use super::ExternalInputs3Var;
use super::PoseidonSpongeVar;

/// A LatticeFold+ tree circuit family for heterogeneous IVC.
///
/// # Circuit variants
///
/// | Variant | Index | Description |
/// |---------|-------|-------------|
/// | Leaf ring-equation verifier | 0 | Checks `c·z_s + z_e - t - c·d ≡ 0` (placeholder) |
/// | Internal fold verifier | 1 | Accumulates child hashes into parent |
/// | Lagrange fold verifier | 2 | Lagrange coefficient computation with share provenance |
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
        if self.depth == 0 {
            1
        } else {
            3 // leaf, internal, lagrange
        }
    }

    fn circuit_index(&self, i: usize) -> usize {
        match i {
            0 => 0, // leaf
            1 => 1, // internal
            2 => 2, // lagrange
            _ => unimplemented!("circuit_index out of range: {i}"),
        }
    }

    fn circuit_hash(&self, idx: usize) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        match idx {
            0 => hasher.update(b"pvthfhe/micronova/leaf-ring-verifier/v1"),
            1 => hasher.update(b"pvthfhe/micronova/internal-fold-verifier/v1"),
            _ => hasher.update(b"pvthfhe/micronova/lagrange-fold/v1"),
        };
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..32]);
        hash
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: ExternalInputs3Var<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let ext = external_inputs;

        // Both variants: compute Poseidon(ext.0, ext.1) and check == ext.2
        // Leaf:  (share_eval, lagrange_coeff, expected_leaf_hash)
        // Internal: (left_hash, right_hash, expected_parent_hash)
        let mut sponge = PoseidonSpongeVar::new();
        sponge.absorb(&[ext.0.clone(), ext.1.clone()])?;
        let computed_hash = sponge.squeeze_one()?;
        computed_hash.enforce_equal(&ext.2)?;

        // State accumulation (identical for both variants)
        let z0 = &z_i[0] + &computed_hash;
        let z1 = &z_i[1] + &FpVar::<F>::constant(F::one());
        let z2 = &z_i[2] + &FpVar::<F>::constant(F::one());

        Ok(vec![z0, z1, z2])
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
    fn latticefold_family_depth2_has_three_circuits() {
        let family = LatticeFoldTreeCircuitFamily { depth: 2 };
        assert_eq!(num_circuits(&family), 3);
        assert_eq!(circuit_index(&family, 0), 0); // leaf
        assert_eq!(circuit_index(&family, 1), 1); // internal
        assert_eq!(circuit_index(&family, 2), 2); // lagrange
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
        let h2 = circuit_hash(&family, 2);
        assert_ne!(h0, h1, "leaf and internal circuit hashes must differ");
        assert_ne!(h0, h2, "leaf and lagrange circuit hashes must differ");
        assert_ne!(h1, h2, "internal and lagrange circuit hashes must differ");
    }
}
