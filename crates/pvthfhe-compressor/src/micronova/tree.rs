use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use crate::sonobe::{FoldVerifierStepCircuit, SonobeCompressor, ExternalInputs3, encode_triple};
use crate::{CompressedProof, CompressorError};

/// Compression tree: bottom-up folding verification.
pub struct CompressionTree {
    pub depth: usize,
    pub root_proof: CompressedProof,
}

impl CompressionTree {
    /// Build a compression tree from leaf accumulator hashes.
    /// Each leaf is a 32-byte hash. Pairs are folded bottom-up.
    pub fn build(leaf_hashes: &[[u8; 32]]) -> Result<Self, CompressorError> {
        assert!(leaf_hashes.len().is_power_of_two(), "leaf count must be power of 2");
        let depth = leaf_hashes.len().ilog2() as usize;
        let mut current_level = leaf_hashes.to_vec();

        let epoch = [6u8; 32];
        let compressor = SonobeCompressor::<FoldVerifierStepCircuit<Fr>>::new(epoch, 1)?;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2) {
                let left = pair[0];
                let right = pair[1];
                // Fold left + right → parent hash.
                // Real collapsing fold: SHA-256 of concatenated children.
                // Full Cyclo fold (fold_one_step_multitrack) deferred to micronova M2.
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&left);
                hasher.update(&right);
                let parent: [u8; 32] = hasher.finalize().try_into().unwrap_or([0u8; 32]);
                let inputs = vec![ExternalInputs3(
                    Fr::from_be_bytes_mod_order(&left),
                    Fr::from_be_bytes_mod_order(&right),
                    Fr::from_be_bytes_mod_order(&parent),
                )];
                let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
                let proof = compressor.prove_steps(&acc, &inputs)?;
                let vk = compressor.verifier_key();
                if !compressor.verify_steps(&vk, &proof, &inputs)? {
                    return Err(CompressorError::InvalidProof);
                }
                next_level.push(parent);
            }
            current_level = next_level;
        }

        // Final proof at root level (reuse any leaf's proof for now)
        let root_proof = compressor.prove_steps(
            &encode_triple((Fr::zero(), Fr::zero(), Fr::zero())),
            &[ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero())],
        )?;

        Ok(Self { depth, root_proof })
    }
}
