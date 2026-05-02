//! Recursive aggregation harness for folding N party proofs into a single final SNARK.
//! 
//! Note: Full LatticeFold+/HyperNova/MicroNova over RLWE is an open research problem (P2).
//! This implementation provides a simulated folding harness that uses a hash-chain 
//! accumulation as a surrogate for real folding.

use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FoldingError {
    #[error("Invalid leaf proof for party {0}")]
    InvalidLeaf(u32),
}

#[derive(Debug, Clone)]
pub struct PartyProof {
    pub party_id: u32,
    pub share_hash: [u8; 32],
    pub nizk_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FinalSnark {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
    pub prover_time_ms: u64,
    pub proof_size_bytes: usize,
}

pub struct FoldingAccumulator {
    proofs: Vec<PartyProof>,
}

impl Default for FoldingAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl FoldingAccumulator {
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
    }

    pub fn add_proof(&mut self, proof: PartyProof) -> Result<(), FoldingError> {
        self.proofs.push(proof);
        Ok(())
    }

    pub fn finalize(&self) -> Result<FinalSnark, FoldingError> {
        let mut hasher = Sha256::new();
        let mut public_inputs = Vec::with_capacity(self.proofs.len());
        
        let start_time = std::time::Instant::now();
        
        for proof in &self.proofs {
            if proof.nizk_bytes.is_empty() {
                return Err(FoldingError::InvalidLeaf(proof.party_id));
            }
            hasher.update(&proof.share_hash);
            hasher.update(&proof.nizk_bytes);
            public_inputs.push(proof.share_hash);
        }
        
        let hash = hasher.finalize();
        let proof_bytes = hash.to_vec();
        
        let prover_time_ms = start_time.elapsed().as_millis() as u64;
        let proof_size_bytes = proof_bytes.len();
        
        Ok(FinalSnark {
            proof_bytes,
            public_inputs,
            prover_time_ms,
            proof_size_bytes,
        })
    }
}
