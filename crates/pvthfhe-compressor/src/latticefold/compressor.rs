use ark_bn254::Fr;
use ark_ff::Zero;
use sha3::{Digest, Keccak256};

use crate::nova::{CycloFoldStepCircuit, ExternalInputs3, NovaCompressor};
use crate::{CompressedProof, CompressorError, VerifierKey};

use super::fold::double_commit;
use super::range_proof::algebraic_range_check;

pub struct LatticeFoldCompressor {
    nova_compressor: NovaCompressor<CycloFoldStepCircuit<Fr>>,
    verifier_key: VerifierKey,
    ivc_steps: usize,
    srs_hash: [u8; 32],
    decrypt_nizk_hash: [u8; 32],
    dkg_transcript_hash: [u8; 32],
    range_proof_bound: u64,
}

impl LatticeFoldCompressor {
    pub fn new(
        epoch_hash: [u8; 32],
        ivc_steps: usize,
        range_proof_bound: u64,
    ) -> Result<Self, CompressorError> {
        let nova_compressor =
            NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch_hash, ivc_steps)?;

        let srs_hash: [u8; 32] =
            Keccak256::digest([&epoch_hash[..], b"latticefold-srs"].concat()).into();

        let circuit_hash = Keccak256::digest(b"latticefold-cyclofold").into();

        let srs_id = format!(
            "latticefold-srs-{:02x}{:02x}{:02x}{:02x}",
            srs_hash[0], srs_hash[1], srs_hash[2], srs_hash[3],
        );

        let verifier_key = VerifierKey {
            srs_id,
            step_circuit_hash: circuit_hash,
            backend_id: "latticefold-plus".to_string(),
            version: 1,
        };

        Ok(Self {
            nova_compressor,
            verifier_key,
            ivc_steps,
            srs_hash,
            decrypt_nizk_hash: [0u8; 32],
            dkg_transcript_hash: [0u8; 32],
            range_proof_bound,
        })
    }

    pub fn verifier_key(&self) -> VerifierKey {
        self.verifier_key.clone()
    }

    pub fn srs_hash(&self) -> [u8; 32] {
        self.srs_hash
    }

    pub fn ivc_steps(&self) -> usize {
        self.ivc_steps
    }

    pub fn set_decrypt_nizk_hash(&mut self, hash: [u8; 32]) {
        self.decrypt_nizk_hash = hash;
        self.nova_compressor.set_decrypt_nizk_hash(hash);
    }

    pub fn set_dkg_transcript_hash(&mut self, hash: [u8; 32]) {
        self.dkg_transcript_hash = hash;
        self.nova_compressor.set_dkg_transcript_hash(hash);
    }

    /// §4.3 Algebraic range proof — proves |w| ≤ B without bit decomposition.
    pub fn verify_norm_bound(&self, witness_value: u64, bound: u64) -> bool {
        let challenge = {
            let mut h = Keccak256::new();
            h.update(b"latticefold-norm-challenge-v1");
            h.update(&self.srs_hash);
            h.finalize().into()
        };
        algebraic_range_check(witness_value, bound, &challenge)
    }

    /// §4.1 Double commitment of inner data.
    pub fn commit(&self, data: &[u8]) -> super::fold::DoubleCommitment {
        double_commit(data, &self.srs_hash)
    }

    /// §5 Folding: fold n instances into one.
    pub fn fold(&self, instances: &[ExternalInputs3<Fr>]) -> super::fold::FoldedInstance {
        super::fold::fold_instances(instances, &self.srs_hash)
    }

    pub fn prove(
        &self,
        acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<CompressedProof, CompressorError> {
        self.nova_compressor.prove(acc, public_inputs)
    }

    pub fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        let nova_vk = self.nova_compressor.verifier_key();
        self.nova_compressor
            .verify(&nova_vk, proof, acc, public_inputs)
    }

    pub fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.bytes
    }

    pub fn inner_nova(&self) -> &NovaCompressor<CycloFoldStepCircuit<Fr>> {
        &self.nova_compressor
    }

    pub fn set_range_proof_bound(&mut self, bound: u64) {
        self.range_proof_bound = bound;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> [u8; 32] {
        Keccak256::digest(b"test-epoch").into()
    }

    #[test]
    fn latticefold_compressor_new() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 3, 131072);
        assert!(compressor.is_ok());
    }

    #[test]
    fn latticefold_compressor_norm_bound() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();
        assert!(compressor.verify_norm_bound(50, 100));
        assert!(compressor.verify_norm_bound(0, 100));
        assert!(compressor.verify_norm_bound(100, 100));
        assert!(!compressor.verify_norm_bound(101, 100));
    }

    #[test]
    fn latticefold_compressor_verifier_key() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 5, 131072).unwrap();
        let vk = compressor.verifier_key();
        assert_eq!(vk.backend_id, "latticefold-plus");
    }

    #[test]
    fn latticefold_srs_hash_deterministic() {
        let epoch = test_epoch();
        let c1 = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();
        let c2 = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();
        assert_eq!(c1.srs_hash(), c2.srs_hash());
    }

    #[test]
    fn double_commit_roundtrip() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();
        let data = b"test commitment data";
        let dc = compressor.commit(data);
        assert!(super::super::fold::verify_double_commitment(
            &dc,
            data,
            &compressor.srs_hash()
        ));
    }

    #[test]
    fn fold_instances_via_compressor() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 3, 100).unwrap();
        let instances = vec![
            ExternalInputs3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)),
            ExternalInputs3(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)),
        ];
        let folded = compressor.fold(&instances);
        assert!(super::super::fold::verify_folded_instance(
            &folded,
            &instances,
            &compressor.srs_hash()
        ));
    }
}
