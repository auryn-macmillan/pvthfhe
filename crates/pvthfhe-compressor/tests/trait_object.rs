#![cfg(feature = "legacy-nova")]

use pvthfhe_compressor::{CompressedProof, CompressorError, ProofCompressor, VerifierKey};

struct NoopCompressor {
    vk: Vec<u8>,
}

impl ProofCompressor for NoopCompressor {
    fn prove(
        &self,
        _acc: &[u8],
        _public_inputs: &[u8],
    ) -> Result<CompressedProof, CompressorError> {
        Ok(CompressedProof(vec![0u8; 4]))
    }

    fn verify(
        &self,
        _vk: &VerifierKey,
        _proof: &CompressedProof,
        _public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        Ok(true)
    }

    fn backend_id(&self) -> &str {
        "noop"
    }

    fn vk_bytes(&self) -> &[u8] {
        &self.vk
    }

    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.0
    }
}

#[test]
fn proof_compressor_is_object_safe() {
    let compressor: Box<dyn ProofCompressor> = Box::new(NoopCompressor { vk: vec![1, 2, 3] });
    let vk = VerifierKey {
        srs_id: "test-srs".to_string(),
        step_circuit_hash: [7u8; 32],
        backend_id: compressor.backend_id().to_string(),
        version: 1,
    };
    let proof = compressor.prove(b"acc", b"public").expect("proof");

    assert_eq!(compressor.backend_id(), "noop");
    assert_eq!(compressor.vk_bytes(), &[1, 2, 3]);
    assert_eq!(compressor.compressed_proof_bytes(&proof), &[0, 0, 0, 0]);
    assert!(compressor.verify(&vk, &proof, b"public").expect("verify"));
}
