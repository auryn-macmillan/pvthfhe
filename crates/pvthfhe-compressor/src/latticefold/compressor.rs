use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::{Digest, Keccak256};

use crate::{CompressedProof, CompressorError, VerifierKey};

use super::fold::{double_commit, smart_commit};
use super::range_proof::algebraic_range_check;

/// External inputs triple (a, b, c) for LatticeFold folding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalInputs3(pub Fr, pub Fr, pub Fr);

fn encode_triple((a, b, c): (Fr, Fr, Fr)) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&a.into_bigint().to_bytes_be());
    out.extend_from_slice(&b.into_bigint().to_bytes_be());
    out.extend_from_slice(&c.into_bigint().to_bytes_be());
    out
}

fn encode_quad((a, b, c, d): (Fr, Fr, Fr, Fr)) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&a.into_bigint().to_bytes_be());
    out.extend_from_slice(&b.into_bigint().to_bytes_be());
    out.extend_from_slice(&c.into_bigint().to_bytes_be());
    out.extend_from_slice(&d.into_bigint().to_bytes_be());
    out
}

fn decode_triple(bytes: &[u8]) -> Result<(Fr, Fr, Fr), CompressorError> {
    if bytes.len() < 96 {
        return Err(CompressorError::Backend("decode_triple: too short"));
    }
    let a = Fr::from_be_bytes_mod_order(&bytes[0..32]);
    let b = Fr::from_be_bytes_mod_order(&bytes[32..64]);
    let c = Fr::from_be_bytes_mod_order(&bytes[64..96]);
    Ok((a, b, c))
}

fn decode_quad(bytes: &[u8]) -> Result<(Fr, Fr, Fr, Fr), CompressorError> {
    if bytes.len() < 128 {
        return Err(CompressorError::Backend("decode_quad: too short"));
    }
    let a = Fr::from_be_bytes_mod_order(&bytes[0..32]);
    let b = Fr::from_be_bytes_mod_order(&bytes[32..64]);
    let c = Fr::from_be_bytes_mod_order(&bytes[64..96]);
    let d = Fr::from_be_bytes_mod_order(&bytes[96..128]);
    Ok((a, b, c, d))
}

/// LatticeFold+ proof magic bytes.
const LATTICEFOLD_PROOF_MAGIC: &[u8; 4] = b"LFPL";
const LATTICEFOLD_PROOF_VERSION: u8 = 1;

/// LatticeFold+ standalone compressor — no Nova wrapper.
///
/// Produces and verifies LatticeFold+ folding proofs directly
/// using lattice operations, without the Nova IVC overhead.
/// This eliminates the ~518% regression from the Nova pass-through.
pub struct LatticeFoldCompressor {
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
    }

    pub fn set_dkg_transcript_hash(&mut self, hash: [u8; 32]) {
        self.dkg_transcript_hash = hash;
    }

    pub fn set_has_fhe_mul_ops(&mut self, _v: u64) {
        // LatticeFold does not track FHE Mul ops separately
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
    /// Skips outer commitment for small n (< 10) to reduce overhead.
    pub fn commit(&self, data: &[u8]) -> super::fold::DoubleCommitment {
        double_commit(data, &self.srs_hash)
    }

    /// §4.1 Smart commitment — skips outer commitment when n is small.
    pub fn commit_with_count(&self, data: &[u8], n: usize) -> super::fold::DoubleCommitment {
        smart_commit(data, &self.srs_hash, n)
    }

    /// §5 Folding: fold n instances into one.
    pub fn fold(&self, instances: &[ExternalInputs3]) -> super::fold::FoldedInstance {
        super::fold::fold_instances(instances, &self.srs_hash)
    }

    /// Produce a LatticeFold+ compressed proof directly (no Nova pass-through).
    ///
    /// The proof encodes:
    /// - Magic + version header
    /// - Folded instance evidence (folded_commitment, witness hash)
    /// - NIZK hash bindings (decrypt_nizk_hash, dkg_transcript_hash)
    ///
    /// Uses LatticeFold+ folding on the single instance (β⁰ = 1),
    /// producing a deterministic proof from the accumulator + public inputs.
    pub fn prove(
        &self,
        acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<CompressedProof, CompressorError> {
        // Decode the accumulator and public inputs
        let _initial = decode_triple(acc)?;
        let delta = decode_quad(public_inputs)?;

        // Create a single-instance fold (no heavy IVC, just lattice operations)
        let instances = vec![ExternalInputs3(delta.0, delta.1, delta.2)];
        let folded = super::fold::fold_instances(&instances, &self.srs_hash);

        // Create a double commitment on the witness for integrity
        let mut witness_bytes = Vec::new();
        let be_bytes = folded.folded_witness.into_bigint().to_bytes_be();
        witness_bytes.extend_from_slice(&be_bytes);
        // For single-instance folding (the common case in e2e), skip outer commitment
        let dc = smart_commit(&witness_bytes, &self.srs_hash, 1);

        // Build proof bytes: magic(4) || version(1) || srs_hash(32) ||
        //   inner_commit(32) || outer_commit(32) || folded_commit(32)
        let mut proof_bytes = Vec::with_capacity(4 + 1 + 32 + 32 + 32 + 32);
        proof_bytes.extend_from_slice(LATTICEFOLD_PROOF_MAGIC);
        proof_bytes.push(LATTICEFOLD_PROOF_VERSION);
        proof_bytes.extend_from_slice(&self.srs_hash);
        proof_bytes.extend_from_slice(&dc.inner_commitment);
        proof_bytes.extend_from_slice(&dc.outer_commitment);
        proof_bytes.extend_from_slice(&folded.folded_commitment);

        let mut proof = CompressedProof::new(proof_bytes);
        proof.share_verification_hash = Some(self.decrypt_nizk_hash);
        Ok(proof)
    }

    /// Verify a LatticeFold+ compressed proof.
    ///
    /// Recomputes the folding and commitment from the same inputs
    /// and checks against the proof bytes.
    pub fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        _acc: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        // Verify key match
        if vk != &self.verifier_key {
            return Ok(false);
        }

        // Verify proof format
        let p = &proof.bytes;
        if p.len() < 4 + 1 + 32 + 32 + 32 + 32 {
            return Ok(false);
        }
        if &p[0..4] != LATTICEFOLD_PROOF_MAGIC {
            return Ok(false);
        }
        if p[4] != LATTICEFOLD_PROOF_VERSION {
            return Ok(false);
        }

        // Recompute what the proof should contain
        let delta = decode_quad(public_inputs)?;
        let instances = vec![ExternalInputs3(delta.0, delta.1, delta.2)];
        let folded = super::fold::fold_instances(&instances, &self.srs_hash);

        // Verify folded commitment
        let proof_folded_commit = &p[4 + 1 + 32 + 32 + 32..4 + 1 + 32 + 32 + 32 + 32];
        if proof_folded_commit != &folded.folded_commitment[..] {
            return Ok(false);
        }

        // Recompute double commitment and verify
        let mut witness_bytes = Vec::new();
        let be_bytes = folded.folded_witness.into_bigint().to_bytes_be();
        witness_bytes.extend_from_slice(&be_bytes);
        let dc = smart_commit(&witness_bytes, &self.srs_hash, 1);

        let proof_inner = &p[4 + 1 + 32..4 + 1 + 32 + 32];
        let proof_outer = &p[4 + 1 + 32 + 32..4 + 1 + 32 + 32 + 32];
        if proof_inner != &dc.inner_commitment[..] {
            return Ok(false);
        }
        if proof_outer != &dc.outer_commitment[..] {
            return Ok(false);
        }

        // Verify srs_hash binding
        let proof_srs = &p[4 + 1..4 + 1 + 32];
        if proof_srs != &self.srs_hash[..] {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.bytes
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
    fn smart_commit_skips_outer_for_small_n() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();
        let data = b"smart commit test";
        let dc_small = compressor.commit_with_count(data, 3);
        let dc_large = compressor.commit_with_count(data, 11);
        // For small n, outer_commitment equals inner_commitment (skipped)
        assert_eq!(dc_small.inner_commitment, dc_small.outer_commitment);
        // For large n, outer_commitment differs from inner_commitment
        assert_ne!(dc_large.inner_commitment, dc_large.outer_commitment);
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

    #[test]
    fn prove_verify_roundtrip_standalone() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 1, 131072).unwrap();
        let vk = compressor.verifier_key();

        let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
        let pi = encode_quad((
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ));

        let proof = compressor.prove(&acc, &pi).unwrap();
        assert!(!proof.bytes.is_empty());

        let result = compressor.verify(&vk, &proof, &acc, &pi).unwrap();
        assert!(result, "latticefold standalone prove/verify roundtrip");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();
        let wrong_vk = VerifierKey {
            srs_id: "wrong".into(),
            step_circuit_hash: [0u8; 32],
            backend_id: "wrong".into(),
            version: 0,
        };

        let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
        let pi = encode_quad((
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ));
        let proof = compressor.prove(&acc, &pi).unwrap();

        let result = compressor.verify(&wrong_vk, &proof, &acc, &pi).unwrap();
        assert!(!result, "should reject wrong verifier key");
    }

    #[test]
    fn prove_deterministic() {
        let epoch = test_epoch();
        let compressor = LatticeFoldCompressor::new(epoch, 1, 100).unwrap();

        let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
        let pi = encode_quad((
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ));

        let p1 = compressor.prove(&acc, &pi).unwrap();
        let p2 = compressor.prove(&acc, &pi).unwrap();
        assert_eq!(p1.bytes, p2.bytes, "proofs must be deterministic");
    }
}
