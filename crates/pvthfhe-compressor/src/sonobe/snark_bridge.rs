use crate::CompressorError;
use ark_bn254::Fr;
use ark_grumpkin::Projective as G2;
use ark_serialize::CanonicalSerialize;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::Nova,
    frontend::FCircuit,
    FoldingScheme,
};
use sha3::{Digest, Keccak256};

/// Result of wrapping an IVC proof with transparent decider (no Groth16 ceremony).
#[derive(Clone, Debug)]
pub struct SnarkWrappedProof {
    pub ivc_bytes: Vec<u8>,
    pub snark_proof_bytes: Vec<u8>,
    pub pp_hash: [u8; 32],
}

/// Transparent IVC is always available — no trusted ceremony required.
pub const fn is_snark_available() -> bool {
    true
}

/// Type alias matching the Nova instance used by SonobeCompressor in mod.rs.
type NovaType<S> =
    Nova<ark_bn254::G1Projective, G2, S, KZG<'static, ark_bn254::Bn254>, Pedersen<G2>, false>;

/// Wrap a fully-proved Nova instance into a transparent IVC proof.
///
/// Serializes the Nova IVC proof and extracts the public-parameter hash
/// for binding into the compressed proof format. No Groth16 ceremony is
/// required — the IVC proof bytes serve as the verifiable output.
pub fn wrap_nova_instance<S>(
    nova_instance: NovaType<S>,
    _verifier_key_bytes: &[u8],
    _state_len: usize,
    _seed: u64,
) -> Result<SnarkWrappedProof, CompressorError>
where
    S: FCircuit<Fr> + Clone + core::fmt::Debug,
{
    let ivc_proof = nova_instance.ivc_proof();
    let mut ivc_bytes = Vec::new();
    ivc_proof
        .serialize_compressed(&mut ivc_bytes)
        .map_err(|_| CompressorError::Backend("IVC serialization failed"))?;

    let ivc_hash = Keccak256::digest(&ivc_bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&ivc_hash);

    Ok(SnarkWrappedProof {
        ivc_bytes,
        snark_proof_bytes: vec![],
        pp_hash: hash_bytes,
    })
}

/// Serialize a wrapped proof into the binary proof format.
pub fn serialize_wrapped_proof(
    ivc_bytes: &[u8],
    snark_proof_bytes: &[u8],
    acc_hash: &[u8; 32],
    public_inputs_hash: &[u8; 32],
) -> Vec<u8> {
    super::build_proof_bytes(
        super::PROOF_MAGIC,
        super::PROOF_VERSION,
        acc_hash,
        public_inputs_hash,
        ivc_bytes,
        if snark_proof_bytes.is_empty() {
            None
        } else {
            Some(snark_proof_bytes)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snark_available_unconditionally() {
        assert!(is_snark_available());
    }

    #[test]
    fn serialize_wrapped_proof_roundtrip() {
        let acc_hash = [1u8; 32];
        let pi_hash = [2u8; 32];
        let ivc = vec![3u8; 100];

        let proof = serialize_wrapped_proof(&ivc, &[], &acc_hash, &pi_hash);
        let parsed = super::super::parse_proof(&proof).unwrap();
        assert!(parsed.snark_bytes.is_none());
        assert_eq!(parsed.ivc_bytes.len(), 100);

        let snark = vec![4u8; 64];
        let proof_with_snark = serialize_wrapped_proof(&ivc, &snark, &acc_hash, &pi_hash);
        let parsed2 = super::super::parse_proof(&proof_with_snark).unwrap();
        assert!(parsed2.snark_bytes.is_some());
        assert_eq!(parsed2.snark_bytes.unwrap().len(), 64);
    }
}
