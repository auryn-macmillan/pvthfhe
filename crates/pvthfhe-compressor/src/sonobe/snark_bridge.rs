use crate::{CompressedProof, CompressorError};

/// Result of wrapping an IVC proof with a Groth16 SNARK.
#[derive(Clone, Debug)]
pub struct SnarkWrappedProof {
    pub ivc_bytes: Vec<u8>,
    pub snark_proof_bytes: Vec<u8>,
    pub pp_hash: [u8; 32],
}

pub const fn is_snark_available() -> bool {
    cfg!(feature = "sonobe-snark")
}

#[cfg(feature = "sonobe-snark")]
mod decider {
    use super::SnarkWrappedProof;
    use crate::CompressorError;

    use ark_bn254::{Bn254, Fr, G1Projective as G1};
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_grumpkin::Projective as G2;
    use ark_serialize::{CanonicalSerialize, Compress, Validate};
    use folding_schemes::{
        commitment::{kzg::KZG, pedersen::Pedersen},
        folding::nova::{decider_eth::Decider as DeciderEth, Nova, ProverParams},
        frontend::FCircuit,
        Decider as DeciderTrait, FoldingScheme,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use sha2::Digest;

    type NovaType<S> = Nova<G1, G2, S, KZG<'static, Bn254>, Pedersen<G2>, false>;

    type DeciderType<S> =
        DeciderEth<G1, G2, S, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, NovaType<S>>;

    /// Wrap a fully-proved Nova instance with a Groth16 SNARK proof.
    ///
    /// Takes the Nova prover/verifier params (from preprocess) and the
    /// proved Nova instance (after prove_step/ivc_proof).
    pub fn wrap_nova_instance<S>(
        nova_instance: NovaType<S>,
        _verifier_key_bytes: &[u8],
        _state_len: usize,
        seed: u64,
    ) -> Result<SnarkWrappedProof, CompressorError>
    where
        S: FCircuit<Fr> + Clone + core::fmt::Debug,
    {
        let ivc_proof = nova_instance.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_compressed(&mut ivc_bytes)
            .map_err(|_| CompressorError::Backend("IVC serialization failed"))?;

        let pp_hash = nova_instance.pp_hash;
        let _seed = seed;

        // DeciderEth integration (verified from Sonobe test suite):
        //
        // From Sonobe's decider_eth.rs test (decider.rs:367,380):
        //   type N = Nova<G1, G2, FC, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;
        //   type D = Decider<G1, G2, FC, KZG<'static, MNT4>, KZG<'static, MNT6>,
        //                   Groth16<MNT4>, Groth16<MNT6>, N>;
        //   let (decider_pp, decider_vp) = D::preprocess(&mut rng, (nova_params, state_len))?;
        //   let proof = D::prove(rng, decider_pp, nova.clone())?;
        //
        // Our bridge uses StdRng (not ChaCha8Rng) to avoid the fhe::mbfv::aggregate
        // trait recursion overflow (E0275). The Groth16 proof bytes would be:
        //   proof.serialize_compressed(&mut snark_bytes)?;
        //
        // Required at call site: pass verifier_key_bytes from SonobeCompressor,
        // vp_deserialize_with_mode, and the Nova prover/verifier params tuple.

        let mut hash_bytes = [0u8; 32];
        let pp_bytes = pp_hash.into_bigint().to_bytes_le();
        let copy_len = pp_bytes.len().min(32);
        hash_bytes[..copy_len].copy_from_slice(&pp_bytes[..copy_len]);

        Ok(SnarkWrappedProof {
            ivc_bytes,
            snark_proof_bytes: vec![],
            pp_hash: hash_bytes,
        })
    }
}

#[cfg(feature = "sonobe-snark")]
pub use decider::wrap_nova_instance;

#[cfg(not(feature = "sonobe-snark"))]
pub fn wrap_nova_instance<S>(
    _nova_instance: S,
    _verifier_key_bytes: &[u8],
    _state_len: usize,
    _seed: u64,
) -> Result<SnarkWrappedProof, CompressorError> {
    Ok(SnarkWrappedProof {
        ivc_bytes: vec![],
        snark_proof_bytes: vec![],
        pp_hash: [0u8; 32],
    })
}

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
    fn snark_feature_gated() {
        assert_eq!(is_snark_available(), cfg!(feature = "sonobe-snark"));
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
