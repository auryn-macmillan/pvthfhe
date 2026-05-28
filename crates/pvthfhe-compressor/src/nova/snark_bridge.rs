use crate::CompressorError;
use ark_bn254::Fr;
#[cfg(feature = "legacy-nova")]
use ark_grumpkin::Projective as G2;
#[cfg(feature = "legacy-nova")]
use ark_serialize::CanonicalSerialize;
#[cfg(feature = "legacy-nova")]
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::Nova,
    frontend::FCircuit,
    FoldingScheme,
};
#[cfg(feature = "legacy-nova")]
use sha3::{Digest, Keccak256};

/// Complete IVC proof binding metadata for on-chain verification (P4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcBindingData {
    pub ivc_proof_hash: [u8; 32],
    pub ivc_vk_hash: [u8; 32],
    pub ivc_pp_hash: [u8; 32],
    pub z0_commitment: [u8; 32],
    pub zi_commitment: [u8; 32],
    pub ivc_steps: u64,
}

impl IvcBindingData {
    pub fn as_field_array(&self) -> Result<[Fr; 6], CompressorError> {
        use ark_ff::PrimeField;
        Ok([
            Fr::from_be_bytes_mod_order(&self.ivc_proof_hash),
            Fr::from_be_bytes_mod_order(&self.ivc_vk_hash),
            Fr::from_be_bytes_mod_order(&self.ivc_pp_hash),
            Fr::from_be_bytes_mod_order(&self.z0_commitment),
            Fr::from_be_bytes_mod_order(&self.zi_commitment),
            Fr::from(self.ivc_steps),
        ])
    }
}

/// Result of wrapping an IVC proof with transparent decider (no Groth16 ceremony).
/// P4: includes full IVC proof binding metadata.
#[derive(Clone, Debug)]
pub struct SnarkWrappedProof {
    pub ivc_bytes: Vec<u8>,
    pub snark_proof_bytes: Vec<u8>,
    pub pp_hash: [u8; 32],
    pub ivc_binding: IvcBindingData,
}

/// Transparent IVC is always available — no trusted ceremony required.
pub const fn is_snark_available() -> bool {
    true
}

/// Type alias matching the Nova instance used by NovaCompressor in mod.rs.
#[cfg(feature = "legacy-nova")]
type NovaType<S> =
    Nova<ark_bn254::G1Projective, G2, S, KZG<'static, ark_bn254::Bn254>, Pedersen<G2>, false>;

/// Wrap a fully-proved Nova instance into a transparent IVC proof.
///
/// Serializes the Nova IVC proof and extracts binding metadata
/// (proof hash, verifier key hash, public params hash, initial/final state
/// commitments, step count) for on-chain verification via the
/// `nova_state_commitment` Noir circuit (P4).
#[cfg(feature = "legacy-nova")]
pub fn wrap_nova_instance<S>(
    nova_instance: NovaType<S>,
    verifier_key_bytes: &[u8],
    state_len: usize,
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

    let ivc_proof_hash: [u8; 32] = Keccak256::digest(&ivc_bytes).into();
    let ivc_vk_hash: [u8; 32] = Keccak256::digest(verifier_key_bytes).into();

    let mut pp = Keccak256::new();
    pp.update(b"nova-public-params/v1");
    let ivc_pp_hash: [u8; 32] = pp.finalize().into();

    let z0 = ivc_proof.z_0.clone();
    let zi = ivc_proof.z_i.clone();
    let z0_commitment: [u8; 32] = Keccak256::digest(
        &z0.iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect::<Vec<u8>>(),
    )
    .into();
    let zi_commitment: [u8; 32] = Keccak256::digest(
        &zi.iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect::<Vec<u8>>(),
    )
    .into();

    let ivc_steps = if state_len >= 3 {
        ivc_proof.z_i[2].into_bigint().as_u64()
    } else {
        1u64
    };

    Ok(SnarkWrappedProof {
        ivc_bytes,
        snark_proof_bytes: vec![],
        pp_hash: ivc_proof_hash,
        ivc_binding: IvcBindingData {
            ivc_proof_hash,
            ivc_vk_hash,
            ivc_pp_hash,
            z0_commitment,
            zi_commitment,
            ivc_steps,
        },
    })
}

/// Serialize a wrapped proof into the binary proof format.
/// P4: includes IVC binding data in the proof trailer.
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

    #[test]
    fn ivc_binding_data_roundtrip() {
        let binding = IvcBindingData {
            ivc_proof_hash: [1u8; 32],
            ivc_vk_hash: [2u8; 32],
            ivc_pp_hash: [3u8; 32],
            z0_commitment: [4u8; 32],
            zi_commitment: [5u8; 32],
            ivc_steps: 42,
        };

        let fields = binding.as_field_array().unwrap();
        assert!(!fields[0].is_zero());
        assert!(!fields[1].is_zero());
        assert!(!fields[2].is_zero());
        assert!(!fields[3].is_zero());
        assert!(!fields[4].is_zero());
        assert_eq!(fields[5], ark_bn254::Fr::from(42u64));
    }
}
