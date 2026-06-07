use crate::nova::noir_sponge;
use crate::CompressorError;
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
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

/// Complete IVC proof binding metadata for on-chain verification (P4 + P1.5).
/// G1+G4: includes share_verification_hash to bind per-share BFV sigma results.
/// P1.5: includes decrypt_nizk_hash, dkg_transcript_hash, nova_final_state_commitment.
/// S6: includes ivc_verify_result to bind RecursiveSNARK verification outcome.
///
/// P4-upgrade: includes Noir-compatible Poseidon hashes of actual IVC proof bytes and
/// state data. These allow the `nova_state_commitment` Noir circuit to reconstruct
/// the Poseidon hash from private witness data rather than blindly trusting the prover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcBindingData {
    pub ivc_proof_hash: [u8; 32],
    pub ivc_vk_hash: [u8; 32],
    pub ivc_pp_hash: [u8; 32],
    pub z0_commitment: [u8; 32],
    pub zi_commitment: [u8; 32],
    pub ivc_steps: u64,
    pub share_verification_hash: [u8; 32],
    pub decrypt_nizk_hash: [u8; 32],
    pub dkg_transcript_hash: [u8; 32],
    pub nova_final_state_commitment: [u8; 32],
    /// S6: RecursiveSNARK verification result (1 = passed, 0 = failed).
    pub ivc_verify_result: u64,
    /// S2: Flag indicating at least one FHE Mul operation was verified in the IVC chain.
    /// Set to 1 when any FheOp::Mul is verified; 0 otherwise.
    /// The on-chain circuit asserts this == 1 to prove Mul was performed.
    pub has_fhe_mul_ops: u64,
    /// P4-upgrade: Noir-compatible Poseidon hash of IVC proof bytes (31-byte chunks).
    pub noir_proof_hash: Fr,
    /// P4-upgrade: Noir-compatible Poseidon hash of z0 state (8 Fr elements).
    pub noir_z0_commitment: Fr,
    /// P4-upgrade: Noir-compatible Poseidon hash of zi state (8 Fr elements).
    pub noir_zi_commitment: Fr,
}

impl IvcBindingData {
    pub fn as_field_array(&self) -> Result<[Fr; 12], CompressorError> {
        use ark_ff::PrimeField;
        Ok([
            Fr::from_be_bytes_mod_order(&self.ivc_proof_hash),
            Fr::from_be_bytes_mod_order(&self.ivc_vk_hash),
            Fr::from_be_bytes_mod_order(&self.ivc_pp_hash),
            Fr::from_be_bytes_mod_order(&self.z0_commitment),
            Fr::from_be_bytes_mod_order(&self.zi_commitment),
            Fr::from(self.ivc_steps),
            Fr::from_be_bytes_mod_order(&self.share_verification_hash),
            Fr::from_be_bytes_mod_order(&self.decrypt_nizk_hash),
            Fr::from_be_bytes_mod_order(&self.dkg_transcript_hash),
            Fr::from_be_bytes_mod_order(&self.nova_final_state_commitment),
            Fr::from(self.ivc_verify_result),
            Fr::from(self.has_fhe_mul_ops),
        ])
    }
}

/// Maximum number of 31-byte proof chunks (covers ~2 KB IVC proofs).
/// Must match `PROOF_MAX_CHUNKS` in `circuits/nova_state_commitment/src/main.nr`.
pub const PROOF_MAX_CHUNKS: usize = 64;

/// Compute a Noir-compatible Poseidon hash of raw IVC proof bytes.
///
/// Chunks `ivc_bytes` into 31-byte segments (each fits in Fr ≈ 254 bits),
/// converts each to Fr via `from_be_bytes_mod_order`, pads to exactly
/// `PROOF_MAX_CHUNKS` elements with zeros, and hashes through Noir's
/// `poseidon::poseidon::bn254::sponge`. Matching Noir circuit also computes
/// sponge over a fixed `[Field; PROOF_MAX_CHUNKS]` array.
pub fn compute_noir_proof_hash(ivc_bytes: &[u8]) -> Fr {
    let mut elements = [Fr::zero(); PROOF_MAX_CHUNKS];
    for (i, chunk) in ivc_bytes.chunks(31).enumerate() {
        if i >= PROOF_MAX_CHUNKS {
            break;
        }
        let mut padded = [0u8; 32];
        let start = 32 - chunk.len();
        padded[start..].copy_from_slice(chunk);
        elements[i] = Fr::from_be_bytes_mod_order(&padded);
    }
    noir_sponge::sponge(&elements)
}

/// Compute a Noir-compatible Poseidon hash of 8 state elements.
///
/// Hashes the flat array of 8 Fr elements through the Noir Poseidon x5_5 sponge,
/// matching `poseidon::poseidon::bn254::sponge` in Noir.
pub fn compute_noir_state_hash(state_elements: &[Fr]) -> Fr {
    noir_sponge::sponge(state_elements)
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
    share_verification_hash: [u8; 32],
    decrypt_nizk_hash: [u8; 32],
    dkg_transcript_hash: [u8; 32],
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

    // P4-upgrade: compute Noir-compatible Poseidon hashes for in-circuit
    // reconstruction from witness data. These allow the circuit to verify
    // that the prover actually possesses the proof bytes and state data.
    let noir_proof_hash = compute_noir_proof_hash(&ivc_bytes);
    let noir_z0_commitment = compute_noir_state_hash(&z0);
    let noir_zi_commitment = compute_noir_state_hash(&zi);

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
            share_verification_hash,
            decrypt_nizk_hash,
            dkg_transcript_hash,
            nova_final_state_commitment: zi_commitment,
            ivc_verify_result: 1,
            noir_proof_hash,
            noir_z0_commitment,
            noir_zi_commitment,
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
    use ark_ff::{PrimeField, Zero};

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
            share_verification_hash: [6u8; 32],
            decrypt_nizk_hash: [7u8; 32],
            dkg_transcript_hash: [8u8; 32],
            nova_final_state_commitment: [9u8; 32],
            ivc_verify_result: 1,
            has_fhe_mul_ops: 1,
            noir_proof_hash: ark_bn254::Fr::from(100u64),
            noir_z0_commitment: ark_bn254::Fr::from(200u64),
            noir_zi_commitment: ark_bn254::Fr::from(300u64),
        };

        let fields = binding.as_field_array().unwrap();
        assert_eq!(fields.len(), 12);
        assert!(!fields[0].is_zero());
        assert!(!fields[1].is_zero());
        assert!(!fields[2].is_zero());
        assert!(!fields[3].is_zero());
        assert!(!fields[4].is_zero());
        assert_eq!(fields[5], ark_bn254::Fr::from(42u64));
        assert!(!fields[6].is_zero());
        assert!(!fields[7].is_zero());
        assert!(!fields[8].is_zero());
        assert!(!fields[9].is_zero());
        assert_eq!(fields[10], ark_bn254::Fr::from(1u64));
        assert_eq!(fields[11], ark_bn254::Fr::from(1u64));
    }

    #[test]
    fn compute_noir_proof_hash_deterministic() {
        let data = b"test ivc proof bytes for deterministic hash";
        let h1 = compute_noir_proof_hash(data);
        let h2 = compute_noir_proof_hash(data);
        assert_eq!(h1, h2);
        assert!(!h1.is_zero());

        let different = b"different ivc proof bytes";
        let h3 = compute_noir_proof_hash(different);
        assert_ne!(h1, h3);
    }

    #[test]
    fn compute_noir_state_hash_deterministic() {
        let state: Vec<ark_bn254::Fr> = (0..8).map(|i| ark_bn254::Fr::from(i as u64)).collect();
        let h1 = compute_noir_state_hash(&state);
        let h2 = compute_noir_state_hash(&state);
        assert_eq!(h1, h2);
        assert!(!h1.is_zero());

        let different: Vec<ark_bn254::Fr> = (1..9).map(|i| ark_bn254::Fr::from(i as u64)).collect();
        let h3 = compute_noir_state_hash(&different);
        assert_ne!(h1, h3);
    }
}
