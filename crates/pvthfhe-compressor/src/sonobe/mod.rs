//! Sonobe Nova proof-compressor backend.

use std::fmt::Debug;
use std::fs;

use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use folding_schemes::{
    commitment::pedersen::Pedersen,
    folding::nova::{IVCProof, Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Keccak256};

use crate::{CompressedProof, CompressorError, ProofCompressor, VerifierKey};

const BACKEND_ID: &str = "sonobe-nova-bn254-grumpkin";
const PROOF_MAGIC: [u8; 4] = *b"SNOB";
const PROOF_VERSION: u32 = 1;
const IVC_STEPS: usize = 4;
const SRS_ID: &str = "sonobe-pedersen-test-srs";
const STEP_CIRCUIT_TAG: &[u8] = b"pvthfhe/sonobe/toy-step/v1";

type SonobeNova = Nova<G1, G2, ToyStepCircuit<Fr>, Pedersen<G1>, Pedersen<G2>, false>;
type SonobeIvcProof = IVCProof<G1, G2>;

#[derive(Clone, Copy, Debug)]
struct ToyStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for ToyStepCircuit<F> {
    type Params = ();
    type ExternalInputs = F;
    type ExternalInputsVar = FpVar<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _field: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![z_i[0].clone() + external_inputs])
    }
}

/// Proof compressor backed by Sonobe Nova over the BN254/Grumpkin cycle.
#[derive(Clone, Debug)]
pub struct SonobeCompressor {
    seed: u64,
    prover_key_bytes: Vec<u8>,
    verifier_key_bytes: Vec<u8>,
    verifier_key: VerifierKey,
}

impl SonobeCompressor {
    /// Creates a new deterministic Sonobe compressor instance for a fixed seed.
    pub fn new(seed: u64) -> Result<Self, CompressorError> {
        let circuit = ToyStepCircuit::<Fr>::new(())
            .map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let params = SonobeNova::preprocess(
            &mut rng,
            &PreprocessorParam::new(poseidon_canonical_config::<Fr>(), circuit),
        )
        .map_err(|_| CompressorError::Backend("sonobe preprocess failed"))?;

        let mut prover_key_bytes = Vec::new();
        params
            .0
            .serialize_with_mode(&mut prover_key_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe prover key serialization failed"))?;

        let mut verifier_key_bytes = Vec::new();
        params
            .1
            .serialize_with_mode(&mut verifier_key_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe verifier key serialization failed"))?;

        tracing::info!(
            prover_key_bytes_len = prover_key_bytes.len(),
            verifier_key_bytes_len = verifier_key_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: params serialized"
        );

        let verifier_key = VerifierKey {
            srs_id: SRS_ID.to_string(),
            step_circuit_hash: step_circuit_hash(),
            backend_id: BACKEND_ID.to_string(),
            version: PROOF_VERSION,
        };

        Ok(Self {
            seed,
            prover_key_bytes,
            verifier_key_bytes,
            verifier_key,
        })
    }

    /// Returns the structured verifier-key metadata for this backend instance.
    pub fn verifier_key(&self) -> VerifierKey {
        self.verifier_key.clone()
    }

    fn deserialize_params(
        &self,
    ) -> Result<
        (
            <SonobeNova as FoldingScheme<G1, G2, ToyStepCircuit<Fr>>>::ProverParam,
            <SonobeNova as FoldingScheme<G1, G2, ToyStepCircuit<Fr>>>::VerifierParam,
        ),
        CompressorError,
    > {
        let rss_before = rss_kb();
        tracing::info!(rss_kb = rss_before, "sonobe: deserialize_params start");
        let prover = SonobeNova::pp_deserialize_with_mode(
            self.prover_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe prover key deserialization failed"))?;
        tracing::info!(
            rss_kb = rss_kb(),
            rss_delta_kb = rss_kb().saturating_sub(rss_before),
            "sonobe: pp_deserialize done"
        );
        let verifier = SonobeNova::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;
        tracing::info!(
            rss_kb = rss_kb(),
            rss_delta_kb = rss_kb().saturating_sub(rss_before),
            "sonobe: vp_deserialize done"
        );
        Ok((prover, verifier))
    }
}

impl ProofCompressor for SonobeCompressor {
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError> {
        let initial_state = decode_scalar(acc)?;
        let delta = decode_scalar(public_inputs)?;
        let params = self.deserialize_params()?;
        let circuit = ToyStepCircuit::<Fr>::new(())
            .map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let mut nova = SonobeNova::init(&params, circuit, vec![initial_state])
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        tracing::info!(rss_kb = rss_kb(), "sonobe: Nova::init done");
        let mut rng = ChaCha20Rng::seed_from_u64(self.seed);

        for step in 0..IVC_STEPS {
            nova.prove_step(&mut rng, delta, None)
                .map_err(|_| CompressorError::Backend("sonobe prove step failed"))?;
            tracing::info!(step = step, rss_kb = rss_kb(), "sonobe: prove_step done");
        }

        let ivc_proof = nova.ivc_proof();
        let mut ivc_bytes = Vec::new();
        ivc_proof
            .serialize_with_mode(&mut ivc_bytes, Compress::Yes)
            .map_err(|_| CompressorError::Backend("sonobe proof serialization failed"))?;
        tracing::info!(
            ivc_bytes_len = ivc_bytes.len(),
            rss_kb = rss_kb(),
            "sonobe: ivc proof serialized"
        );

        let mut proof_bytes = Vec::with_capacity(76 + ivc_bytes.len());
        proof_bytes.extend_from_slice(&PROOF_MAGIC);
        proof_bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        proof_bytes.extend_from_slice(&normalized_hash(acc)?);
        proof_bytes.extend_from_slice(&normalized_hash(public_inputs)?);
        proof_bytes.extend_from_slice(&(ivc_bytes.len() as u32).to_be_bytes());
        proof_bytes.extend_from_slice(&ivc_bytes);
        Ok(CompressedProof(proof_bytes))
    }

    fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError> {
        if vk != &self.verifier_key {
            return Ok(false);
        }

        let parsed = parse_proof(&proof.0)?;
        if parsed.public_inputs_hash != normalized_hash(public_inputs)? {
            return Ok(false);
        }

        let ivc_proof =
            SonobeIvcProof::deserialize_with_mode(parsed.ivc_bytes, Compress::Yes, Validate::Yes)
                .map_err(|_| CompressorError::InvalidProof)?;

        if ivc_proof.z_0.len() != 1 || ivc_proof.z_i.len() != 1 {
            return Ok(false);
        }

        if normalized_hash(&encode_scalar(ivc_proof.z_0[0]))? != parsed.acc_hash {
            return Ok(false);
        }

        let delta = decode_scalar(public_inputs)?;
        let expected_state = ivc_proof.z_0[0] + repeated_sum(delta, IVC_STEPS);
        if ivc_proof.z_i[0] != expected_state {
            return Ok(false);
        }

        let verifier = SonobeNova::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        Ok(SonobeNova::verify(verifier, ivc_proof).is_ok())
    }

    fn backend_id(&self) -> &str {
        BACKEND_ID
    }

    fn vk_bytes(&self) -> &[u8] {
        &self.verifier_key_bytes
    }

    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8] {
        &proof.0
    }
}

struct ParsedProof<'a> {
    acc_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
    ivc_bytes: &'a [u8],
}

fn parse_proof(bytes: &[u8]) -> Result<ParsedProof<'_>, CompressorError> {
    if bytes.len() < 76 || bytes[0..4] != PROOF_MAGIC {
        return Err(CompressorError::InvalidProof);
    }

    let version = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| CompressorError::InvalidProof)?,
    );
    if version != PROOF_VERSION {
        return Err(CompressorError::InvalidProof);
    }

    let acc_hash = bytes[8..40]
        .try_into()
        .map_err(|_| CompressorError::InvalidProof)?;
    let public_inputs_hash = bytes[40..72]
        .try_into()
        .map_err(|_| CompressorError::InvalidProof)?;
    let ivc_len = u32::from_be_bytes(
        bytes[72..76]
            .try_into()
            .map_err(|_| CompressorError::InvalidProof)?,
    ) as usize;
    if bytes.len() != 76 + ivc_len {
        return Err(CompressorError::InvalidProof);
    }

    Ok(ParsedProof {
        acc_hash,
        public_inputs_hash,
        ivc_bytes: &bytes[76..],
    })
}

fn decode_scalar(bytes: &[u8]) -> Result<Fr, CompressorError> {
    if bytes.is_empty() {
        return Err(CompressorError::InvalidInput);
    }
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

fn encode_scalar(value: Fr) -> Vec<u8> {
    let mut bytes = value.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    bytes
}

fn normalized_hash(bytes: &[u8]) -> Result<[u8; 32], CompressorError> {
    let scalar = decode_scalar(bytes)?;
    Ok(Keccak256::digest(encode_scalar(scalar)).into())
}

fn repeated_sum(delta: Fr, count: usize) -> Fr {
    (0..count).fold(Fr::from(0u64), |acc, _| acc + delta)
}

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4)
        .unwrap_or(0)
}

fn step_circuit_hash() -> [u8; 32] {
    Keccak256::digest(STEP_CIRCUIT_TAG).into()
}
