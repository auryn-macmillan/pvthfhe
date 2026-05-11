//! Sonobe Nova proof-compressor backend.

use std::fmt::Debug;
use std::fs;

use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use folding_schemes::{
    commitment::pedersen::Pedersen,
    folding::nova::{IVCProof, Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use pvthfhe_domain_tags::Tag;
use pvthfhe_rng::OsRng;
use pvthfhe_types::witness_language::{BfvParameters as SchemaBfvParams, WitnessStatement};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Keccak256};

// R3.0a — schema types wired for R5.2 GREEN migration
const _: () = {
    let _: Option<SchemaBfvParams> = None;
    let _: Option<WitnessStatement> = None;
};

use crate::{CompressedProof, CompressorError, ProofCompressor, StepCircuit, StepCircuitDescriptor, VerifierKey};

const BACKEND_ID: &str = "sonobe-nova-bn254-grumpkin";
const PROOF_MAGIC: [u8; 4] = *b"SNOB";
const PROOF_VERSION: u32 = 1;

type SonobeIvcProof = IVCProof<G1, G2>;

/// Toy step circuit for R4.0 Sonobe IVC stub (z_{i+1} = z_i + ext).
#[derive(Clone, Copy, Debug)]
pub struct ToyStepCircuit<F: PrimeField> {
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

impl<F: PrimeField> StepCircuit for ToyStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 1 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::SonobeToyStep.as_bytes()).into()
    }
}

/// CycloFold step circuit encoding the R4 aggregator fold relation (R5.2).
///
/// State: [accumulated_instance_hash, accumulated_norm, fold_count].
/// Step: folds a new party instance into the accumulated state.
#[derive(Clone, Copy, Debug)]
pub struct CycloFoldStepCircuit<F: PrimeField> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for CycloFoldStepCircuit<F> {
    type Params = ();
    type ExternalInputs = F;
    type ExternalInputsVar = FpVar<F>;

    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _field: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let one = FpVar::<F>::constant(F::from(1u64));

        // Commitment folding: multiplicative fold of accumulated hash with new instance.
        // Allocates a multiplication constraint in cs via the FpVar * operator.
        let folded_hash = z_i[0].clone() * &external_inputs + z_i[0].clone();

        // Norm escalation: additive accumulation of norms from folded instances.
        let escalated_norm = z_i[1].clone() + &external_inputs;

        // Count increment: each fold step advances the counter by 1.
        let count_inc = z_i[2].clone() + one;

        // Touch cs to suppress unused-variable warning (the multiplication above
        // already uses it internally).
        let _ = cs.num_constraints();

        Ok(vec![folded_hash, escalated_norm, count_inc])
    }
}

impl<F: PrimeField> StepCircuit for CycloFoldStepCircuit<F> {
    fn descriptor(&self) -> StepCircuitDescriptor {
        StepCircuitDescriptor { width: 3 }
    }

    fn circuit_hash(&self) -> [u8; 32] {
        Keccak256::digest(Tag::SonobeCycloFold.as_bytes()).into()
    }
}

/// Proof compressor backed by Sonobe Nova over the BN254/Grumpkin cycle.
#[derive(Clone, Debug)]
pub struct SonobeCompressor<S: FCircuit<Fr, Params = (), ExternalInputs = Fr> + StepCircuit + Clone + Debug> {
    prover_key_bytes: Vec<u8>,
    verifier_key_bytes: Vec<u8>,
    verifier_key: VerifierKey,
    ivc_steps: usize,
    state_len: usize,
    srs_hash: [u8; 32],
    _step_circuit: std::marker::PhantomData<S>,
}

type SonobeNova<S> = Nova<G1, G2, S, Pedersen<G1>, Pedersen<G2>, false>;

impl<S: FCircuit<Fr, Params = (), ExternalInputs = Fr> + StepCircuit + Clone + Debug> SonobeCompressor<S> {
    /// Creates a new Sonobe compressor instance bound to an on-chain epoch.
    ///
    /// The SRS is derived deterministically from `epoch_hash`, making it
    /// reproducible by any verifier that knows the current on-chain epoch.
    /// `ivc_steps` sets the number of IVC fold steps (must equal the number
    /// of participating parties).
    pub fn new(epoch_hash: [u8; 32], ivc_steps: usize) -> Result<Self, CompressorError> {
        let circuit = S::new(())
            .map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let circuit_hash = circuit.circuit_hash();
        let state_len = circuit.state_len();

        // Derive SRS hash: H(epoch_hash || SonobeSrs)
        let srs_hash: [u8; 32] = Keccak256::digest(
            &[&epoch_hash[..], Tag::SonobeSrs.as_bytes()].concat(),
        )
        .into();

        // Derive deterministic RNG from epoch_hash for reproducible SRS.
        // allow-seeded-rng: SRS bound to on-chain epoch per R5.3
        let srs_seed: [u8; 32] = Keccak256::digest(
            &[&epoch_hash[..], Tag::SonobeSrs.as_bytes(), b"-seed"].concat(),
        )
        .into();
        let mut rng = ChaCha20Rng::from_seed(srs_seed);

        let params = SonobeNova::<S>::preprocess(
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

        let srs_id = format!(
            "sonobe-srs-{:02x}{:02x}{:02x}{:02x}",
            srs_hash[0], srs_hash[1], srs_hash[2], srs_hash[3],
        );

        let verifier_key = VerifierKey {
            srs_id,
            step_circuit_hash: circuit_hash,
            backend_id: BACKEND_ID.to_string(),
            version: PROOF_VERSION,
        };

        Ok(Self {
            prover_key_bytes,
            verifier_key_bytes,
            verifier_key,
            ivc_steps,
            state_len,
            srs_hash,
            _step_circuit: std::marker::PhantomData,
        })
    }

    /// Returns the structured verifier-key metadata for this backend instance.
    pub fn verifier_key(&self) -> VerifierKey {
        self.verifier_key.clone()
    }

    /// Returns the SRS hash derived from the epoch at construction time.
    /// Used by on-chain verifiers to match the committed SRS for the epoch.
    pub fn srs_hash(&self) -> [u8; 32] {
        self.srs_hash
    }

    /// Returns the number of IVC fold steps configured at construction time.
    pub fn ivc_steps(&self) -> usize {
        self.ivc_steps
    }

    fn deserialize_params(
        &self,
    ) -> Result<
        (
            <SonobeNova::<S> as FoldingScheme<G1, G2, S>>::ProverParam,
            <SonobeNova::<S> as FoldingScheme<G1, G2, S>>::VerifierParam,
        ),
        CompressorError,
    > {
        let rss_before = rss_kb();
        tracing::info!(rss_kb = rss_before, "sonobe: deserialize_params start");
        let prover = SonobeNova::<S>::pp_deserialize_with_mode(
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
        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
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

impl<S: FCircuit<Fr, Params = (), ExternalInputs = Fr> + StepCircuit + Clone + Debug> ProofCompressor for SonobeCompressor<S> {
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError> {
        let initial_scalar = decode_scalar(acc)?;
        let delta = decode_scalar(public_inputs)?;
        let params = self.deserialize_params()?;
        let circuit = S::new(())
            .map_err(|_| CompressorError::Backend("sonobe circuit init failed"))?;
        let state_len = circuit.state_len();

        let mut initial_state = Vec::with_capacity(state_len);
        initial_state.push(initial_scalar);
        for _ in 1..state_len {
            initial_state.push(Fr::from(0u64));
        }

        let mut nova = SonobeNova::<S>::init(&params, circuit, initial_state)
            .map_err(|_| CompressorError::Backend("sonobe init failed"))?;
        tracing::info!(rss_kb = rss_kb(), "sonobe: Nova::init done");
        let mut rng = OsRng;

        for step in 0..self.ivc_steps {
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

        if ivc_proof.z_0.len() != self.state_len || ivc_proof.z_i.len() != self.state_len {
            return Ok(false);
        }

        if normalized_hash(&encode_scalar(ivc_proof.z_0[0]))? != parsed.acc_hash {
            return Ok(false);
        }

        let verifier = SonobeNova::<S>::vp_deserialize_with_mode(
            self.verifier_key_bytes.as_slice(),
            Compress::Yes,
            Validate::Yes,
            (),
        )
        .map_err(|_| CompressorError::Backend("sonobe verifier key deserialization failed"))?;

        Ok(SonobeNova::<S>::verify(verifier, ivc_proof).is_ok())
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

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4)
        .unwrap_or(0)
}
