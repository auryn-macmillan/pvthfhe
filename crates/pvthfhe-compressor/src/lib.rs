//! Frozen trait surface for the P2→P3 proof-compression boundary.

/// Sonobe-backed proof compressor implementation.
pub mod sonobe;

/// Opaque compressed-proof bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedProof(pub Vec<u8>);

/// Shared verifier-key metadata for proof-compression backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierKey {
    /// Structured reference string identifier.
    pub srs_id: String,
    /// Hash of the frozen step-circuit shape.
    pub step_circuit_hash: [u8; 32],
    /// Stable backend identifier.
    pub backend_id: String,
    /// Version of the verifier-key encoding.
    pub version: u32,
}

/// Minimal step-circuit descriptor shared across compressor backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepCircuitDescriptor {
    /// Input/output state width for one step.
    pub width: usize,
}

/// Marker trait for backend-agnostic step-circuit shapes.
pub trait StepCircuit {
    /// Returns the frozen state width for this step circuit.
    fn descriptor(&self) -> StepCircuitDescriptor;
}

/// Errors returned by compressor implementations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompressorError {
    /// Input bytes do not satisfy the backend contract.
    InvalidInput,
    /// Proof bytes failed backend verification.
    InvalidProof,
    /// Backend-specific failure surfaced as a static message.
    Backend(&'static str),
}

/// Setup artifacts exported by a proof-compression backend.
pub trait CompressorSetup {
    /// Serialized prover key bytes.
    fn prover_key_bytes(&self) -> &[u8];

    /// Serialized verifier key bytes.
    fn verifier_key_bytes(&self) -> &[u8];

    /// Structured reference string identifier.
    fn srs_id(&self) -> &str;
}

/// Frozen backend boundary for proof compression.
pub trait ProofCompressor {
    /// Compresses accumulator bytes and public inputs into a proof object.
    fn prove(&self, acc: &[u8], public_inputs: &[u8]) -> Result<CompressedProof, CompressorError>;

    /// Verifies a compressed proof against the verifier key and public inputs.
    fn verify(
        &self,
        vk: &VerifierKey,
        proof: &CompressedProof,
        public_inputs: &[u8],
    ) -> Result<bool, CompressorError>;

    /// Returns the stable backend identifier.
    fn backend_id(&self) -> &str;

    /// Returns serialized verifier-key bytes.
    fn vk_bytes(&self) -> &[u8];

    /// Borrows the byte encoding of a compressed proof.
    fn compressed_proof_bytes<'a>(&self, proof: &'a CompressedProof) -> &'a [u8];
}
