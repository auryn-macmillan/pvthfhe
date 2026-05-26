//! Frozen trait surface for the P2→P3 proof-compression boundary.

/// Poseidon-based 8-ary Merkle tree for share coefficient commitment.
pub mod merkle;

/// Polynomial evaluation over Bn254 scalar field.
pub mod poly_eval;

/// Witness generation pipeline for C7 decryption aggregation.
pub mod witness;

/// Sonobe-backed proof compressor implementation.
pub mod sonobe;
pub use sonobe::heterogeneous;

/// MicroNova recursive compression (P3-M2).
pub mod micronova;

/// Opaque compressed-proof bytes.
///
/// The wire format encodes an IVC folding proof followed by an optional
/// SNARK wrapping proof (Groth16/PLONK) of the final relaxed R1CS instance.
/// When `snark_len == 0`, no SNARK wrapper is present and the on-chain
/// verifier falls back to the Poseidon hash shortcut
/// (see `circuits/sonobe_state_commitment/src/main.nr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedProof {
    /// Serialized proof bytes (IVC + optional SNARK).
    pub bytes: Vec<u8>,
    /// Hash of the transparent IVC proof (Keccak256 of serialized IVC bytes).
    /// Populated after `wrap_nova_instance` in the compressor prove path.
    /// Used for on-chain verification via the Poseidon hash shortcut
    /// (see `circuits/sonobe_state_commitment/src/main.nr`).
    pub ivc_proof_hash: Option<[u8; 32]>,
}

impl CompressedProof {
    /// Create a new compressed proof from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        CompressedProof {
            bytes,
            ivc_proof_hash: None,
        }
    }

    /// Returns true if this proof includes a SNARK wrapping proof.
    pub fn has_snark(&self) -> bool {
        // The proof has SNARK wrapping if the format includes a non-zero
        // snark_len field. Check by parsing the header.
        parse_snark_present(&self.bytes)
    }

    /// Return the IVC proof bytes (without the SNARK part).
    pub fn ivc_bytes(&self) -> &[u8] {
        // The IVC bytes are the middle section of the proof format.
        // For now, return the full bytes since parsing is format-specific.
        &self.bytes
    }
}

fn parse_snark_present(data: &[u8]) -> bool {
    // Use the extended proof parser to check for SNARK bytes.
    data.len() > 76
        && crate::sonobe::parse_proof(data)
            .map(|p| p.snark_bytes.is_some())
            .unwrap_or(false)
}

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

/// DKG public anchor values surfaced at the compressed-proof boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedDkgPublicAnchors {
    /// DKG transcript root shared by DKG and decryption proofs.
    pub dkg_root: [u8; 32],
    /// Commitment to the aggregated public key.
    pub aggregated_pk_commit: [u8; 32],
    /// Hash of the accepted participant set.
    pub participant_set_hash: [u8; 32],
    /// Root of aggregated secret-key share commitments.
    pub sk_agg_commits_root: [u8; 32],
    /// Root of aggregated committed-smudge commitments.
    pub esm_agg_commits_root: [u8; 32],
    /// Hash of the smudge-slot allocation policy.
    pub smudge_slot_policy_hash: [u8; 32],
}

/// Decryption public anchor values surfaced at the compressed-proof boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedDecryptionPublicAnchors {
    /// DKG transcript root claimed by the decryption proof.
    pub dkg_root: [u8; 32],
    /// Hash of the ciphertext being decrypted.
    pub ciphertext_hash: [u8; 32],
    /// Expected DKG aggregate secret-key commitment root.
    pub expected_sk_commits_root: [u8; 32],
    /// Expected DKG aggregate committed-smudge commitment root.
    pub expected_esm_commits_root: [u8; 32],
    /// Public committed-smudge slot identifier.
    pub slot_id: u64,
    /// Public decryption round identifier.
    pub decrypt_round: u64,
    /// Hash of the decoded plaintext.
    pub plaintext_hash: [u8; 32],
}

/// Checks public DKG/decryption anchors before accepting compressed proof inputs.
pub fn verify_compressed_public_anchors(
    dkg: &CompressedDkgPublicAnchors,
    decrypt: &CompressedDecryptionPublicAnchors,
) -> Result<(), CompressorError> {
    if dkg.dkg_root != decrypt.dkg_root
        || dkg.sk_agg_commits_root != decrypt.expected_sk_commits_root
        || dkg.esm_agg_commits_root != decrypt.expected_esm_commits_root
    {
        return Err(CompressorError::InvalidProof);
    }
    Ok(())
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

    /// Returns the cryptographically-unique hash identifier for this step-circuit shape.
    fn circuit_hash(&self) -> [u8; 32];
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
