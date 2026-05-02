// Vendored stub of gnosisguild/enclave types (read-only after T42 creation)
// These represent the interface boundary our adapter must satisfy.
// Source: https://github.com/gnosisguild/enclave (interface reference only)
// DO NOT modify this file after initial creation.

/// A key share produced by an Enclave ciphernode during DKG.
pub struct EnclaveKeyShare(pub Vec<u8>);

/// An RLWE ciphertext in Enclave wire format.
pub struct EnclaveCiphertext(pub Vec<u8>);

/// A partial decryption share produced by an Enclave ciphernode.
pub struct EnclaveDecryptShare(pub Vec<u8>);

/// A proof (UltraHonk / LatticeFold+) in Enclave wire format.
pub struct EnclaveProof(pub Vec<u8>);

/// The aggregate public key assembled from all ciphernode key shares.
pub struct EnclavePublicKey(pub Vec<u8>);

/// Interface for an Enclave ciphernode (maps to PVTHFHE `Party` trait).
pub trait EnclaveCiphernode {
    /// Generate a DKG key share.
    fn generate_key_share(
        &self,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<EnclaveKeyShare, String>;

    /// Produce a partial decryption share for the given ciphertext.
    fn partial_decrypt(
        &self,
        ct: &EnclaveCiphertext,
        key_share: &EnclaveKeyShare,
    ) -> Result<EnclaveDecryptShare, String>;
}

/// Interface for an Enclave aggregator (maps to PVTHFHE `Aggregator` trait).
pub trait EnclaveAggregator {
    /// Aggregate DKG key shares into a collective public key.
    fn aggregate_keys(
        &self,
        shares: &[EnclaveKeyShare],
    ) -> Result<EnclavePublicKey, String>;

    /// Aggregate partial decryption shares into the recovered plaintext.
    fn aggregate_decrypt(
        &self,
        ct: &EnclaveCiphertext,
        shares: &[EnclaveDecryptShare],
    ) -> Result<Vec<u8>, String>;

    /// Verify a proof against public inputs.
    fn verify_proof(
        &self,
        proof: &EnclaveProof,
        public_inputs: &[u8],
    ) -> Result<bool, String>;
}
