//! Shared opaque types exchanged between [`crate::FheBackend`] methods.
//!
//! All types are opaque byte wrappers. No backend-internal types appear here.

use serde::{Deserialize, Serialize};

/// A keygen share produced by one party during distributed key generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeygenShare {
    /// The party that produced this share.
    pub party_id: u32,
    /// Opaque serialised share bytes.
    pub bytes: Vec<u8>,
}

/// The collective public key assembled from all keygen shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    /// Opaque serialised public key bytes.
    pub bytes: Vec<u8>,
}

/// An RLWE ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    /// Opaque serialised ciphertext bytes.
    pub bytes: Vec<u8>,
}

/// A partial decryption share produced by one party.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptShare {
    /// The party that produced this share.
    pub party_id: u32,
    /// Opaque serialised share bytes.
    pub bytes: Vec<u8>,
}

/// RLWE parameters loaded from a TOML configuration string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// RLWE polynomial degree.
    pub n: u32,
    /// Base-2 logarithm of the ciphertext modulus Q.
    pub log2_q: u32,
    /// Plaintext modulus t.
    pub t_plain: u32,
    /// Explicit RNS ciphertext moduli.
    pub moduli: Vec<u64>,
    /// Discrete Gaussian variance used for error sampling.
    pub variance: usize,
}
