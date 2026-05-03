//! FHE backend abstraction for PVTHFHE.
//!
//! This crate defines the [`FheBackend`] trait and provides two implementations:
//!
//! - **Mock** (feature `mock`): deterministic, test-only, no cryptographic security.
//! - **Primary** (`fhers` module): wraps gnosisguild/fhe.rs BFV APIs.

#![warn(missing_docs)]

pub mod error;
pub mod fhers;
#[cfg(feature = "real-nizk")]
pub mod real_nizk;
pub mod types;

mod mock_impl;

#[cfg(feature = "mock")]
pub mod mock;

pub use error::FheError;
pub use types::{Ciphertext, DecryptShare, KeygenShare, Params, PublicKey};

use rand_core::RngCore;

/// Abstraction over an FHE backend supporting threshold keygen and decryption.
///
/// Implementors must be `Send + Sync` so they can be shared across async tasks.
/// All backend-internal types are hidden behind the opaque types in [`types`].
pub trait FheBackend: Send + Sync {
    /// Load and validate RLWE parameters from a TOML string.
    ///
    /// The TOML must contain an `[rlwe]` table with at minimum:
    /// - `n`: polynomial degree (u32)
    /// - `log2_q`: base-2 log of ciphertext modulus (u32)
    /// - `t_plain`: plaintext modulus (u32)
    fn load_params(toml: &str) -> Result<Self, FheError>
    where
        Self: Sized;

    /// Generate a keygen share for the given party.
    ///
    /// Returns a [`KeygenShare`] with `party_id` set to `party_id`.
    fn keygen_share(&self, party_id: u32, rng: &mut dyn RngCore) -> Result<KeygenShare, FheError>;

    /// Aggregate keygen shares into a collective public key.
    ///
    /// All shares in `shares` must have been produced by distinct parties.
    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<PublicKey, FheError>;

    /// Encrypt `plaintext` under the collective public key `pk`.
    fn encrypt(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError>;

    /// Produce a partial decryption share for `ct` from party `party_id`.
    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError>;

    /// Aggregate partial decryption shares into the recovered plaintext.
    ///
    /// Returns [`FheError::InsufficientShares`] when `shares.len() < threshold`.
    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
    ) -> Result<Vec<u8>, FheError>;
}
