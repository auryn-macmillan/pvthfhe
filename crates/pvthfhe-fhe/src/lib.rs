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
pub mod wire;

mod mock_impl;

#[cfg(feature = "mock")]
pub mod mock;

pub use error::FheError;
pub use pvthfhe_types::{DecryptionWitness, EncryptionWitness};
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
    /// - `variance`: discrete Gaussian variance (usize)
    /// - `moduli`: explicit RNS moduli list (`parse_params` currently shims a
    ///   canonical default when omitted)
    fn load_params(toml: &str) -> Result<Self, FheError>
    where
        Self: Sized;

    /// Generate a keygen share for the given party.
    ///
    /// Returns a [`KeygenShare`] with `party_id` set to `party_id`.
    fn keygen_share(&self, party_id: u32, rng: &mut dyn RngCore) -> Result<KeygenShare, FheError> {
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);
        self.keygen_share_with_session(&session_id, party_id, rng)
    }

    /// Generate a keygen share for the given party within a specific session.
    fn keygen_share_with_session(
        &self,
        _session_id: &[u8; 32],
        _party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<KeygenShare, FheError> {
        Err(FheError::Backend {
            reason: "keygen_share_with_session not implemented".into(),
        })
    }

    /// Returns whether this backend supports deterministic session-scoped keygen.
    fn supports_session_scoped_keygen(&self) -> bool {
        false
    }

    /// Prepare threshold-decryption state after all keygen shares exist.
    fn setup_threshold(&self, _n: usize, _t: usize) -> Result<(), FheError> {
        Ok(())
    }

    /// Returns whether this backend requires the mock acknowledgement env var.
    fn requires_mock_acknowledgement(&self) -> bool {
        false
    }

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

    /// Encrypt `plaintext` under `pk` and return the full encryption witness.
    ///
    /// In addition to the ciphertext, this method exposes the internal
    /// encryption randomness and error polynomials needed for well-formedness
    /// proofs. The default implementation returns an error; backends that
    /// support witness extraction must override this.
    fn encrypt_with_witness(
        &self,
        _pk: &PublicKey,
        _plaintext: &[u8],
        _rng: &mut dyn RngCore,
    ) -> Result<(Ciphertext, EncryptionWitness), FheError> {
        Err(FheError::Backend {
            reason: "encrypt_with_witness not implemented".into(),
        })
    }

    /// Produce a partial decryption share for `ct` from party `party_id`.
    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError>;

    /// Produce a partial decryption share and the structured decryption witness.
    ///
    /// Returns the same [`DecryptShare`] that [`FheBackend::partial_decrypt`]
    /// would produce, plus a [`DecryptionWitness`] containing the polynomial
    /// decompositions needed by the proof layer: ciphertext components,
    /// aggregated secret-key share, smudging noise, and resulting share.
    ///
    /// The default implementation returns an error; backends that support
    /// witness extraction must override this.
    #[allow(unused_variables)]
    fn partial_decrypt_with_witness(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<(DecryptShare, DecryptionWitness), FheError> {
        Err(FheError::Backend {
            reason: "partial_decrypt_with_witness not implemented".into(),
        })
    }

    /// Produce a partial decryption share using a committed smudging-noise
    /// polynomial instead of sampling fresh local noise.
    ///
    /// The `esm_noise_poly_bytes` must be the exact smudging noise polynomial
    /// that was committed during DKG. The backend adds this to the decryption
    /// share instead of sampling fresh Gaussian noise.
    ///
    /// The default implementation returns an error; backends that support
    /// committed-smudge mode must override this.
    #[allow(unused_variables)]
    fn partial_decrypt_committed_smudge(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        esm_noise_poly_bytes: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        Err(FheError::Backend {
            reason: "partial_decrypt_committed_smudge not implemented".into(),
        })
    }

    /// Produce a partial decryption share and a structured [`DecryptionWitness`]
    /// using a committed smudging-noise polynomial.
    ///
    /// Returns the same [`DecryptShare`] that
    /// [`FheBackend::partial_decrypt_committed_smudge`] would produce, plus a
    /// [`DecryptionWitness`] with `esm_committed: true` and the actual committed
    /// `e_sm` poly bytes recorded.
    ///
    /// The `rng` parameter is retained for API compatibility but is NOT used to
    /// sample fresh smudging noise — the committed `esm_noise_poly_bytes` are
    /// used instead.
    ///
    /// The default implementation returns an error; backends that support
    /// committed-smudge mode must override this.
    #[allow(unused_variables)]
    fn partial_decrypt_committed_smudge_with_witness(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        esm_noise_poly_bytes: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<(DecryptShare, DecryptionWitness), FheError> {
        Err(FheError::Backend {
            reason: "partial_decrypt_committed_smudge_with_witness not implemented".into(),
        })
    }

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

/// Compare recovered plaintext with original, tolerating noise/padding.
pub fn noise_tolerant_plaintext_compare(recovered: &[u8], original: &[u8]) -> bool {
    recovered.get(..original.len()) == Some(original)
}
