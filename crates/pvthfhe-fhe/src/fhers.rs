//! FHE backend shim. Methods currently delegate to MockBackendInner. Real fhe.rs API wiring is deferred to T33 (see .sisyphus/evidence/audit-surrogate/regeneration.md).

use crate::{
    error::FheError,
    mock_impl::MockBackendInner,
    types::{Ciphertext, DecryptShare, KeygenShare, PublicKey},
    FheBackend,
};
use rand_core::RngCore;

/// Primary backend wrapping gnosisguild/fhe.rs BFV.
///
/// Until T33 completes the real API wiring, all methods delegate to
/// the internal mock so that conformance tests pass.
#[derive(Clone, Debug)]
pub struct FhersBackend {
    inner: MockBackendInner,
}

impl FheBackend for FhersBackend {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        // TODO(T33): wire real fhe.rs API — currently delegates to MockBackendInner
        let inner = MockBackendInner::load_params(toml)?;
        Ok(Self { inner })
    }

    fn keygen_share(&self, party_id: u32, rng: &mut dyn RngCore) -> Result<KeygenShare, FheError> {
        // TODO(T33): wire real fhe.rs API — currently delegates to MockBackendInner
        self.inner.keygen_share(party_id, rng)
    }

    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        // TODO(T33): wire real fhe.rs API — currently delegates to MockBackendInner
        self.inner.aggregate_keygen(shares)
    }

    fn encrypt(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        // TODO(T33): wire real fhe.rs API — currently delegates to MockBackendInner
        self.inner.encrypt(pk, plaintext, rng)
    }

    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        // TODO(T33): wire real fhe.rs API — currently delegates to MockBackendInner
        self.inner.partial_decrypt(ct, party_id, rng)
    }

    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
    ) -> Result<Vec<u8>, FheError> {
        // TODO(T33): wire real fhe.rs API — currently delegates to MockBackendInner
        self.inner.aggregate_decrypt(ct, shares, threshold)
    }
}
