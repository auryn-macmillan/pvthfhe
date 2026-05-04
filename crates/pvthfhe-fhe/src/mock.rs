//! Deterministic mock [`FheBackend`] for testing.
//!
//! **Not cryptographically secure.** Enabled with `--features mock`.
//!
//! Round-trip invariant: `aggregate_decrypt(encrypt(pk, m), shares, t) == m`
//! where `pk = aggregate_keygen(shares)` and each `ds_i = partial_decrypt(ct, i)`.
//!
//! # Safety opt-in
//!
//! Every entry point in this module checks that the environment variable
//! `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK` is set to `"1"` at runtime.
//! Calling any method without that variable set will **panic** with a
//! descriptive message.  This prevents mock backends from silently running
//! in non-test environments.

use crate::{
    error::FheError,
    mock_impl::MockBackendInner,
    types::{Ciphertext, DecryptShare, KeygenShare, PublicKey},
    FheBackend,
};
use rand_core::RngCore;

/// Assert that the caller has explicitly acknowledged this is a mock backend.
///
/// Panics unless `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` is set in the
/// process environment.
fn assert_mock_acknowledged() {
    if std::env::var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK").as_deref() != Ok("1") {
        panic!(
            "PVTHFHE: mock backend requires PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 \
             to be set in the environment. This backend provides NO cryptographic \
             security and must never be used outside of explicit testing."
        );
    }
}

/// Deterministic mock backend.
///
/// Uses XOR-based toy operations. The round-trip property holds:
/// `aggregate_decrypt(encrypt(pk, m)) == m`.
///
/// **Not cryptographically secure.**
///
/// Requires `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` in the environment.
pub struct MockBackend {
    inner: MockBackendInner,
}

impl FheBackend for MockBackend {
    fn load_params(toml: &str) -> Result<Self, FheError>
    where
        Self: Sized,
    {
        assert_mock_acknowledged();
        let inner = MockBackendInner::load_params(toml)?;
        Ok(Self { inner })
    }

    fn keygen_share(&self, party_id: u32, rng: &mut dyn RngCore) -> Result<KeygenShare, FheError> {
        assert_mock_acknowledged();
        self.inner.keygen_share(party_id, rng)
    }

    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        assert_mock_acknowledged();
        self.inner.aggregate_keygen(shares)
    }

    fn encrypt(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        assert_mock_acknowledged();
        self.inner.encrypt(pk, plaintext, rng)
    }

    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        assert_mock_acknowledged();
        self.inner.partial_decrypt(ct, party_id, rng)
    }

    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
    ) -> Result<Vec<u8>, FheError> {
        assert_mock_acknowledged();
        self.inner.aggregate_decrypt(ct, shares, threshold)
    }
}
