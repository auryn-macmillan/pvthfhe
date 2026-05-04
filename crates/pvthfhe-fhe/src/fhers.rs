//! FHE backend shim. Methods return a sentinel error until T33 wires the real fhe.rs API.
//! Real fhe.rs API wiring is deferred to T33 (see .sisyphus/evidence/audit-surrogate/regeneration.md).

use crate::{
    error::FheError,
    mock_impl,
    types::{Ciphertext, DecryptShare, KeygenShare, Params, PublicKey},
    FheBackend,
};
use rand_core::RngCore;

/// Sentinel error returned by all `FhersBackend` primitive calls until T33.
fn not_implemented() -> FheError {
    FheError::Backend {
        reason: "FhersBackend: real fhe.rs API not yet implemented (T33); \
                 to use mock backend set PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 \
                 and enable the `mock` feature"
            .into(),
    }
}

/// Primary backend wrapping gnosisguild/fhe.rs BFV.
///
/// Until T33 completes the real API wiring, `load_params` succeeds (params are
/// parsed and validated) but every cryptographic primitive returns
/// [`FheError::Backend`] as a sentinel.  This ensures that default-feature
/// builds produce an unambiguous error rather than silently executing the
/// mock XOR operations.
#[derive(Clone, Debug)]
pub struct FhersBackend {
    
    _params: Params,
}

impl FheBackend for FhersBackend {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        // Parse and validate params — this succeeds so callers can inspect them.
        let params = mock_impl::parse_params(toml)?;
        Ok(Self { _params: params })
    }

    fn keygen_share(
        &self,
        _party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<KeygenShare, FheError> {
        // TODO(T33): wire real fhe.rs API
        Err(not_implemented())
    }

    fn aggregate_keygen(&self, _shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        // TODO(T33): wire real fhe.rs API
        Err(not_implemented())
    }

    fn encrypt(
        &self,
        _pk: &PublicKey,
        _plaintext: &[u8],
        _rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        // TODO(T33): wire real fhe.rs API
        Err(not_implemented())
    }

    fn partial_decrypt(
        &self,
        _ct: &Ciphertext,
        _party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        // TODO(T33): wire real fhe.rs API
        Err(not_implemented())
    }

    fn aggregate_decrypt(
        &self,
        _ct: &Ciphertext,
        _shares: &[DecryptShare],
        _threshold: usize,
    ) -> Result<Vec<u8>, FheError> {
        // TODO(T33): wire real fhe.rs API
        Err(not_implemented())
    }
}
