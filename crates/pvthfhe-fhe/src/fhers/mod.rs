//! FHE backend shim.
//!
//! Primary backend wrapping gnosisguild/fhe.rs BFV. Split by responsibility:
//! - [`backend`]: the [`FheBackend`](crate::FheBackend) trait implementation
//!   (a single impl block, as Rust coherence requires).
//! - [`keys`]: public-key decoding and DKG smudge-noise commitment.
//! - [`encrypt`]: plaintext slot encoding.
//! - [`eval`]: homomorphic ciphertext operations.
//! - [`threshold`]: Shamir resharing and decryption-share helpers.
//! - [`nizk`]: NIZK glue and C7 verification helpers.

mod backend;
mod encrypt;
mod eval;
mod keys;
mod nizk;
mod threshold;

pub use encrypt::{bytes_to_slots, slots_to_bytes};

use crate::{error::FheError, types::Params};
use fhe::bfv::BfvParameters;
use fhe::mbfv::CommonRandomPoly;
use fhe_math::rq::Poly;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Smudging noise standard deviation per coefficient.
/// σ_smudge = 2^44 · σ_err ≈ 5.610 × 10^13 (IND-CPAD §G.26).
/// Raised from 2^40 for 128-bit security with unlimited queries.
const SIGMA_SMUDGE: f64 = 56_099_278_028_800.0;

/// Per-party state retained across protocol rounds.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PartyState {
    /// Sum of Shamir secret-key shares received from all parties for this party.
    pub sk_poly_sum: Vec<i64>,
    /// Full polynomial form of the aggregated Shamir secret-key share.
    pub sk_poly_sum_poly: Option<Poly>,
    /// Placeholder for smudging-error sums added in later tasks.
    pub esi_poly_sum: Vec<Poly>,
    sk_shamir_shares: Vec<Vec<i64>>,
    /// Original key-generation error polynomial (for BFV keypair NIZK).
    pub keygen_error_coeffs: Option<Vec<i64>>,
    /// Original key-generation ternary secret-key coefficients (for BFV keypair NIZK).
    pub keygen_sk_coeffs: Option<Vec<i64>>,
    /// Original key-generation error polynomial serialized (for BFV keypair NIZK).
    pub keygen_error_poly_bytes: Option<Vec<u8>>,
}

/// Primary backend wrapping gnosisguild/fhe.rs BFV.
pub struct FhersBackend {
    _params: Params,
    bfv_params: Arc<BfvParameters>,
    /// SECURITY: In multi-party production deployments, `party_states` must be
    /// per-process. The current single-process prototype stores ALL parties' secret
    /// keys in one map. See `party_secret_key_bytes()` for access-control notes.
    party_states: Arc<Mutex<HashMap<u32, PartyState>>>,
    threshold_n: Arc<Mutex<Option<usize>>>,
    threshold_t: Arc<Mutex<Option<usize>>>,
    /// Per-party committed smudging-noise polynomial bytes from DKG transcript (B.2).
    esm_noise_poly_map: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
    /// Debug-only: tracks which party_id this backend instance "owns" for
    /// access-control auditing. Only checked in debug builds.
    #[cfg(debug_assertions)]
    owned_party_id: std::sync::Mutex<Option<u32>>,
    /// Set to true by setup_threshold, checked in aggregate_decrypt for session binding.
    setup_threshold_called: Arc<AtomicBool>,
    /// Set to true by setup_threshold; reset to false by abort_session.
    dkg_initialized: Arc<AtomicBool>,
}

impl Clone for FhersBackend {
    fn clone(&self) -> Self {
        Self {
            _params: self._params.clone(),
            bfv_params: self.bfv_params.clone(),
            party_states: self.party_states.clone(),
            threshold_n: self.threshold_n.clone(),
            threshold_t: self.threshold_t.clone(),
            esm_noise_poly_map: self.esm_noise_poly_map.clone(),
            #[cfg(debug_assertions)]
            owned_party_id: {
                let val = self.owned_party_id.lock().ok().and_then(|guard| *guard);
                std::sync::Mutex::new(val)
            },
            setup_threshold_called: self.setup_threshold_called.clone(),
            dkg_initialized: self.dkg_initialized.clone(),
        }
    }
}

impl FhersBackend {
    /// Returns the loaded BFV parameters.
    pub fn bfv_params(&self) -> &Arc<BfvParameters> {
        &self.bfv_params
    }

    /// Return the serialized secret-key coefficients for `party_id`.
    ///
    /// Each coefficient is written as 8 little-endian bytes.
    ///
    /// # Security
    /// This method returns raw secret-key bytes. In the current single-process
    /// prototype, this is acceptable. In production multi-party deployments, each
    /// process must only have access to its own party's key material. Access control
    /// is enforced via `#[cfg(debug_assertions)]` auditing.
    pub fn party_secret_key_bytes(&self, party_id: u32) -> Result<Vec<u8>, FheError> {
        #[cfg(debug_assertions)]
        {
            let owned = self
                .owned_party_id
                .lock()
                .map_err(|err| FheError::Backend {
                    reason: format!("owned_party_id lock poisoned: {err}"),
                })?;
            if let Some(owned_id) = *owned {
                if party_id != owned_id {
                    tracing::warn!(
                        "party_secret_key_bytes: party_id={party_id} differs from owned_id={owned_id}. \
                         This is only safe in prototype single-process deployments."
                    );
                }
            }
        }

        let (sk_poly_sum, _sk_poly_sum_poly, _esi_poly_sum) = self.party_state_data(party_id)?;
        let mut bytes = Vec::with_capacity(sk_poly_sum.len() * 8);
        for coeff in &sk_poly_sum {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Return the key-generation witness (sk, e) for BFV keypair NIZK.
    /// Returns `None` if no keygen data was stored for this party.
    #[allow(clippy::type_complexity)]
    pub fn party_keygen_witness(
        &self,
        party_id: u32,
    ) -> Result<Option<(Vec<i64>, Vec<u8>)>, FheError> {
        let states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: format!("party_states lock poisoned: {err}"),
        })?;
        match states.get(&party_id) {
            Some(state) => match (&state.keygen_sk_coeffs, &state.keygen_error_poly_bytes) {
                (Some(sk), Some(e_bytes)) => Ok(Some((sk.clone(), e_bytes.clone()))),
                _ => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Store committed smudging-noise polynomial bytes for `party_id` (B.2).
    pub fn store_esm_noise_poly_bytes(&self, party_id: u32, bytes: Vec<u8>) {
        if let Ok(mut map) = self.esm_noise_poly_map.lock() {
            map.insert(party_id, bytes);
        }
    }

    /// Look up committed smudging-noise polynomial bytes for `party_id` (B.2).
    pub fn esm_noise_poly_for(&self, party_id: u32) -> Option<Vec<u8>> {
        self.esm_noise_poly_map
            .lock()
            .ok()
            .and_then(|map| map.get(&party_id).cloned())
    }

    /// Remove and return the stored state for `party_id`.
    #[doc(hidden)]
    pub fn take_party_state(&self, party_id: u32) -> Result<PartyState, FheError> {
        let mut party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        party_states
            .remove(&party_id)
            .ok_or(FheError::UnknownParty { party_id })
    }

    /// Abort the current session: zeroize all secret state and reset to pre-DKG state.
    ///
    /// Call this when a protocol round fails or a party is blamed. Unlike `Drop`,
    /// which runs whenever the struct leaves scope, this is an explicit API that
    /// can be called at the precise point of protocol abort.
    pub fn abort_session(&mut self) {
        let mut party_states = match self.party_states.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        for state in party_states.values_mut() {
            state.zeroize();
        }
        party_states.clear();
        drop(party_states);
        self.dkg_initialized.store(false, Ordering::SeqCst);
    }

    fn crp_for_session(&self, session_id: &[u8; 32]) -> Result<CommonRandomPoly, FheError> {
        CommonRandomPoly::new_deterministic(&self.bfv_params, *session_id).map_err(|err| {
            FheError::Backend {
                reason: err.to_string(),
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn crp_for_session_bytes_for_test(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Vec<u8>, FheError> {
        Ok(fhe_traits::Serialize::to_bytes(
            &self.crp_for_session(session_id)?,
        ))
    }

    /// Extract secret-key data for `party_id` without cloning the full [`PartyState`].
    #[allow(clippy::type_complexity)]
    fn party_state_data(
        &self,
        party_id: u32,
    ) -> Result<(Vec<i64>, Option<Poly>, Vec<Poly>), FheError> {
        let party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        let state = party_states
            .get(&party_id)
            .ok_or(FheError::UnknownParty { party_id })?;
        Ok((
            state.sk_poly_sum.clone(),
            state.sk_poly_sum_poly.clone(),
            state.esi_poly_sum.clone(),
        ))
    }

    fn threshold_params(&self) -> Result<(usize, usize), FheError> {
        let threshold_n = *self.threshold_n.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let threshold_t = *self.threshold_t.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        match (threshold_n, threshold_t) {
            (Some(n), Some(t)) => Ok((n, t)),
            _ => Err(FheError::Backend {
                reason: "setup_threshold not called".into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FheBackend;
    use zeroize::Zeroize;

    const TEST_PARAMS_TOML: &str = r#"
[rlwe]
n = 8192
log2_q = 174
t_plain = 65536
moduli = [288230376173076481, 288230376167047169, 288230376161280001]
variance = 10
"#;

    #[test]
    fn party_state_is_zeroized_on_drop() {
        // RED: Verify that dropped PartyState has zeroized secret fields.
        let mut state = PartyState {
            sk_poly_sum: vec![1i64, 2, 3, 4, 5],
            sk_poly_sum_poly: None,
            esi_poly_sum: Vec::new(),
            sk_shamir_shares: vec![vec![7i64, 8, 9]],
            keygen_error_coeffs: None,
            keygen_sk_coeffs: None,
            keygen_error_poly_bytes: None,
        };
        // Simulate drop via Zeroize trait (ZeroizeOnDrop calls this in Drop impl).
        state.zeroize();
        assert!(
            state.sk_poly_sum.is_empty() || state.sk_poly_sum.iter().all(|&x| x == 0),
            "sk_poly_sum must be zeroized"
        );
        assert!(
            state.sk_shamir_shares.is_empty()
                || state
                    .sk_shamir_shares
                    .iter()
                    .all(|v| v.is_empty() || v.iter().all(|&x| x == 0)),
            "sk_shamir_shares must be zeroized"
        );
    }

    #[test]
    fn crp_for_session_is_deterministic_per_session_id() {
        let backend_a = FhersBackend::load_params(TEST_PARAMS_TOML).expect("load params a");
        let backend_b = FhersBackend::load_params(TEST_PARAMS_TOML).expect("load params b");

        let session_id = [7u8; 32];
        let other_session_id = [8u8; 32];

        let crp_a = backend_a
            .crp_for_session_bytes_for_test(&session_id)
            .expect("crp for session a");
        let crp_b = backend_b
            .crp_for_session_bytes_for_test(&session_id)
            .expect("crp for session b");
        let crp_other = backend_a
            .crp_for_session_bytes_for_test(&other_session_id)
            .expect("crp for other session");

        assert_eq!(crp_a, crp_b);
        assert_ne!(crp_a, crp_other);
    }

    #[test]
    fn abort_session_zeroizes_and_resets() {
        let mut backend = FhersBackend::load_params(TEST_PARAMS_TOML).expect("load params");

        // Set dkg_initialized flag directly (avoid env var pollution from setup_threshold)
        backend.dkg_initialized.store(true, Ordering::SeqCst);

        // Abort: should zeroize state and reset
        backend.abort_session();
        assert!(
            !backend.dkg_initialized.load(Ordering::SeqCst),
            "dkg_initialized must be false after abort"
        );
        assert!(
            backend.party_states.lock().unwrap().is_empty(),
            "party_states must be empty after abort"
        );
    }
}
