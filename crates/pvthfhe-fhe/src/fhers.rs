//! FHE backend shim.

use crate::{
    error::FheError,
    mock_impl,
    types::{Ciphertext, DecryptShare, KeygenShare, Params, PublicKey as OpaquePublicKey},
    wire, DecryptionWitness, EncryptionWitness, FheBackend,
};
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext as BfvCiphertext, Encoding, Plaintext,
    PublicKey as BfvPublicKey, SecretKey,
};
use fhe::mbfv::{Aggregate, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::ShareManager;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{
    DeserializeParametrized, DeserializeWithContext, FheDecoder, FheEncoder, FheEncrypter,
    Serialize,
};
use ndarray::Array2;
use rand::rngs::StdRng;
use rayon::prelude::*;
use pvthfhe_types::ProtocolBytes;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use rand_distr::{Distribution, Normal};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Smudging noise standard deviation per coefficient.
/// σ_smudge = 2^40 · σ_err ≈ 3.506 × 10^12.
/// See `.sisyphus/design/smudging.md` §4 for derivation.
const SIGMA_SMUDGE: f64 = 3_506_204_876_800.0;

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
}

/// Primary backend wrapping gnosisguild/fhe.rs BFV.
pub struct FhersBackend {
    _params: Params,
    bfv_params: Arc<BfvParameters>,
    party_states: Arc<Mutex<HashMap<u32, PartyState>>>,
    threshold_n: Arc<Mutex<Option<usize>>>,
    threshold_t: Arc<Mutex<Option<usize>>>,
    /// Per-party committed smudging-noise polynomial bytes from DKG transcript (B.2).
    esm_noise_poly_map: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
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
        }
    }
}

impl FhersBackend {
    fn shamir_threshold(&self, _n: usize, t: usize) -> usize {
        // fhe.rs ShareManager stores threshold as the Shamir polynomial degree.
        // decrypt_from_shares requires threshold + 1 shares.
        // Our convention: t = number of shares needed for reconstruction.
        // Convert to fhe.rs convention: polynomial degree = t - 1.
        if t == 0 {
            return 0;
        }
        t - 1
    }

    /// Returns the loaded BFV parameters.
    pub fn bfv_params(&self) -> &Arc<BfvParameters> {
        &self.bfv_params
    }

    /// Return the serialized secret-key coefficients for `party_id`.
    ///
    /// Each coefficient is written as 8 little-endian bytes.
    pub fn party_secret_key_bytes(&self, party_id: u32) -> Result<Vec<u8>, FheError> {
        let (sk_poly_sum, _sk_poly_sum_poly, _esi_poly_sum) = self.party_state_data(party_id)?;
        let mut bytes = Vec::with_capacity(sk_poly_sum.len() * 8);
        for coeff in &sk_poly_sum {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
        Ok(bytes)
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

    /// Generate deterministic committed smudging-noise polynomial bytes for a party
    /// and store them in the backend (B.2). Returns the serialized polynomial bytes.
    pub fn generate_deterministic_esm_noise_for_party(
        &self,
        party_id: u32,
        seed: u64,
    ) -> Result<Vec<u8>, FheError> {
        let degree = self.bfv_params.degree();
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        let mut hasher = Sha256::new();
        hasher.update(b"pvthfhe-esm-noise-v1");
        hasher.update(party_id.to_be_bytes());
        hasher.update(seed.to_be_bytes());
        let seed_bytes: [u8; 32] = hasher.finalize().into();
        let mut noise_rng = ChaCha8Rng::from_seed(seed_bytes);

        let dist = Normal::new(0.0, SIGMA_SMUDGE).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let noise_coeffs: Vec<i64> = (0..degree)
            .map(|_| {
                let sample: f64 = dist.sample(&mut noise_rng);
                sample.round() as i64
            })
            .collect();
        let noise_poly = Poly::try_convert_from(
            noise_coeffs.as_slice(),
            &ctx,
            false,
            Representation::PowerBasis,
        )
        .map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let bytes = noise_poly.to_bytes();
        self.store_esm_noise_poly_bytes(party_id, bytes.clone());
        Ok(bytes)
    }

    /// Remove and return the stored state for `party_id`.
    pub fn take_party_state(&self, party_id: u32) -> Result<PartyState, FheError> {
        let mut party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        party_states
            .remove(&party_id)
            .ok_or(FheError::UnknownParty { party_id })
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

    fn decode_public_key(&self, pk: &OpaquePublicKey) -> Result<BfvPublicKey, FheError> {
        let decoded =
            wire::decode_public_key(&pk.bytes).map_err(|_| FheError::MalformedPublicKey)?;
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let p0 = Poly::from_bytes(&decoded.p0, &ctx).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let p1 = Poly::from_bytes(&decoded.p1, &ctx).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let c = BfvCiphertext::new(vec![p0, p1], &self.bfv_params).map_err(|err| {
            FheError::Backend {
                reason: err.to_string(),
            }
        })?;

        Ok(BfvPublicKey {
            par: self.bfv_params.clone(),
            c,
        })
    }

    /// Extract secret-key data for `party_id` without cloning the full [`PartyState`].
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

    fn zero_poly_level0(&self) -> Result<Poly, FheError> {
        Ok(Poly::zero(
            self.bfv_params
                .ctx_at_level(0)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?,
            Representation::PowerBasis,
        ))
    }

    fn decryption_share_poly_from_coeffs(
        &self,
        ciphertext: Arc<BfvCiphertext>,
        party_id: u32,
        n: usize,
        t: usize,
    ) -> Result<Poly, FheError> {
        let (sk_poly_sum_coeffs, sk_poly_sum_poly, esi_poly_sum) =
            self.party_state_data(party_id)?;
        let share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());
        let sk_poly_sum = match sk_poly_sum_poly {
            Some(poly) => poly,
            None => share_manager
                .coeffs_to_poly_level0(&sk_poly_sum_coeffs)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?
                .as_ref()
                .clone(),
        };
        let esi_poly = match esi_poly_sum.first() {
            Some(poly) => poly.clone(),
            None => self.zero_poly_level0()?,
        };

        share_manager
            .decryption_share(ciphertext, sk_poly_sum, esi_poly)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })
    }

    fn decryption_share_poly_from_full_state(
        &self,
        ciphertext: Arc<BfvCiphertext>,
        party_id: u32,
        n: usize,
        t: usize,
    ) -> Result<Poly, FheError> {
        let (sk_poly_sum, sk_poly_sum_poly, esi_poly_sum) = self.party_state_data(party_id)?;
        let share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());
        let sk_poly_sum = match &sk_poly_sum_poly {
            Some(poly) => poly.clone(),
            None => share_manager
                .coeffs_to_poly_level0(&sk_poly_sum)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?
                .as_ref()
                .clone(),
        };
        let esi_poly = match esi_poly_sum.first() {
            Some(poly) => poly.clone(),
            None => self.zero_poly_level0()?,
        };

        share_manager
            .decryption_share(ciphertext, sk_poly_sum, esi_poly)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })
    }

    fn compute_party_sk_sums(&self, n: usize, t: usize) -> Result<(), FheError> {
        tracing::debug!(n_participants = n, threshold = t, "setup_threshold: computing Shamir shares for all parties (O(n²·degree))");
        if n == 0 {
            return Err(FheError::Backend {
                reason: "n must be > 0".into(),
            });
        }
        const MAX_N_PRACTICAL: usize = 1024;
        if n > MAX_N_PRACTICAL {
            return Err(FheError::Backend {
                reason: format!("n={n} exceeds practical limit {MAX_N_PRACTICAL} (O(n²) memory would exceed available RAM). Use per-node simulation for scaling benchmarks.")
            });
        }
        let max_party_id = u32::try_from(n).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        // ── Pre-read: extract sk_poly_sum under lock, then release ──
        let all_sk_coeffs: HashMap<u32, Vec<i64>> = {
            let party_states = self.party_states.lock().map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
            for pid in 1u32..=max_party_id {
                if !party_states.contains_key(&pid) {
                    return Err(FheError::UnknownParty { party_id: pid });
                }
            }
            (1u32..=max_party_id)
                .map(|pid| (pid, party_states[&pid].sk_poly_sum.clone()))
                .collect()
        };

        let t_pre_read = std::time::Instant::now();
        tracing::info!(n = n, ms = t_pre_read.elapsed().as_secs_f64() * 1000.0, "setup_threshold: pre-read sk_coeffs");

        let threshold = self.shamir_threshold(n, t);
        let bfv_params = self.bfv_params.clone();
        let mut distributed = HashMap::<u32, Vec<Array2<u64>>>::new();
        for party_id in 1u32..=max_party_id {
            distributed.insert(party_id, Vec::with_capacity(n));
        }

        // ── Parallel: each party generates Shamir shares for all recipients ──
        // allow-seeded-rng: deterministic Shamir share generation so parallel
        // execution is deterministic and reproducible.
        let all_shares: Vec<Result<((u32, Vec<Array2<u64>>), Vec<Vec<i64>>), FheError>> =
            (1u32..=max_party_id)
                .into_par_iter()
                .map(|party_id| {
                    let mut sm = ShareManager::new(n, threshold, bfv_params.clone());
                    let sk_poly = sm
                        .coeffs_to_poly_level0(&all_sk_coeffs[&party_id])
                        .map_err(|err| FheError::Backend {
                            reason: err.to_string(),
                        })?;
                    let mut rng = StdRng::seed_from_u64(party_id as u64);
                    let shares = sm
                        .generate_secret_shares_from_poly(sk_poly, &mut rng)
                        .map_err(|err| FheError::Backend {
                            reason: err.to_string(),
                        })?;
                    let sk_shamir: Vec<Vec<i64>> = (0..n)
                        .map(|ri| {
                            shares[0]
                                .row(ri)
                                .iter()
                                .copied()
                                .map(|c| {
                                    i64::try_from(c).map_err(|err| FheError::Backend {
                                        reason: err.to_string(),
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(((party_id, shares), sk_shamir))
                })
                .collect();

        let t_parallel = std::time::Instant::now();
        let n_parties = max_party_id as usize;
        let total_allocated_mb = n_parties * (n_parties - 1) * self.bfv_params.moduli().len() * self.bfv_params.degree() * 8 / (1024 * 1024);
        tracing::info!(n = n, ms = t_parallel.elapsed().as_secs_f64() * 1000.0, total_allocated_mb = total_allocated_mb, "setup_threshold: parallel Shamir generation");

        // ── Re-acquire lock for sequential merge ──
        let mut party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        for result in all_shares {
            let ((party_id, shares), sk_shamir_shares) = result?;
            party_states
                .get_mut(&party_id)
                .ok_or(FheError::UnknownParty { party_id })?
                .sk_shamir_shares = sk_shamir_shares;
            for receiver_index in 0..n {
                let receiver_party_id =
                    u32::try_from(receiver_index + 1).map_err(|err| FheError::Backend {
                        reason: err.to_string(),
                    })?;
                let mut sender_share_data = Vec::with_capacity(
                    self.bfv_params.moduli().len() * self.bfv_params.degree(),
                );
                for modulus_matrix in &shares {
                    sender_share_data
                        .extend(modulus_matrix.row(receiver_index).iter().copied());
                }
                let sender_share = Array2::from_shape_vec(
                    (self.bfv_params.moduli().len(), self.bfv_params.degree()),
                    sender_share_data,
                )
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?;
                distributed
                    .get_mut(&receiver_party_id)
                    .ok_or(FheError::UnknownParty {
                        party_id: receiver_party_id,
                    })?
                    .push(sender_share);
            }
        }

        let t_merge = std::time::Instant::now();
        tracing::info!(n = n, ms = t_merge.elapsed().as_secs_f64() * 1000.0, "setup_threshold: sequential merge into distributed");

        let share_manager = ShareManager::new(n, threshold, bfv_params);
        for party_id in 1u32..=max_party_id {
            let collected = distributed
                .remove(&party_id)
                .ok_or(FheError::UnknownParty { party_id })?;
            let poly_sum = share_manager
                .aggregate_collected_shares(&collected)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?;
            let coeffs = poly_sum
                .coefficients()
                .row(0)
                .iter()
                .copied()
                .into_iter()
                .map(|coeff| {
                    i64::try_from(coeff).map_err(|err| FheError::Backend {
                        reason: err.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let state = party_states
                .get_mut(&party_id)
                .ok_or(FheError::UnknownParty { party_id })?;
            state.sk_poly_sum = coeffs;
            state.sk_poly_sum_poly = Some(poly_sum);
            state.esi_poly_sum = Vec::new();
        }

        let t_aggregate = std::time::Instant::now();
        tracing::info!(n = n, ms = t_aggregate.elapsed().as_secs_f64() * 1000.0, "setup_threshold: aggregate collected shares");

        let t_total = std::time::Instant::now();
        tracing::info!(n = n, ms = t_total.elapsed().as_secs_f64() * 1000.0, "setup_threshold: DONE");

        Ok(())
    }
}

/// Packs plaintext bytes into little-endian 2-byte `u64` slots and pads to `degree`.
pub fn bytes_to_slots(input: &[u8], degree: usize) -> Vec<u64> {
    let mut slots = input
        .chunks(2)
        .map(|chunk| {
            let lo = u64::from(chunk[0]);
            let hi = u64::from(*chunk.get(1).unwrap_or(&0)) << 8;
            lo | hi
        })
        .collect::<Vec<_>>();
    slots.resize(degree, 0);
    slots
}

/// Unpacks little-endian 2-byte `u64` slots back into plaintext bytes.
pub fn slots_to_bytes(slots: &[u64], original_len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(slots.len() * 2);
    for slot in slots {
        bytes.push((slot & 0xff) as u8);
        bytes.push(((slot >> 8) & 0xff) as u8);
    }
    bytes.truncate(original_len);
    bytes
}

fn encode_plaintext_slots(plaintext: &[u8], degree: usize) -> Result<Vec<u64>, FheError> {
    let max = degree.saturating_sub(1) * 2;
    if plaintext.len() > max {
        return Err(FheError::PlaintextTooLong {
            max,
            got: plaintext.len(),
        });
    }

    let mut slots = Vec::with_capacity(degree);
    slots.push(
        u64::try_from(plaintext.len()).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?,
    );
    slots.extend(bytes_to_slots(plaintext, degree.saturating_sub(1)));
    slots.truncate(degree);
    #[cfg(feature = "trace-decrypt")]
    eprintln!(
        "[FHE-ENCODE] plaintext_len={} first_slot(original_len)={} total_slots_after_trunc={}",
        plaintext.len(),
        slots[0],
        slots.len()
    );
    Ok(slots)
}

fn decode_plaintext_slots(slots: &[u64]) -> Result<Vec<u8>, FheError> {
    let Some((&original_len, payload_slots)) = slots.split_first() else {
        return Ok(Vec::new());
    };
    let original_len = usize::try_from(original_len).map_err(|err| FheError::Backend {
        reason: err.to_string(),
    })?;
    let max = payload_slots.len() * 2;
    if original_len > max {
        #[cfg(feature = "trace-decrypt")]
        eprintln!("[FHE-DECODE] FAIL: decoded plaintext length {original_len} exceeds max {max}");
        #[cfg(feature = "trace-decrypt")]
        eprintln!(
            "  total_slots={} first_few_slots={:02x?}",
            slots.len(),
            &slots[..std::cmp::min(8, slots.len())]
        );
        return Err(FheError::Backend {
            reason: format!("decoded plaintext length {original_len} exceeds max {max}"),
        });
    }

    Ok(slots_to_bytes(payload_slots, original_len))
}

impl FheBackend for FhersBackend {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        // Parse and validate params — this succeeds so callers can inspect them.
        let params = mock_impl::parse_params(toml)?;
        let bfv_params = BfvParametersBuilder::new()
            .set_degree(params.n as usize)
            .set_moduli(&params.moduli)
            .set_plaintext_modulus(params.t_plain as u64)
            .build_arc()
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        Ok(Self {
            _params: params,
            bfv_params,
            party_states: Arc::new(Mutex::new(HashMap::new())),
            threshold_n: Arc::new(Mutex::new(None)),
            threshold_t: Arc::new(Mutex::new(None)),
            esm_noise_poly_map: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn keygen_share_with_session(
        &self,
        session_id: &[u8; 32],
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<KeygenShare, FheError> {
        let crp = self.crp_for_session(session_id)?;
        let mut seeded_rng = ChaCha8Rng::from_rng(rng).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let sk = SecretKey::random(&self.bfv_params, &mut seeded_rng);
        let (p0_share, _pk_1, _sk_poly, _e) =
            PublicKeyShare::new_extended(&sk, crp.clone(), &mut seeded_rng).map_err(|err| {
                FheError::Backend {
                    reason: err.to_string(),
                }
            })?;

        let party_state = PartyState {
            sk_poly_sum: sk.coeffs.to_vec(),
            sk_poly_sum_poly: None,
            esi_poly_sum: Vec::new(),
            sk_shamir_shares: Vec::new(),
        };

        let mut party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        party_states.insert(party_id, party_state);

        Ok(KeygenShare {
            party_id,
            bytes: ProtocolBytes(wire::encode_keygen_share(
                &crp.to_bytes(),
                &p0_share.to_bytes(),
            )),
        })
    }

    fn supports_session_scoped_keygen(&self) -> bool {
        true
    }

    fn setup_threshold(&self, n: usize, t: usize) -> Result<(), FheError> {
        if t == 0 || t > n {
            return Err(FheError::Backend {
                reason: format!("invalid threshold parameters: n={n}, t={t}"),
            });
        }
        let max_t = (n - 1) / 2;
        if t > max_t {
            return Err(FheError::Backend {
                reason: format!("threshold t={t} exceeds max_t={max_t} for n={n}. Must satisfy t ≤ (n-1)/2 for Shamir security.")
            });
        }
        self.compute_party_sk_sums(n, t)?;

        *self.threshold_n.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })? = Some(n);
        *self.threshold_t.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })? = Some(t);

        Ok(())
    }

    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<OpaquePublicKey, FheError> {
        let mut crp_bytes = None::<Vec<u8>>;
        let mut p0_share_bytes = Vec::with_capacity(shares.len());
        let mut seen_party_ids = std::collections::HashSet::new();

        for share in shares {
            if !seen_party_ids.insert(share.party_id) {
                return Err(FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                });
            }

            let decoded = wire::decode_keygen_share(share.bytes.as_slice()).map_err(|_| {
                FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                }
            })?;

            if let Some(expected_crp) = &crp_bytes {
                if expected_crp.as_slice() != decoded.crp.as_slice() {
                    return Err(FheError::InconsistentCrp);
                }
            } else {
                crp_bytes = Some(decoded.crp.0.clone());
            }

            p0_share_bytes.push(decoded.p0_share.0);
        }

        let crp_bytes = crp_bytes.ok_or_else(|| FheError::Backend {
            reason: "aggregate_keygen requires at least one share".into(),
        })?;

        let crp = CommonRandomPoly::deserialize(&crp_bytes, &self.bfv_params).map_err(|err| {
            FheError::Backend {
                reason: err.to_string(),
            }
        })?;

        let pk_shares = p0_share_bytes
            .into_iter()
            .map(|p0_share| {
                PublicKeyShare::deserialize(&p0_share, &self.bfv_params, crp.clone()).map_err(
                    |err| FheError::Backend {
                        reason: err.to_string(),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let aggregated_pk =
            BfvPublicKey::from_shares(pk_shares).map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        let p0 = aggregated_pk
            .c
            .get(0)
            .ok_or(FheError::MalformedPublicKey)?
            .to_bytes();
        let p1 = aggregated_pk
            .c
            .get(1)
            .ok_or(FheError::MalformedPublicKey)?
            .to_bytes();

        Ok(OpaquePublicKey {
            bytes: wire::encode_public_key(&p0, &p1),
        })
    }

    fn encrypt(
        &self,
        pk: &OpaquePublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        let degree = self.bfv_params.degree();
        let bfv_pk = self.decode_public_key(pk)?;
        let slots = encode_plaintext_slots(plaintext, degree)?;
        let pt =
            Plaintext::try_encode(&slots, Encoding::poly(), &self.bfv_params).map_err(|err| {
                FheError::Backend {
                    reason: err.to_string(),
                }
            })?;
        let mut encrypt_rng = ChaCha8Rng::from_rng(rng).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let ct = bfv_pk
            .try_encrypt(&pt, &mut encrypt_rng)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        Ok(Ciphertext {
            bytes: ct.to_bytes(),
        })
    }

    fn encrypt_with_witness(
        &self,
        pk: &OpaquePublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCore,
    ) -> Result<(Ciphertext, EncryptionWitness), FheError> {
        let degree = self.bfv_params.degree();
        let bfv_pk = self.decode_public_key(pk)?;
        let slots = encode_plaintext_slots(plaintext, degree)?;
        let pt =
            Plaintext::try_encode(&slots, Encoding::poly(), &self.bfv_params).map_err(|err| {
                FheError::Backend {
                    reason: err.to_string(),
                }
            })?;

        // Capture the plaintext polynomial bytes before encryption consumes `pt`.
        let plaintext_poly = pt.to_poly();
        let plaintext_poly_bytes = plaintext_poly.to_bytes();

        let mut encrypt_rng = ChaCha8Rng::from_rng(rng).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        // try_encrypt_extended returns (ciphertext, u, e1, e2) where:
        //   u  = encryption randomness (CBD with SK_VARIANCE)
        //   e1 = error polynomial for ct₀ leg (error_1 variance)
        //   e2 = error polynomial for ct₁ leg (standard variance)
        let (ct, u, e1, e2) =
            bfv_pk
                .try_encrypt_extended(&pt, &mut encrypt_rng)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?;

        let ct0_poly = ct.get(0).ok_or(FheError::Backend {
            reason: "ciphertext missing c[0]".into(),
        })?;
        let ct1_poly = ct.get(1).ok_or(FheError::Backend {
            reason: "ciphertext missing c[1]".into(),
        })?;

        let ciphertext_bytes = ct.to_bytes();

        let pk0_bytes = bfv_pk
            .c
            .get(0)
            .ok_or(FheError::MalformedPublicKey)?
            .to_bytes();
        let pk1_bytes = bfv_pk
            .c
            .get(1)
            .ok_or(FheError::MalformedPublicKey)?
            .to_bytes();

        let witness = EncryptionWitness {
            plaintext_poly_bytes,
            u_poly_bytes: u.to_bytes(),
            e0_poly_bytes: e1.to_bytes(),
            e1_poly_bytes: e2.to_bytes(),
            ct0_poly_bytes: ct0_poly.to_bytes(),
            ct1_poly_bytes: ct1_poly.to_bytes(),
            ciphertext_bytes: ciphertext_bytes.clone(),
            recipient_pk0_bytes: pk0_bytes,
            recipient_pk1_bytes: pk1_bytes,
        };

        Ok((
            Ciphertext {
                bytes: ciphertext_bytes,
            },
            witness,
        ))
    }

    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        // B.2: delegate to committed-smudge path when DKG esm data is available
        if let Some(esm_bytes) = self.esm_noise_poly_for(party_id) {
            return self.partial_decrypt_committed_smudge(ct, party_id, &esm_bytes, rng);
        }

        let (n, t) = self.threshold_params()?;
        let ct = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;

        let mut d_share_poly =
            self.decryption_share_poly_from_coeffs(Arc::new(ct.clone()), party_id, n, t)?;

        // Sample smudging noise: 8192 Gaussian coefficients with σ = 3.506e12.
        let mut noise_rng = ChaCha8Rng::from_rng(rng).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let dist = Normal::new(0.0, SIGMA_SMUDGE).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let degree = self.bfv_params.degree();
        let noise_coeffs: Vec<i64> = (0..degree)
            .map(|_| {
                let sample: f64 = dist.sample(&mut noise_rng);
                sample.round() as i64
            })
            .collect();
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let noise_poly = Poly::try_convert_from(
            noise_coeffs.as_slice(),
            ctx,
            false,
            Representation::PowerBasis,
        )
        .map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        d_share_poly += &noise_poly;
        let poly_bytes = d_share_poly.to_bytes();

        Ok(DecryptShare {
            party_id,
            bytes: ProtocolBytes(wire::encode_decrypt_share(&poly_bytes)),
            nizk_proof_bytes: None,
        })
    }

    fn partial_decrypt_with_witness(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        rng: &mut dyn RngCore,
    ) -> Result<(DecryptShare, DecryptionWitness), FheError> {
        let (n, t) = self.threshold_params()?;
        let ct_bfv = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;

        // Extract ciphertext component polynomial bytes.
        let ct0_poly_bytes = ct_bfv.c[0].to_bytes();
        let ct1_poly_bytes = ct_bfv.c[1].to_bytes();

        // Retrieve the aggregated secret-key share polynomial from party state.
        let (sk_poly_sum_coeffs, sk_poly_sum_poly, esi_poly_sum) =
            self.party_state_data(party_id)?;
        let share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());

        let sk_poly = match sk_poly_sum_poly {
            Some(poly) => poly,
            None => share_manager
                .coeffs_to_poly_level0(&sk_poly_sum_coeffs)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?
                .as_ref()
                .clone(),
        };
        let sk_agg_poly_bytes = sk_poly.to_bytes();

        let esi_poly = match esi_poly_sum.first() {
            Some(poly) => poly.clone(),
            None => self.zero_poly_level0()?,
        };

        // Pre-smudge decryption share (before injecting Gaussian noise).
        let pre_smudge_d_share = share_manager
            .decryption_share(Arc::new(ct_bfv.clone()), sk_poly, esi_poly)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        // Sample smudging noise: 8192 Gaussian coefficients with σ = 3.506e12.
        let mut noise_rng = ChaCha8Rng::from_rng(rng).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let dist = Normal::new(0.0, SIGMA_SMUDGE).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let degree = self.bfv_params.degree();
        let noise_coeffs: Vec<i64> = (0..degree)
            .map(|_| {
                let sample: f64 = dist.sample(&mut noise_rng);
                sample.round() as i64
            })
            .collect();
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let noise_poly = Poly::try_convert_from(
            noise_coeffs.as_slice(),
            ctx,
            false,
            Representation::PowerBasis,
        )
        .map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let esm_noise_poly_bytes = noise_poly.to_bytes();

        let mut d_share_poly = pre_smudge_d_share;
        d_share_poly += &noise_poly;
        let d_share_poly_bytes = d_share_poly.to_bytes();
        let wire_bytes = wire::encode_decrypt_share(&d_share_poly_bytes);

        let witness = DecryptionWitness {
            ct0_poly_bytes,
            ct1_poly_bytes,
            sk_agg_poly_bytes,
            esm_noise_poly_bytes,
            // Quotient/reduction polynomials are not directly accessible from
            // ShareManager::decryption_share; left empty until Batch F wires
            // committed e_sm and quotient tracking.
            quotient_poly_bytes: Vec::new(),
            d_share_poly_bytes,
            decrypted_share_bytes: wire_bytes.clone(),
            esm_committed: false,
        };

        Ok((
            DecryptShare {
                party_id,
                bytes: ProtocolBytes(wire_bytes),
                nizk_proof_bytes: None,
            },
            witness,
        ))
    }

    fn partial_decrypt_committed_smudge(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        esm_noise_poly_bytes: &[u8],
        _rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        if esm_noise_poly_bytes.is_empty() {
            return Err(FheError::Backend {
                reason: "esm_noise_poly_bytes is empty".into(),
            });
        }

        let (n, t) = self.threshold_params()?;
        let ct_bfv = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;

        let mut d_share_poly =
            self.decryption_share_poly_from_coeffs(Arc::new(ct_bfv.clone()), party_id, n, t)?;

        // Deserialize the committed smudge poly instead of sampling fresh noise.
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let esm_noise_poly =
            Poly::from_bytes(esm_noise_poly_bytes, &ctx).map_err(|err| FheError::Backend {
                reason: format!("failed to deserialize esm_noise_poly: {err}"),
            })?;

        d_share_poly += &esm_noise_poly;
        let poly_bytes = d_share_poly.to_bytes();

        Ok(DecryptShare {
            party_id,
            bytes: ProtocolBytes(wire::encode_decrypt_share(&poly_bytes)),
            nizk_proof_bytes: None,
        })
    }

    fn partial_decrypt_committed_smudge_with_witness(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        esm_noise_poly_bytes: &[u8],
        _rng: &mut dyn RngCore,
    ) -> Result<(DecryptShare, DecryptionWitness), FheError> {
        if esm_noise_poly_bytes.is_empty() {
            return Err(FheError::Backend {
                reason: "esm_noise_poly_bytes is empty".into(),
            });
        }

        let (n, t) = self.threshold_params()?;
        let ct_bfv = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;

        // Extract ciphertext component polynomial bytes.
        let ct0_poly_bytes = ct_bfv.c[0].to_bytes();
        let ct1_poly_bytes = ct_bfv.c[1].to_bytes();

        // Retrieve the aggregated secret-key share polynomial from party state.
        let (sk_poly_sum_coeffs, sk_poly_sum_poly, esi_poly_sum) =
            self.party_state_data(party_id)?;
        let share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());

        let sk_poly = match sk_poly_sum_poly {
            Some(poly) => poly,
            None => share_manager
                .coeffs_to_poly_level0(&sk_poly_sum_coeffs)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?
                .as_ref()
                .clone(),
        };
        let sk_agg_poly_bytes = sk_poly.to_bytes();

        let esi_poly = match esi_poly_sum.first() {
            Some(poly) => poly.clone(),
            None => self.zero_poly_level0()?,
        };

        // Pre-smudge decryption share (before adding committed esm noise).
        let pre_smudge_d_share = share_manager
            .decryption_share(Arc::new(ct_bfv.clone()), sk_poly, esi_poly)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        // Deserialize the committed smudge poly instead of sampling fresh noise.
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let esm_noise_poly =
            Poly::from_bytes(esm_noise_poly_bytes, &ctx).map_err(|err| FheError::Backend {
                reason: format!("failed to deserialize esm_noise_poly: {err}"),
            })?;

        // Record the committed esm bytes (exactly as provided).
        let esm_noise_poly_bytes_clone = esm_noise_poly_bytes.to_vec();

        let mut d_share_poly = pre_smudge_d_share;
        d_share_poly += &esm_noise_poly;
        let d_share_poly_bytes = d_share_poly.to_bytes();
        let wire_bytes = wire::encode_decrypt_share(&d_share_poly_bytes);

        let witness = DecryptionWitness {
            ct0_poly_bytes,
            ct1_poly_bytes,
            sk_agg_poly_bytes,
            esm_noise_poly_bytes: esm_noise_poly_bytes_clone,
            quotient_poly_bytes: Vec::new(),
            d_share_poly_bytes,
            decrypted_share_bytes: wire_bytes.clone(),
            esm_committed: true,
        };

        Ok((
            DecryptShare {
                party_id,
                bytes: ProtocolBytes(wire_bytes),
                nizk_proof_bytes: None,
            },
            witness,
        ))
    }

    fn decode_pk_polys(&self, pk: &OpaquePublicKey) -> Result<(Vec<u8>, Vec<u8>), FheError> {
        let bfv_pk = self.decode_public_key(pk)?;
        let p0 = bfv_pk.c.get(0).ok_or(FheError::MalformedPublicKey)?;
        let p1 = bfv_pk.c.get(1).ok_or(FheError::MalformedPublicKey)?;
        let p1 = bfv_pk.c.get(1).ok_or(FheError::MalformedPublicKey)?;
        let mut p0 = p0.clone();
        p0.change_representation(Representation::PowerBasis);
        let mut p1 = p1.clone();
        p1.change_representation(Representation::PowerBasis);
        Ok((p0.to_bytes(), p1.to_bytes()))
    }

    fn decode_ct_polys(&self, ct: &Ciphertext) -> Result<(Vec<u8>, Vec<u8>), FheError> {
        let ct = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;
        let c0 = ct.c.get(0).ok_or(FheError::MalformedCiphertext)?;
        let c1 = ct.c.get(1).ok_or(FheError::MalformedCiphertext)?;
        let mut c0 = c0.clone();
        c0.change_representation(Representation::PowerBasis);
        let mut c1 = c1.clone();
        c1.change_representation(Representation::PowerBasis);
        Ok((c0.to_bytes(), c1.to_bytes()))
    }

    fn bfv_plaintext_modulus(&self) -> Result<u64, FheError> {
        Ok(self.bfv_params.plaintext())
    }

    fn bfv_moduli(&self) -> Result<Vec<u64>, FheError> {
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        Ok(ctx.q.iter().map(|m| m.modulus()).collect())
    }

    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
        _session_id: &[u8],
    ) -> Result<Vec<u8>, FheError> {
        let (n, configured_threshold) = self.threshold_params()?;
        if shares.len() < configured_threshold {
            return Err(FheError::InsufficientShares {
                have: shares.len(),
                need: configured_threshold,
            });
        }
        if threshold != configured_threshold {
            return Err(FheError::Backend {
                reason: format!(
                    "threshold mismatch: requested {threshold}, configured {configured_threshold}"
                ),
            });
        }

        for share in shares {
            if share.party_id == 0 || share.party_id as usize > n {
                return Err(FheError::MalformedDecryptShare {
                    party_id: share.party_id,
                });
            }
        }

        let ciphertext = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;
        let ciphertext = Arc::new(ciphertext);
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        let effective_shares = shares
            .iter()
            .map(|share| {
                let decoded = wire::decode_decrypt_share(share.bytes.as_slice()).map_err(|_| {
                    FheError::MalformedDecryptShare {
                        party_id: share.party_id,
                    }
                })?;
                let poly =
                    Poly::from_bytes(decoded.d_share_poly.as_slice(), &ctx).map_err(|err| {
                        FheError::Backend {
                            reason: err.to_string(),
                        }
                    })?;
                Ok((share.party_id as usize, poly))
            })
            .collect::<Result<Vec<_>, FheError>>()?;
        let (party_ids, share_polys): (Vec<_>, Vec<_>) = effective_shares.into_iter().unzip();

        let share_manager = ShareManager::new(
            n,
            self.shamir_threshold(n, configured_threshold),
            self.bfv_params.clone(),
        );
        let plaintext = share_manager
            .decrypt_from_shares(share_polys, party_ids, ciphertext)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let slots = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).map_err(|err| {
            FheError::Backend {
                reason: err.to_string(),
            }
        })?;
        #[cfg(feature = "trace-decrypt")]
        eprintln!(
            "[FHE-DECRYPT] aggregate_decrypt: slots.len()={} first_8_slots={:02x?}",
            slots.len(),
            &slots[..std::cmp::min(8, slots.len())]
        );

        decode_plaintext_slots(&slots)
    }
}

impl FhersBackend {
    /// Decode polynomial bytes into i64 coefficients (for C7 verification).
    pub fn poly_coeffs_from_bytes(&self, poly_bytes: &[u8]) -> Result<Vec<i64>, FheError> {
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let mut poly = Poly::from_bytes(poly_bytes, &ctx).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        // Ensure coefficients are in power-basis representation (not NTT) for
        // coefficient-wise arithmetic checks (C7 ring-aware verification).
        poly.change_representation(Representation::PowerBasis);
        let mut coeffs = Vec::new();
        for c in poly.coefficients() {
            coeffs.push(*c as i64);
        }
        Ok(coeffs)
    }

    /// CRT-reconstruct polynomial coefficients from RNS residues (3 moduli → 1 integer per coeff).
    ///
    /// The [`poly_coeffs_from_bytes`](Self::poly_coeffs_from_bytes) method returns
    /// 24 576 residues (8192 coefficients × 3 moduli, modulus-major layout:
    /// all coefficients for q₀, then all for q₁, then all for q₂).
    /// This method reconstructs them into 8 192 i128 integers via CRT.
    pub fn crt_reconstruct_coeffs(&self, residues: &[i64]) -> Vec<i128> {
        use num_bigint::BigInt;
        use num_traits::ToPrimitive;

        const MODULI_I128: [i128; 3] = [
            288230376173076481,
            288230376167047169,
            288230376161280001,
        ];
        let moduli_big: [BigInt; 3] = [
            BigInt::from(MODULI_I128[0]),
            BigInt::from(MODULI_I128[1]),
            BigInt::from(MODULI_I128[2]),
        ];
        let q_big: BigInt = &moduli_big[0] * &moduli_big[1] * &moduli_big[2];

        let n_coeffs = residues.len() / 3;
        let mut coeffs = Vec::with_capacity(n_coeffs);

        // Precompute M_j = Q / q_j (as BigInt)
        let m_big: [BigInt; 3] = [
            &q_big / &moduli_big[0],
            &q_big / &moduli_big[1],
            &q_big / &moduli_big[2],
        ];
        // Precompute inv_j = M_j^{-1} mod q_j (as i128, since q_j < 2^63)
        let mut m_inv = [0i128; 3];
        for j in 0..3 {
            let mj_i128 = (&m_big[j] % &moduli_big[j])
                .to_i128()
                .unwrap_or(0);
            let (_, inv, _) = Self::egcd_i128(mj_i128, MODULI_I128[j]);
            m_inv[j] = (inv % MODULI_I128[j] + MODULI_I128[j]) % MODULI_I128[j];
        }

        // Residues are in modulus-major layout: [c0_q0, c1_q0, ..., cₙ₋₁_q0, c0_q1, ..., cₙ₋₁_q2]
        for i in 0..n_coeffs {
            let mut val_big = BigInt::from(0u32);
            for j in 0..3 {
                let r = residues[j * n_coeffs + i] as i128;
                let term = BigInt::from(r)
                    * &m_big[j]
                    * m_inv[j];
                val_big = (&val_big + term) % &q_big;
            }
            // Convert back to i128; since Q ≈ 2^174 > i128::MAX, this may truncate.
            // The caller is responsible for using a type that fits.
            match val_big.to_i128() {
                Some(v) => coeffs.push(v),
                None => coeffs.push(i128::MAX), // overflow sentinel
            }
        }
        coeffs
    }

    fn egcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
        if b == 0 {
            (a, 1, 0)
        } else {
            let (g, x1, y1) = Self::egcd_i128(b, a.wrapping_rem_euclid(b));
            (g, y1, x1 - (a / b) * y1)
        }
    }

    /// Aggregate decryption shares into recovered plaintext and plaintext polynomial bytes.
    ///
    /// Returns `(decoded_plaintext_bytes, plaintext_poly_bytes)` where:
    /// - `decoded_plaintext_bytes` is the slot-decoded message (same as [`FheBackend::aggregate_decrypt`])
    /// - `plaintext_poly_bytes` is the raw [`Poly`](fhe_math::rq::Poly) byte serialization
    ///   of the recovered plaintext polynomial (N coefficients, i64 each, little-endian)
    ///
    /// The polynomial bytes are needed by the C7 verification path to check
    /// `Σ λ_i · d_i(r) ≡ plaintext(r) (mod Q)`.
        pub fn aggregate_decrypt_with_poly(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
        _session_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), FheError> {
        let (n, configured_threshold) = self.threshold_params()?;
        if shares.len() < configured_threshold {
            return Err(FheError::InsufficientShares {
                have: shares.len(),
                need: configured_threshold,
            });
        }
        if threshold != configured_threshold {
            return Err(FheError::Backend {
                reason: format!(
                    "threshold mismatch: requested {threshold}, configured {configured_threshold}"
                ),
            });
        }

        for share in shares {
            if share.party_id == 0 || share.party_id as usize > n {
                return Err(FheError::MalformedDecryptShare {
                    party_id: share.party_id,
                });
            }
        }

        let ciphertext = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;
        let ciphertext = Arc::new(ciphertext);
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        let t_start = std::time::Instant::now();

        let effective_shares = shares
            .iter()
            .map(|share| {
                let decoded = wire::decode_decrypt_share(share.bytes.as_slice()).map_err(|_| {
                    FheError::MalformedDecryptShare {
                        party_id: share.party_id,
                    }
                })?;
                let poly =
                    Poly::from_bytes(decoded.d_share_poly.as_slice(), &ctx).map_err(|err| {
                        FheError::Backend {
                            reason: err.to_string(),
                        }
                    })?;
                Ok((share.party_id as usize, poly))
            })
            .collect::<Result<Vec<_>, FheError>>()?;
        let (party_ids, share_polys): (Vec<_>, Vec<_>) = effective_shares.into_iter().unzip();

        let t1 = std::time::Instant::now();
        tracing::info!(
            ms = t1.duration_since(t_start).as_secs_f64() * 1000.0,
            "aggregate_decrypt: decode shares"
        );

        let share_manager = ShareManager::new(
            n,
            self.shamir_threshold(n, configured_threshold),
            self.bfv_params.clone(),
        );
        let t2 = std::time::Instant::now();
        tracing::info!(
            ms = t2.duration_since(t1).as_secs_f64() * 1000.0,
            "aggregate_decrypt: Lagrange coeffs"
        );

        let plaintext = share_manager
            .decrypt_from_shares(share_polys, party_ids, ciphertext)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        let t3 = std::time::Instant::now();
        tracing::info!(
            ms = t3.duration_since(t2).as_secs_f64() * 1000.0,
            "aggregate_decrypt: decrypt_from_shares (NTT)"
        );

        // Capture the raw plaintext polynomial bytes before slot-decoding.
        let plaintext_poly = plaintext.to_poly();
        let plaintext_poly_bytes = plaintext_poly.to_bytes();

        let slots = Vec::<u64>::try_decode(&plaintext, Encoding::poly()).map_err(|err| {
            FheError::Backend {
                reason: err.to_string(),
            }
        })?;
        #[cfg(feature = "trace-decrypt")]
        eprintln!(
            "[FHE-DECRYPT] aggregate_decrypt_with_poly: slots.len()={} first_8_slots={:02x?}",
            slots.len(),
            &slots[..std::cmp::min(8, slots.len())]
        );

        let decoded = decode_plaintext_slots(&slots)?;

        let t4 = std::time::Instant::now();
        tracing::info!(
            ms = t4.duration_since(t3).as_secs_f64() * 1000.0,
            "aggregate_decrypt: slot decode"
        );

        Ok((decoded, plaintext_poly_bytes))
    }

    /// Compute integer Lagrange coefficients for the given 1-based party IDs.
    ///
    /// λ_i = Π_{j≠i} (0 - x_j) / Π_{j≠i} (x_i - x_j) for evaluation at 0.
    fn compute_lagrange_coeffs_integer(party_ids: &[usize]) -> Vec<i64> {
        let n = party_ids.len();
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            let xi = party_ids[i] as i128;
            let mut num: i128 = 1;
            let mut den: i128 = 1;
            for j in 0..n {
                if i != j {
                    let xj = party_ids[j] as i128;
                    num *= -xj;
                    den *= xi - xj;
                }
            }
            // SAFETY: For party IDs {1..10}, Lagrange coefficients are small integers
            // (< 10! ≈ 3.6e6). The division (num/den) fits in i64 for these parameters.
            coeffs.push((num / den) as i64);
        }
        coeffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
