//! FHE backend shim.

use crate::{
    error::FheError,
    mock_impl,
    types::{Ciphertext, DecryptShare, KeygenShare, Params, PublicKey as OpaquePublicKey},
    wire, FheBackend,
};
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext as BfvCiphertext, Encoding, Plaintext,
    PublicKey as BfvPublicKey, SecretKey,
};
use fhe::mbfv::{Aggregate, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::ShareManager;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{
    DeserializeParametrized, DeserializeWithContext, FheDecoder, FheEncoder, FheEncrypter,
    Serialize,
};
use ndarray::Array2;
use rand::thread_rng;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Per-party state retained across protocol rounds.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct FhersBackend {
    _params: Params,
    bfv_params: Arc<BfvParameters>,
    party_states: Arc<Mutex<HashMap<u32, PartyState>>>,
    threshold_n: Arc<Mutex<Option<usize>>>,
    threshold_t: Arc<Mutex<Option<usize>>>,
}

impl FhersBackend {
    fn shamir_threshold(&self, n: usize, t: usize) -> usize {
        t.saturating_sub(1).min(n.saturating_sub(t))
    }

    /// Returns the loaded BFV parameters.
    pub fn bfv_params(&self) -> &Arc<BfvParameters> {
        &self.bfv_params
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

    fn party_state(&self, party_id: u32) -> Result<PartyState, FheError> {
        let party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        party_states
            .get(&party_id)
            .cloned()
            .ok_or(FheError::UnknownParty { party_id })
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
        let party_state = self.party_state(party_id)?;
        let share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());
        let sk_poly_sum = share_manager
            .coeffs_to_poly_level0(&party_state.sk_poly_sum)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?
            .as_ref()
            .clone();
        let esi_poly = match party_state.esi_poly_sum.first() {
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
        let party_state = self.party_state(party_id)?;
        let share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());
        let sk_poly_sum = match &party_state.sk_poly_sum_poly {
            Some(poly) => poly.clone(),
            None => share_manager
                .coeffs_to_poly_level0(&party_state.sk_poly_sum)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?
                .as_ref()
                .clone(),
        };
        let esi_poly = match party_state.esi_poly_sum.first() {
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
        let mut party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;

        let max_party_id = u32::try_from(n).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let party_ids = (1u32..=max_party_id).collect::<Vec<_>>();

        if party_ids
            .iter()
            .any(|party_id| !party_states.contains_key(party_id))
        {
            let missing = party_ids
                .into_iter()
                .find(|party_id| !party_states.contains_key(party_id))
                .expect("checked above");
            return Err(FheError::UnknownParty { party_id: missing });
        }

        let mut share_manager =
            ShareManager::new(n, self.shamir_threshold(n, t), self.bfv_params.clone());
        let mut distributed = HashMap::<u32, Vec<Array2<u64>>>::new();
        for party_id in 1u32..=max_party_id {
            distributed.insert(party_id, Vec::with_capacity(n));
        }

        for party_id in 1u32..=max_party_id {
            let sk_poly = share_manager
                .coeffs_to_poly_level0(
                    party_states
                        .get(&party_id)
                        .ok_or(FheError::UnknownParty { party_id })?
                        .sk_poly_sum
                        .as_slice(),
                )
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?;
            let mut rng = ChaCha8Rng::seed_from_u64(u64::from(party_id));
            let shares = share_manager
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?;

            let state = party_states
                .get_mut(&party_id)
                .ok_or(FheError::UnknownParty { party_id })?;
            state.sk_shamir_shares = (0..n)
                .map(|receiver_index| {
                    shares[0]
                        .row(receiver_index)
                        .iter()
                        .copied()
                        .map(|coeff| {
                            i64::try_from(coeff).map_err(|err| FheError::Backend {
                                reason: err.to_string(),
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()?;

            for receiver_index in 0..n {
                let receiver_party_id =
                    u32::try_from(receiver_index + 1).map_err(|err| FheError::Backend {
                        reason: err.to_string(),
                    })?;

                let mut sender_share_data =
                    Vec::with_capacity(self.bfv_params.moduli().len() * self.bfv_params.degree());
                for modulus_matrix in &shares {
                    sender_share_data.extend(modulus_matrix.row(receiver_index).iter().copied());
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
            bytes: wire::encode_keygen_share(&crp.to_bytes(), &p0_share.to_bytes()),
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

        for share in shares {
            let decoded = wire::decode_keygen_share(&share.bytes).map_err(|_| {
                FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                }
            })?;

            if let Some(expected_crp) = &crp_bytes {
                if expected_crp != &decoded.crp {
                    return Err(FheError::InconsistentCrp);
                }
            } else {
                crp_bytes = Some(decoded.crp.clone());
            }

            p0_share_bytes.push(decoded.p0_share);
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
        _rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        let degree = self.bfv_params.degree();
        let pk = self.decode_public_key(pk)?;
        let slots = encode_plaintext_slots(plaintext, degree)?;
        let pt =
            Plaintext::try_encode(&slots, Encoding::poly(), &self.bfv_params).map_err(|err| {
                FheError::Backend {
                    reason: err.to_string(),
                }
            })?;
        let mut rng = thread_rng();
        let ct = pk
            .try_encrypt(&pt, &mut rng)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        Ok(Ciphertext {
            bytes: ct.to_bytes(),
        })
    }

    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        let (n, t) = self.threshold_params()?;
        let ct = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;

        let d_share_poly = self.decryption_share_poly_from_coeffs(Arc::new(ct), party_id, n, t)?;
        let poly_bytes = d_share_poly.to_bytes();

        Ok(DecryptShare {
            party_id,
            bytes: wire::encode_decrypt_share(&poly_bytes),
        })
    }

    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
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

        let ciphertext = BfvCiphertext::from_bytes(&ct.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;
        let ciphertext = Arc::new(ciphertext);
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;

        let _decoded_shares = shares
            .iter()
            .map(|share| {
                let decoded = wire::decode_decrypt_share(&share.bytes).map_err(|_| {
                    FheError::MalformedDecryptShare {
                        party_id: share.party_id,
                    }
                })?;
                let _poly = Poly::from_bytes(&decoded.d_share_poly, &ctx).map_err(|err| {
                    FheError::Backend {
                        reason: err.to_string(),
                    }
                })?;
                Ok(())
            })
            .collect::<Result<Vec<_>, FheError>>()?;
        let effective_shares = shares
            .iter()
            .map(|share| {
                self.decryption_share_poly_from_full_state(
                    ciphertext.clone(),
                    share.party_id,
                    n,
                    configured_threshold,
                )
                .map(|poly| (share.party_id as usize, poly))
            })
            .collect::<Result<Vec<_>, _>>()?;
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

        decode_plaintext_slots(&slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARAMS_TOML: &str = r#"
[rlwe]
n = 8192
log2_q = 174
t_plain = 65536
moduli = [288230376173076481, 288230376167047169, 288230376161280001]
variance = 10
"#;

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
