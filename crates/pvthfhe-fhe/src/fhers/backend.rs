//! [`FheBackend`] trait implementation for [`FhersBackend`]: parameter
//! loading, key generation, encryption, and threshold decryption. Kept as a
//! single impl block because Rust coherence forbids splitting a trait impl
//! across modules.

use super::{
    encrypt::encode_plaintext_slots,
    threshold::{decrypt_share_ciphertext_hash, decode_plaintext_slots, validate_decrypt_share_context},
    FhersBackend, PartyState, SIGMA_SMUDGE,
};
use crate::{
    error::FheError,
    mock,
    types::{Ciphertext, DecryptShare, KeygenShare, PublicKey as OpaquePublicKey},
    wire, DecryptionWitness, EncryptionWitness, FheBackend,
};
use fhe::bfv::{
    BfvParametersBuilder, Ciphertext as BfvCiphertext, Encoding, Plaintext,
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
use pvthfhe_foundations::types::ProtocolBytes;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

impl FheBackend for FhersBackend {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        // Parse and validate params — this succeeds so callers can inspect them.
        let params = mock::parse_params(toml)?;
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
            #[cfg(debug_assertions)]
            owned_party_id: std::sync::Mutex::new(None),
            setup_threshold_called: Arc::new(AtomicBool::new(false)),
            dkg_initialized: Arc::new(AtomicBool::new(false)),
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
        let (p0_share, _pk_1, _sk_poly, keygen_error) =
            PublicKeyShare::new_extended(&sk, crp.clone(), &mut seeded_rng).map_err(|err| {
                FheError::Backend {
                    reason: err.to_string(),
                }
            })?;

        let mut error_pb = keygen_error;
        error_pb.change_representation(Representation::PowerBasis);
        let keygen_e_bytes = error_pb.to_bytes();

        let party_state = PartyState {
            sk_poly_sum: sk.coeffs.to_vec(),
            sk_poly_sum_poly: None,
            esi_poly_sum: Vec::new(),
            sk_shamir_shares: Vec::new(),
            keygen_error_coeffs: None,
            keygen_sk_coeffs: Some(sk.coeffs.to_vec()),
            keygen_error_poly_bytes: Some(keygen_e_bytes),
        };

        let mut party_states = self.party_states.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        party_states.insert(party_id, party_state);

        #[cfg(debug_assertions)]
        {
            let mut owned = self
                .owned_party_id
                .lock()
                .map_err(|err| FheError::Backend {
                    reason: format!("owned_party_id lock poisoned: {err}"),
                })?;
            *owned = Some(party_id);
        }

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

    fn keygen_witness(&self, party_id: u32) -> Result<Option<(Vec<i64>, Vec<u8>)>, FheError> {
        self.party_keygen_witness(party_id)
    }

    fn setup_threshold(&self, n: usize, t: usize, session_seed: [u8; 32]) -> Result<(), FheError> {
        if t == 0 || t > n {
            return Err(FheError::Backend {
                reason: format!("invalid threshold parameters: n={n}, t={t}"),
            });
        }
        // Honest-majority reconstruction threshold per threat-model-v1.md §2.2
        // (t = floor(n/2)+1). Prior (n-1)/2 bound (commit 80a0c82)
        // contradicted the documented model; this is spec conformance, not a relaxation.
        let max_t = n / 2 + 1;
        if t > max_t {
            return Err(FheError::Backend {
                reason: format!("threshold t={t} exceeds max_t={max_t} for n={n}. Must satisfy t ≤ floor(n/2)+1 for the honest-majority threshold policy; Shamir privacy holds against fewer than t shares.")
            });
        }
        if std::env::var("PVTHFHE_SKIP_SETUP_THRESHOLD").as_deref() != Ok("1") {
            self.compute_party_sk_sums(n, t, session_seed)?;
        } else {
            tracing::info!("PVTHFHE_SKIP_SETUP_THRESHOLD=1: skipping O(n²) Shamir regeneration (coeffs→poly deferred to partial_decrypt)");
        }

        *self.threshold_n.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })? = Some(n);
        *self.threshold_t.lock().map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })? = Some(t);

        self.setup_threshold_called.store(true, Ordering::SeqCst);
        self.dkg_initialized.store(true, Ordering::SeqCst);

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
        let ciphertext_hash = decrypt_share_ciphertext_hash(&ct.bytes);
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
            bytes: ProtocolBytes(wire::encode_decrypt_share(
                party_id,
                &ciphertext_hash,
                &poly_bytes,
            )),
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
        let ciphertext_hash = decrypt_share_ciphertext_hash(&ct.bytes);
        let wire_bytes =
            wire::encode_decrypt_share(party_id, &ciphertext_hash, &d_share_poly_bytes);

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
            Poly::from_bytes(esm_noise_poly_bytes, ctx).map_err(|err| FheError::Backend {
                reason: format!("failed to deserialize esm_noise_poly: {err}"),
            })?;

        d_share_poly += &esm_noise_poly;
        let poly_bytes = d_share_poly.to_bytes();
        let ciphertext_hash = decrypt_share_ciphertext_hash(&ct.bytes);

        Ok(DecryptShare {
            party_id,
            bytes: ProtocolBytes(wire::encode_decrypt_share(
                party_id,
                &ciphertext_hash,
                &poly_bytes,
            )),
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
            Poly::from_bytes(esm_noise_poly_bytes, ctx).map_err(|err| FheError::Backend {
                reason: format!("failed to deserialize esm_noise_poly: {err}"),
            })?;

        // Record the committed esm bytes (exactly as provided).
        let esm_noise_poly_bytes_clone = esm_noise_poly_bytes.to_vec();

        let mut d_share_poly = pre_smudge_d_share;
        d_share_poly += &esm_noise_poly;
        let d_share_poly_bytes = d_share_poly.to_bytes();
        let ciphertext_hash = decrypt_share_ciphertext_hash(&ct.bytes);
        let wire_bytes =
            wire::encode_decrypt_share(party_id, &ciphertext_hash, &d_share_poly_bytes);

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
        let _p1 = bfv_pk.c.get(1).ok_or(FheError::MalformedPublicKey)?;
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
        let c0 = ct.c.first().ok_or(FheError::MalformedCiphertext)?;
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

    /// Aggregate threshold decryption from validated shares.
    ///
    /// ⚠️ **Trust Model**: This method computes the plaintext via Lagrange
    /// interpolation WITHOUT post-hoc verification. The result MUST be
    /// re-verified through the C7 Noir circuit + IVC proof chain + on-chain
    /// UltraHonk verification before being trusted in production.
    ///
    /// This method is provided for:
    /// - Test scenarios (no adversary modeled)
    /// - Simulator/pipeline benchmarks
    /// - As input to the `aggregator_final` circuit which independently
    ///   verifies correctness through Schwartz-Zippel identity checking
    ///
    /// In production, the full verification pipeline (NIZK → Circuit → IVC → Honk)
    /// MUST be executed after this method returns.
    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
        session_id: &[u8],
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

        if !session_id.is_empty() && !self.setup_threshold_called.load(Ordering::SeqCst) {
            return Err(FheError::Backend {
                reason: "setup_threshold not called for this backend".into(),
            });
        }

        for share in shares {
            if share.party_id == 0 || share.party_id as usize > n {
                return Err(FheError::MalformedDecryptShare {
                    party_id: share.party_id,
                });
            }
        }
        let mut seen = std::collections::HashSet::new();
        for share in shares {
            if !seen.insert(share.party_id) {
                return Err(FheError::MalformedDecryptShare {
                    party_id: share.party_id,
                });
            }
        }

        let expected_ciphertext_hash = decrypt_share_ciphertext_hash(&ct.bytes);
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
                validate_decrypt_share_context(
                    share.party_id,
                    &expected_ciphertext_hash,
                    &decoded,
                )?;
                let poly =
                    Poly::from_bytes(decoded.d_share_poly.as_slice(), ctx).map_err(|err| {
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
