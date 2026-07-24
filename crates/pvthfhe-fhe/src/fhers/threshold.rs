//! Threshold helpers for the fhe.rs BFV backend: Shamir threshold convention,
//! O(n^2) resharing, decryption-share construction, and share-context
//! validation.

use super::{slots_to_bytes, FhersBackend};
use crate::{error::FheError, wire};
use fhe::bfv::Ciphertext as BfvCiphertext;
use fhe::trbfv::ShareManager;
use fhe_math::rq::{Poly, Representation};
use ndarray::Array2;
use pvthfhe_foundations::domain_tags::Tag;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};

pub(super) fn decode_plaintext_slots(slots: &[u64]) -> Result<Vec<u8>, FheError> {
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

pub(super) fn decrypt_share_ciphertext_hash(ciphertext_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(ciphertext_bytes).into()
}

pub(super) fn validate_decrypt_share_context(
    submitted_party_id: u32,
    expected_ciphertext_hash: &[u8; 32],
    decoded: &wire::DecryptShareV2,
) -> Result<(), FheError> {
    if decoded.party_id != submitted_party_id {
        return Err(FheError::DecryptShareContextMismatch {
            party_id: submitted_party_id,
            field: "party_id",
        });
    }
    if &decoded.ciphertext_hash != expected_ciphertext_hash {
        return Err(FheError::DecryptShareContextMismatch {
            party_id: submitted_party_id,
            field: "ct_hash",
        });
    }

    Ok(())
}

impl FhersBackend {
    pub(super) fn shamir_threshold(&self, _n: usize, t: usize) -> usize {
        // fhe.rs ShareManager stores threshold as the Shamir polynomial degree.
        // decrypt_from_shares requires threshold + 1 shares.
        // Our convention: t = number of shares needed for reconstruction.
        // Convert to fhe.rs convention: polynomial degree = t - 1.
        if t == 0 {
            return 0;
        }
        t - 1
    }

    pub(super) fn zero_poly_level0(&self) -> Result<Poly, FheError> {
        Ok(Poly::zero(
            self.bfv_params
                .ctx_at_level(0)
                .map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?,
            Representation::PowerBasis,
        ))
    }

    pub(super) fn decryption_share_poly_from_coeffs(
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

    #[allow(dead_code)]
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

    #[allow(clippy::type_complexity)]
    pub(super) fn compute_party_sk_sums(
        &self,
        n: usize,
        t: usize,
        session_seed: [u8; 32],
    ) -> Result<(), FheError> {
        tracing::debug!(
            n_participants = n,
            threshold = t,
            "setup_threshold: computing Shamir shares for all parties (O(n²·degree))"
        );
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
        tracing::info!(
            n = n,
            ms = t_pre_read.elapsed().as_secs_f64() * 1000.0,
            "setup_threshold: pre-read sk_coeffs"
        );

        let threshold = self.shamir_threshold(n, t);
        let bfv_params = self.bfv_params.clone();
        let mut distributed = HashMap::<u32, Vec<Array2<u64>>>::new();
        for party_id in 1u32..=max_party_id {
            distributed.insert(party_id, Vec::with_capacity(n));
        }

        // ── Parallel: each party generates Shamir shares for all recipients ──
        // allow-seeded-rng: deterministic Shamir share generation so parallel
        // execution is deterministic and reproducible.
        let all_shares: Vec<Result<((u32, Vec<Array2<u64>>), Vec<Vec<i64>>), FheError>> = (1u32
            ..=max_party_id)
            .into_par_iter()
            .map(|party_id| {
                let mut sm = ShareManager::new(n, threshold, bfv_params.clone());
                let sk_poly = sm
                    .coeffs_to_poly_level0(&all_sk_coeffs[&party_id])
                    .map_err(|err| FheError::Backend {
                        reason: err.to_string(),
                    })?;
                // M3: Use full 256-bit deterministic seed bound to session_seed
                // so that Shamir shares differ across DKG ceremonies.
                let mut h = Sha256::new();
                h.update(Tag::ShareRngSeedV2.as_bytes());
                h.update(session_seed);
                h.update(party_id.to_be_bytes());
                h.update(n.to_be_bytes());
                h.update(threshold.to_be_bytes());
                h.update(bfv_params.degree().to_be_bytes());
                let digest = h.finalize();
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&digest);
                // allow-seeded-rng: deterministic per-party Shamir-share RNG for reproducible parallel DKG (M3); seed = SHA256(domain ‖ session_seed ‖ party_id ‖ n ‖ t ‖ degree)
                let mut rng = StdRng::from_seed(seed);
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
        let total_allocated_mb = n_parties
            * (n_parties - 1)
            * self.bfv_params.moduli().len()
            * self.bfv_params.degree()
            * 8
            / (1024 * 1024);
        tracing::info!(
            n = n,
            ms = t_parallel.elapsed().as_secs_f64() * 1000.0,
            total_allocated_mb = total_allocated_mb,
            "setup_threshold: parallel Shamir generation"
        );

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

        let t_merge = std::time::Instant::now();
        tracing::info!(
            n = n,
            ms = t_merge.elapsed().as_secs_f64() * 1000.0,
            "setup_threshold: sequential merge into distributed"
        );

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
        tracing::info!(
            n = n,
            ms = t_aggregate.elapsed().as_secs_f64() * 1000.0,
            "setup_threshold: aggregate collected shares"
        );

        let t_total = std::time::Instant::now();
        tracing::info!(
            n = n,
            ms = t_total.elapsed().as_secs_f64() * 1000.0,
            "setup_threshold: DONE"
        );

        Ok(())
    }
}
