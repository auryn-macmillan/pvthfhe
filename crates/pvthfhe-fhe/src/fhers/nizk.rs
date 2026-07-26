//! NIZK glue and C7 verification helpers for the fhe.rs BFV backend.

use super::{
    threshold::{
        decode_plaintext_slots, decrypt_share_ciphertext_hash, validate_decrypt_share_context,
    },
    FhersBackend,
};
use crate::{
    error::FheError,
    types::{Ciphertext, DecryptShare},
    wire,
};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use fhe::bfv::{Ciphertext as BfvCiphertext, Encoding};
use fhe::trbfv::ShareManager;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, FheDecoder, Serialize};
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use std::sync::{atomic::Ordering, Arc};

impl FhersBackend {
    /// Decode polynomial bytes into i64 coefficients (for C7 verification).
    pub fn poly_coeffs_from_bytes(&self, poly_bytes: &[u8]) -> Result<Vec<i64>, FheError> {
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let mut poly = Poly::from_bytes(poly_bytes, ctx).map_err(|err| FheError::Backend {
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

    /// CRT-reconstruct polynomial coefficients from RNS residues into BN254 Fr values.
    ///
    /// Takes modulus-major residues (24 576 values = 8192 coeffs × 3 moduli) and
    /// returns 8 192 centered coefficients in the BN254 scalar field. Each coefficient
    /// is CRT-reconstructed and then centered to [-Q/2, Q/2) before embedding in Fr.
    ///
    /// Used by the C7 G3 plaintext-binding verification for polynomial evaluation
    /// in the BN254 field.
    pub fn poly_coeffs_fr_reconstruct(&self, residues: &[i64]) -> Vec<Fr> {
        use num_bigint::BigInt;

        let n_coeffs = residues.len() / 3;
        let mut coeffs = Vec::with_capacity(n_coeffs);

        // CRT constants (same as crt_reconstruct_coeffs):
        //   qⱼ = modulus, Q = q₀·q₁·q₂, Mⱼ = Q/qⱼ, invⱼ = Mⱼ⁻¹ mod qⱼ
        const Q0: u64 = 288230376173076481;
        const Q1: u64 = 288230376167047169;
        const Q2: u64 = 288230376161280001;

        let q0_big = BigInt::from(Q0);
        let q1_big = BigInt::from(Q1);
        let q2_big = BigInt::from(Q2);
        let q_big = &q0_big * &q1_big * &q2_big;
        let q_half_big = &q_big / 2u32; // floor(Q/2), Q is odd

        // Mⱼ = Q / qⱼ
        let m0_big = &q1_big * &q2_big;
        let m1_big = &q0_big * &q2_big;
        let m2_big = &q0_big * &q1_big;

        // invⱼ = Mⱼ⁻¹ mod qⱼ (compute via extended Euclidean)
        let m0_mod = (&m0_big % &q0_big).iter_u64_digits().next().unwrap_or(0);
        let m1_mod = (&m1_big % &q1_big).iter_u64_digits().next().unwrap_or(0);
        let m2_mod = (&m2_big % &q2_big).iter_u64_digits().next().unwrap_or(0);
        let (_, inv0_s, _) = Self::egcd_i128(m0_mod as i128, Q0 as i128);
        let (_, inv1_s, _) = Self::egcd_i128(m1_mod as i128, Q1 as i128);
        let (_, inv2_s, _) = Self::egcd_i128(m2_mod as i128, Q2 as i128);
        let inv0: u64 = ((inv0_s % Q0 as i128 + Q0 as i128) % Q0 as i128) as u64;
        let inv1: u64 = ((inv1_s % Q1 as i128 + Q1 as i128) % Q1 as i128) as u64;
        let inv2: u64 = ((inv2_s % Q2 as i128 + Q2 as i128) % Q2 as i128) as u64;

        for i in 0..n_coeffs {
            // CRT: coeff = (r₀·M₀·inv₀ + r₁·M₁·inv₁ + r₂·M₂·inv₂) mod Q
            let r0 = BigInt::from(residues[i]);
            let r1 = BigInt::from(residues[n_coeffs + i]);
            let r2 = BigInt::from(residues[2 * n_coeffs + i]);

            let t0 = r0 * &m0_big * inv0;
            let t1 = r1 * &m1_big * inv1;
            let t2 = r2 * &m2_big * inv2;
            let mut coeff_big = (t0 + t1 + t2) % &q_big;

            // Center to [-Q/2, Q/2)
            if coeff_big > q_half_big {
                coeff_big -= &q_big;
            }

            // Convert BigInt → Fr
            let (sign, bytes) = coeff_big.to_bytes_le();
            let mut bytes32 = [0u8; 32];
            let copy_len = bytes.len().min(32);
            bytes32[..copy_len].copy_from_slice(&bytes[..copy_len]);
            let mut fr_val = Fr::from_le_bytes_mod_order(&bytes32);
            if sign == num_bigint::Sign::Minus {
                fr_val = -fr_val;
            }
            coeffs.push(fr_val);
        }
        coeffs
    }

    /// CRT-reconstruct polynomial coefficients from RNS residues (3 moduli → 1 integer per coeff).
    ///
    /// The [`poly_coeffs_from_bytes`](Self::poly_coeffs_from_bytes) method returns
    /// 24 576 residues (8192 coefficients × 3 moduli, modulus-major layout:
    /// all coefficients for q₀, then all for q₁, then all for q₂).
    /// This method reconstructs them into 8 192 i128 integers via CRT.
    pub fn crt_reconstruct_coeffs(&self, residues: &[i64]) -> Result<Vec<i128>, FheError> {
        use num_bigint::BigInt;
        use num_traits::ToPrimitive;

        const MODULI_I128: [i128; 3] = [288230376173076481, 288230376167047169, 288230376161280001];
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
            let mj_i128 = (&m_big[j] % &moduli_big[j]).to_i128().unwrap_or(0);
            let (_, inv, _) = Self::egcd_i128(mj_i128, MODULI_I128[j]);
            m_inv[j] = (inv % MODULI_I128[j] + MODULI_I128[j]) % MODULI_I128[j];
        }

        // Residues are in modulus-major layout: [c0_q0, c1_q0, ..., cₙ₋₁_q0, c0_q1, ..., cₙ₋₁_q2]
        for i in 0..n_coeffs {
            let mut val_big = BigInt::from(0u32);
            for j in 0..3 {
                let r = residues[j * n_coeffs + i] as i128;
                let term = BigInt::from(r) * &m_big[j] * m_inv[j];
                val_big = (&val_big + term) % &q_big;
            }
            // Convert back to i128; since Q ≈ 2^174 > i128::MAX, this may overflow.
            match val_big.to_i128() {
                Some(v) => coeffs.push(v),
                None => {
                    return Err(FheError::Backend {
                        reason: format!("CRT coefficient exceeds i128 range at index {i}"),
                    })
                }
            }
        }
        Ok(coeffs)
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
        session_id: &[u8],
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

        let t_start = std::time::Instant::now();

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

    /// Aggregate decrypt returning the raw pre-scaling Lagrange-interpolated
    /// result polynomial (coefficients in [0, Q) domain, before the
    /// `Scaler::new` step).
    ///
    /// Returns `(raw_result_poly_bytes, decoded_plaintext_bytes)` where:
    /// - `raw_result_poly_bytes` is the protobuf-serialized Lagrange
    ///   reconstruction `Σ λ_i·d_i` of the share polynomials (mod Q, not
    ///   scaled).  This equals the C7 circuit accumulator `z0` before
    ///   scaling and is needed for G3 full in-circuit plaintext binding.
    /// - `decoded_plaintext_bytes` is the final decoded plaintext (identical
    ///   to [`aggregate_decrypt`](Self::aggregate_decrypt) output).
    ///
    /// The raw result polynomial bytes use the same encoding as decrypt-share
    /// polynomials and are compatible with [`poly_coeffs_from_bytes`].
    pub fn aggregate_decrypt_raw_result_poly(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
        session_id: &[u8],
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
                // Diagnostic: log first few power-basis coefficients of wire-decoded share poly
                {
                    let mut diag_poly = poly.clone();
                    diag_poly.change_representation(Representation::PowerBasis);
                    let cv = diag_poly.coefficients();
                    let first_row: Vec<u64> = cv.row(0).iter().take(5).copied().collect();
                    tracing::info!(
                        "C7: aggregate_raw wire-decoded share-pid={} first_mod0[0..5]={:?}",
                        share.party_id,
                        first_row
                    );
                }
                Ok((share.party_id as usize, poly))
            })
            .collect::<Result<Vec<_>, FheError>>()?;
        let (party_ids, share_polys): (Vec<_>, Vec<_>) = effective_shares.into_iter().unzip();

        let lagrange_coeffs = Self::compute_lagrange_coeffs_integer(&party_ids)?;
        tracing::info!(
            "C7: aggregate_raw party_ids={:?} lagrange_coeffs_int={:?}",
            party_ids,
            lagrange_coeffs
        );

        let raw_result_poly = {
            let first_poly = &share_polys[0];
            let first_lambda = lagrange_coeffs[0];
            let mut acc = if first_lambda >= 0 {
                first_poly * &BigUint::from(first_lambda as u64)
            } else {
                let abs_val = (-first_lambda) as u64;
                -(first_poly * &BigUint::from(abs_val))
            };

            for (lambda, poly) in lagrange_coeffs[1..].iter().zip(share_polys[1..].iter()) {
                let term = if *lambda >= 0 {
                    poly * &BigUint::from(*lambda as u64)
                } else {
                    let abs_val = (-*lambda) as u64;
                    -(poly * &BigUint::from(abs_val))
                };
                acc = &acc + &term;
            }
            acc
        };

        let raw_result_poly_bytes = raw_result_poly.to_bytes();
        // Immediate roundtrip verification: deserialize and compare
        {
            let rt_poly =
                Poly::from_bytes(&raw_result_poly_bytes, ctx).map_err(|err| FheError::Backend {
                    reason: err.to_string(),
                })?;
            let mut rt = rt_poly.clone();
            rt.change_representation(Representation::PowerBasis);
            let mut orig = raw_result_poly.clone();
            orig.change_representation(Representation::PowerBasis);
            let rt_row0: Vec<u64> = rt.coefficients().row(0).iter().take(5).copied().collect();
            let orig_row0: Vec<u64> = orig.coefficients().row(0).iter().take(5).copied().collect();
            tracing::info!(
                "C7: aggregate_raw roundtrip test rt_row0[0..5]={:?} orig_row0[0..5]={:?} match={}",
                rt_row0,
                orig_row0,
                rt_row0 == orig_row0
            );
        }

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

        let decoded_plaintext = decode_plaintext_slots(&slots)?;

        Ok((raw_result_poly_bytes, decoded_plaintext))
    }

    /// Compute integer Lagrange coefficients for the given 1-based party IDs.
    ///
    /// λ_i = Π_{j≠i} (0 - x_j) / Π_{j≠i} (x_i - x_j) for evaluation at 0.
    ///
    /// Uses [`BigInt`] internally to avoid overflow for n up to 64.
    /// For n > 64, the resulting coefficients may exceed i64 range; an error is returned.
    fn compute_lagrange_coeffs_integer(party_ids: &[usize]) -> Result<Vec<i64>, FheError> {
        let n = party_ids.len();

        // With party IDs in {1..n}, the numerator product grows as ~n!.
        // Beyond n=64, the Lagrange coefficients can exceed i64::MAX,
        // so we conservatively reject larger n.
        if n > 64 {
            return Err(FheError::InvalidParams {
                reason: format!("Lagrange coefficient overflow: n={n} exceeds safe bound of 64"),
            });
        }

        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            let xi = BigInt::from(party_ids[i] as i64);
            let mut num = BigInt::from(1);
            let mut den = BigInt::from(1);
            for (j, &pid_j) in party_ids.iter().enumerate() {
                if i != j {
                    let xj = BigInt::from(pid_j as i64);
                    num *= -&xj;
                    den *= &xi - &xj;
                }
            }
            // Exact integer division: for 1-based integer nodes {1..n},
            // the Lagrange coefficient λ_i is always an integer.
            let result = num / den;
            let coeff_i64 = result.to_i64().ok_or_else(|| FheError::Backend {
                reason: "Lagrange coefficient overflow: result does not fit in i64".to_string(),
            })?;
            coeffs.push(coeff_i64);
        }
        Ok(coeffs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FheBackend;
    use rand::rngs::StdRng;
    use rand_core::{RngCore, SeedableRng};

    const TEST_PARAMS_TOML: &str = r#"
[rlwe]
n = 8192
log2_q = 174
t_plain = 65536
moduli = [288230376173076481, 288230376167047169, 288230376161280001]
variance = 10
"#;

    #[test]
    fn test_aggregate_decrypt_raw_result_poly_roundtrip() {
        let backend = FhersBackend::load_params(TEST_PARAMS_TOML).expect("load params");
        let mut rng = StdRng::seed_from_u64(99);
        let plaintext = b"verify G3 raw poly";

        let n: usize = 5;
        let t: usize = 2;

        let session_id: [u8; 32] = {
            let mut id = [0u8; 32];
            rng.fill_bytes(&mut id);
            id
        };

        let share1 = backend
            .keygen_share_with_session(&session_id, 1, &mut rng)
            .expect("keygen_share(1)");
        let share2 = backend
            .keygen_share_with_session(&session_id, 2, &mut rng)
            .expect("keygen_share(2)");
        let share3 = backend
            .keygen_share_with_session(&session_id, 3, &mut rng)
            .expect("keygen_share(3)");
        let share4 = backend
            .keygen_share_with_session(&session_id, 4, &mut rng)
            .expect("keygen_share(4)");
        let share5 = backend
            .keygen_share_with_session(&session_id, 5, &mut rng)
            .expect("keygen_share(5)");
        let pk = backend
            .aggregate_keygen(&[share1, share2, share3, share4, share5])
            .expect("aggregate_keygen");
        let ct = backend.encrypt(&pk, plaintext, &mut rng).expect("encrypt");
        backend
            .setup_threshold(n, t, [0u8; 32])
            .expect("setup_threshold");
        let ds1 = backend
            .partial_decrypt(&ct, 1, &mut rng)
            .expect("partial_decrypt(1)");
        let ds2 = backend
            .partial_decrypt(&ct, 2, &mut rng)
            .expect("partial_decrypt(2)");

        let (raw_poly_bytes, decoded) = backend
            .aggregate_decrypt_raw_result_poly(&ct, &[ds1, ds2], t, &[])
            .expect("aggregate_decrypt_raw_result_poly");

        assert_eq!(decoded, plaintext.as_ref(), "decoded plaintext must match");

        let ctx = backend.bfv_params.ctx_at_level(0).expect("ctx_at_level");
        let raw_poly = Poly::from_bytes(&raw_poly_bytes, ctx).expect("raw result poly deserialize");
        assert!(
            !raw_poly_bytes.is_empty(),
            "raw result poly bytes must not be empty"
        );

        let coeffs = backend
            .poly_coeffs_from_bytes(&raw_poly_bytes)
            .expect("poly_coeffs_from_bytes on raw poly");
        assert_eq!(
            coeffs.len(),
            24576,
            "raw result poly should have 8192 coeffs × 3 moduli = 24576 residues"
        );

        let _ = raw_poly;
    }
}
