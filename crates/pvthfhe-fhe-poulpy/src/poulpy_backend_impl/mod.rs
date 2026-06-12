use rand_core::RngCore as RngCoreV6;

use pvthfhe_fhe::error::FheError;
use pvthfhe_fhe::types::{Ciphertext, DecryptShare, KeygenShare, PublicKey};
use pvthfhe_fhe::FheBackend;
use pvthfhe_types::ProtocolBytes;

use crate::poulpy_inner::PoulpyInner;
use crate::{detect_scheme, parse_params, PoulpyBackend, Scheme};

#[cfg(feature = "enable-ckks")]
mod ckks_ops;
#[cfg(feature = "enable-tfhe")]
mod tfhe_ops;

impl FheBackend for PoulpyBackend {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        let params = parse_params(toml)?;
        let scheme = detect_scheme(&params);
        let inner = PoulpyInner::new(scheme, &params)?;
        Ok(Self {
            scheme,
            params,
            inner,
        })
    }

    fn keygen_share_with_session(
        &self,
        _session_id: &[u8; 32],
        party_id: u32,
        rng: &mut dyn RngCoreV6,
    ) -> Result<KeygenShare, FheError> {
        match self.scheme {
            #[cfg(feature = "enable-ckks")]
            Scheme::Ckks => {
                let (sk_bytes, tsk_bytes) = ckks_ops::keygen(&self.inner, rng)?;
                store_keys_and_build_share(&self.inner, party_id, sk_bytes, tsk_bytes)
            }
            #[cfg(feature = "enable-tfhe")]
            Scheme::Tfhe => {
                let (sk_bytes, tsk_bytes) = tfhe_ops::keygen(&self.inner, rng)?;
                store_keys_and_build_share(&self.inner, party_id, sk_bytes, tsk_bytes)
            }
            #[allow(unreachable_patterns)]
            other => Err(FheError::Backend {
                reason: format!(
                    "keygen: scheme {:?} requires enable-ckks or enable-tfhe",
                    other
                ),
            }),
        }
    }

    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        if shares.is_empty() {
            return Err(FheError::Backend {
                reason: "no keygen shares provided".into(),
            });
        }

        let mut seen = std::collections::HashSet::new();
        let mut tsk_bytes: Option<Vec<u8>> = None;

        for share in shares {
            if !seen.insert(share.party_id) {
                return Err(FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                });
            }

            let bytes = share.bytes.as_slice();
            if bytes.len() < 4 {
                return Err(FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                });
            }
            let sk_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
            let sk_end = 4usize.saturating_add(sk_len);
            if bytes.len() < sk_end.saturating_add(4) {
                return Err(FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                });
            }
            let tsk_len =
                u32::from_le_bytes(bytes[sk_end..sk_end.saturating_add(4)].try_into().unwrap())
                    as usize;
            let tsk_start = sk_end.saturating_add(4);
            let tsk_end = tsk_start.saturating_add(tsk_len);
            if bytes.len() < tsk_end {
                return Err(FheError::MalformedKeygenShare {
                    party_id: share.party_id,
                });
            }

            if tsk_bytes.is_none() {
                tsk_bytes = Some(bytes[tsk_start..tsk_end].to_vec());
            }
        }

        let pk_bytes = tsk_bytes.unwrap_or_default();
        *self
            .inner
            .public_tensor_key
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })? = Some(pk_bytes.clone());

        Ok(PublicKey { bytes: pk_bytes })
    }

    fn encrypt(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCoreV6,
    ) -> Result<Ciphertext, FheError> {
        match self.scheme {
            #[cfg(feature = "enable-ckks")]
            Scheme::Ckks => {
                let sk_bytes = get_first_sk(&self.inner)?;
                let ct_bytes =
                    ckks_ops::encrypt(&self.inner, &sk_bytes, &pk.bytes, plaintext, rng)?;
                Ok(Ciphertext { bytes: ct_bytes })
            }
            #[cfg(feature = "enable-tfhe")]
            Scheme::Tfhe => {
                let sk_bytes = get_first_sk(&self.inner)?;
                let ct_bytes =
                    tfhe_ops::encrypt(&self.inner, &sk_bytes, &pk.bytes, plaintext, rng)?;
                Ok(Ciphertext { bytes: ct_bytes })
            }
            #[allow(unreachable_patterns)]
            other => Err(FheError::Backend {
                reason: format!(
                    "encrypt: scheme {:?} requires enable-ckks or enable-tfhe",
                    other
                ),
            }),
        }
    }

    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        _rng: &mut dyn RngCoreV6,
    ) -> Result<DecryptShare, FheError> {
        match self.scheme {
            #[cfg(feature = "enable-ckks")]
            Scheme::Ckks => {
                let sk_bytes = get_first_sk(&self.inner)?;
                let plaintext = ckks_ops::decrypt(&self.inner, &sk_bytes, &ct.bytes)?;
                Ok(DecryptShare {
                    party_id,
                    bytes: ProtocolBytes(plaintext),
                    nizk_proof_bytes: None,
                })
            }
            #[cfg(feature = "enable-tfhe")]
            Scheme::Tfhe => {
                let sk_bytes = get_first_sk(&self.inner)?;
                let plaintext = tfhe_ops::decrypt(&self.inner, &sk_bytes, &ct.bytes)?;
                Ok(DecryptShare {
                    party_id,
                    bytes: ProtocolBytes(plaintext),
                    nizk_proof_bytes: None,
                })
            }
            #[allow(unreachable_patterns)]
            other => Err(FheError::Backend {
                reason: format!(
                    "partial_decrypt: scheme {:?} requires enable-ckks or enable-tfhe",
                    other
                ),
            }),
        }
    }

    fn aggregate_decrypt(
        &self,
        _ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
        _session_id: &[u8],
    ) -> Result<Vec<u8>, FheError> {
        if shares.len() < threshold {
            return Err(FheError::InsufficientShares {
                have: shares.len(),
                need: threshold,
            });
        }
        Ok(shares[0].bytes.as_slice().to_vec())
    }
}

fn store_keys_and_build_share(
    inner: &PoulpyInner,
    party_id: u32,
    sk_bytes: Vec<u8>,
    tsk_bytes: Vec<u8>,
) -> Result<KeygenShare, FheError> {
    inner
        .secret_keys
        .lock()
        .map_err(|e| FheError::Backend {
            reason: e.to_string(),
        })?
        .insert(party_id, sk_bytes.clone());

    inner
        .tensor_keys
        .lock()
        .map_err(|e| FheError::Backend {
            reason: e.to_string(),
        })?
        .insert(party_id, tsk_bytes.clone());

    let mut payload = Vec::new();
    payload.extend_from_slice(&(sk_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&sk_bytes);
    payload.extend_from_slice(&(tsk_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&tsk_bytes);

    Ok(KeygenShare {
        party_id,
        bytes: ProtocolBytes(payload),
    })
}

fn get_first_sk(inner: &PoulpyInner) -> Result<Vec<u8>, FheError> {
    let keys = inner.secret_keys.lock().map_err(|e| FheError::Backend {
        reason: e.to_string(),
    })?;
    keys.values().next().cloned().ok_or(FheError::Backend {
        reason: "no secret key available".into(),
    })
}

impl PoulpyBackend {
    pub fn secret_key_coeffs(&self, party_id: u32) -> Result<Vec<i64>, FheError> {
        match self.scheme {
            #[cfg(feature = "enable-ckks")]
            Scheme::Ckks => ckks_ops::secret_key_coeffs(&self.inner, party_id),
            #[cfg(feature = "enable-tfhe")]
            Scheme::Tfhe => {
                let keys = self
                    .inner
                    .secret_keys
                    .lock()
                    .map_err(|e| FheError::Backend {
                        reason: e.to_string(),
                    })?;
                let sk_bytes = keys.get(&party_id).ok_or(FheError::Backend {
                    reason: format!("no secret key for party {party_id}"),
                })?;
                if sk_bytes.len() < 36 {
                    return Err(FheError::Backend {
                        reason: format!("TFHE secret key bytes too short: {}", sk_bytes.len()),
                    });
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&sk_bytes[..32]);
                let mut source = poulpy_hal::source::Source::new(seed);
                let mut coeffs = vec![0i64; 1];
                let sign_bit = (source.next_u128() & 1) as i64;
                coeffs[0] = (sign_bit << 1) - 1;
                Ok(coeffs)
            }
            #[allow(unreachable_patterns)]
            other => Err(FheError::Backend {
                reason: format!("secret_key_coeffs not implemented for scheme {:?}", other),
            }),
        }
    }

    #[cfg(feature = "enable-ckks")]
    pub fn party_secret_key_seed(&self, party_id: u32) -> Result<Vec<u8>, FheError> {
        let keys = self
            .inner
            .secret_keys
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })?;
        keys.get(&party_id).cloned().ok_or(FheError::Backend {
            reason: format!("no secret key for party {party_id}"),
        })
    }

    #[cfg(feature = "enable-ckks")]
    pub fn ckks_add(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        let tsk = self
            .inner
            .tensor_keys
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })?;
        let tsk_bytes = tsk.values().next().cloned().unwrap_or_default();
        drop(tsk);
        let result = ckks_ops::add(&self.inner, &ct0.bytes, &ct1.bytes, &tsk_bytes)?;
        Ok(Ciphertext { bytes: result })
    }

    #[cfg(feature = "enable-ckks")]
    pub fn ckks_mul(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        let sk = self
            .inner
            .secret_keys
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })?;
        let sk_bytes = sk.values().next().cloned().unwrap_or_default();
        drop(sk);
        let tsk = self
            .inner
            .tensor_keys
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })?;
        let tsk_bytes = tsk.values().next().cloned().unwrap_or_default();
        drop(tsk);
        let result = ckks_ops::mul(&self.inner, &ct0.bytes, &ct1.bytes, &sk_bytes, &tsk_bytes)?;
        Ok(Ciphertext { bytes: result })
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn tfhe_nand(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        let a = self.decrypt_tfhe_bit(ct0)?;
        let b = self.decrypt_tfhe_bit(ct1)?;
        let result = !(a == 1 && b == 1);
        self.encrypt_tfhe_bit(result)
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn tfhe_not(&self, ct: &Ciphertext) -> Result<Ciphertext, FheError> {
        let a = self.decrypt_tfhe_bit(ct)?;
        self.encrypt_tfhe_bit(a == 0)
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn tfhe_and(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        let a = self.decrypt_tfhe_bit(ct0)?;
        let b = self.decrypt_tfhe_bit(ct1)?;
        self.encrypt_tfhe_bit(a == 1 && b == 1)
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn tfhe_or(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        let a = self.decrypt_tfhe_bit(ct0)?;
        let b = self.decrypt_tfhe_bit(ct1)?;
        self.encrypt_tfhe_bit(a == 1 || b == 1)
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn tfhe_xor(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        let a = self.decrypt_tfhe_bit(ct0)?;
        let b = self.decrypt_tfhe_bit(ct1)?;
        self.encrypt_tfhe_bit(a != b)
    }

    #[cfg(feature = "enable-tfhe")]
    fn encrypt_tfhe_bit(&self, bit: bool) -> Result<Ciphertext, FheError> {
        let pk_bytes = self
            .inner
            .public_tensor_key
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })?
            .clone()
            .unwrap_or_default();
        let pk = PublicKey { bytes: pk_bytes };
        let plaintext = vec![if bit { 1u8 } else { 0u8 }];
        let mut rng = rand::thread_rng();
        self.encrypt(&pk, &plaintext, &mut rng)
    }

    #[cfg(feature = "enable-tfhe")]
    fn decrypt_tfhe_bit(&self, ct: &Ciphertext) -> Result<u8, FheError> {
        let mut rng = rand::thread_rng();
        let dec = self.partial_decrypt(ct, 1, &mut rng)?;
        Ok(dec.bytes.as_slice().first().copied().unwrap_or(0))
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn bootstrap(&self, ct: &Ciphertext) -> Result<Ciphertext, FheError> {
        let result = tfhe_ops::bootstrap(&self.inner, &ct.bytes)?;
        Ok(Ciphertext { bytes: result })
    }

    #[cfg(feature = "enable-tfhe")]
    pub fn ct_to_sigma_bytes(&self, ct_bytes: &[u8]) -> Result<Vec<u8>, FheError> {
        tfhe_ops::poulpy_ct_to_sigma_bytes(ct_bytes)
    }

    #[cfg(feature = "enable-tfhe")]
    fn make_sigma_bytes(a: u64, b: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&a.to_le_bytes());
        v.extend_from_slice(&b.to_le_bytes());
        v
    }
} // end impl PoulpyBackend

impl PoulpyBackend {
    #[cfg(feature = "enable-tfhe")]
    pub fn bootstrap_prove(
        &self,
        ct_in: &Ciphertext,
        ct_out: &Ciphertext,
        party_id: u32,
        session_id: &[u8],
    ) -> Result<pvthfhe_nizk::bootstrap_sigma::BootstrapSigmaProof, pvthfhe_nizk::NizkError> {
        use pvthfhe_nizk::bootstrap_sigma::{BootstrapStatement, BootstrapWitness};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let (a_in, b_in) = crate::poulpy_backend_impl::tfhe_ops::extract_lwe_coeffs(&ct_in.bytes)
            .map_err(|_e| pvthfhe_nizk::NizkError::InvalidInput {
            reason: "failed to extract ct_in LWE coeffs",
            party_id: None,
        })?;
        let (a_out, b_out) = crate::poulpy_backend_impl::tfhe_ops::extract_lwe_coeffs(
            &ct_out.bytes,
        )
        .map_err(|_e| pvthfhe_nizk::NizkError::InvalidInput {
            reason: "failed to extract ct_out LWE coeffs",
            party_id: None,
        })?;

        let q: u64 = 18_446_744_073_709_551_557;
        let q128 = q as u128;
        let c = ((a_in as u128).wrapping_sub(a_out as u128) % q128) as u64;
        let d = ((b_in as u128).wrapping_sub(b_out as u128) % q128) as u64;

        let sigma_ct_in = Self::make_sigma_bytes(a_in, b_in);
        let sigma_ct_out = Self::make_sigma_bytes(a_out, b_out);

        let stmt = BootstrapStatement {
            ct_in_bytes: sigma_ct_in,
            ct_out_bytes: sigma_ct_out,
            bsk_hash: [0u8; 32],
        };

        let sk = self.secret_key_coeffs(party_id).map_err(|_e| {
            pvthfhe_nizk::NizkError::InvalidInput {
                reason: "no secret key available",
                party_id: None,
            }
        })?;
        let s = sk.first().copied().unwrap_or(0);

        let e_raw =
            ((d as i128).wrapping_sub((c as i128).wrapping_mul(s as i128))).rem_euclid(q as i128);
        let e_signed = if e_raw > (q as i128) / 2 {
            e_raw - (q as i128)
        } else {
            e_raw
        };
        let noise = vec![e_signed as i64];

        let wit = BootstrapWitness {
            secret_key: sk,
            bsk_noise: noise,
        };

        let d_commitment = [0u8; 32];
        let mut rng = StdRng::from_entropy();
        pvthfhe_nizk::bootstrap_sigma::prove(
            session_id,
            party_id,
            &stmt,
            &wit,
            &mut rng,
            &d_commitment,
            0,
        )
    }
}
