use rand_core::RngCore as RngCoreV6;

use pvthfhe_fhe::error::FheError;
use pvthfhe_fhe::types::{Ciphertext, DecryptShare, KeygenShare, PublicKey};
use pvthfhe_fhe::FheBackend;
use pvthfhe_types::ProtocolBytes;

use crate::poulpy_inner::PoulpyInner;
use crate::{detect_scheme, parse_params, PoulpyBackend, Scheme};

#[cfg(feature = "enable-ckks")]
mod ckks_ops;

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

    #[cfg(not(feature = "enable-ckks"))]
    fn keygen_share_with_session(
        &self,
        _session_id: &[u8; 32],
        party_id: u32,
        _rng: &mut dyn RngCoreV6,
    ) -> Result<KeygenShare, FheError> {
        Err(FheError::Backend {
            reason: format!("Poulpy {:?} keygen requires enable-ckks", self.scheme),
        })
    }

    #[cfg(feature = "enable-ckks")]
    fn keygen_share_with_session(
        &self,
        _session_id: &[u8; 32],
        party_id: u32,
        rng: &mut dyn RngCoreV6,
    ) -> Result<KeygenShare, FheError> {
        if self.scheme != Scheme::Ckks {
            return Err(FheError::Backend {
                reason: format!("keygen only implemented for CKKS, got {:?}", self.scheme),
            });
        }
        let (sk_bytes, tsk_bytes) = ckks_ops::keygen(&self.inner, rng)?;

        self.inner
            .secret_keys
            .lock()
            .map_err(|e| FheError::Backend {
                reason: e.to_string(),
            })?
            .insert(party_id, sk_bytes.clone());

        self.inner
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

    #[cfg(not(feature = "enable-ckks"))]
    fn encrypt(
        &self,
        _pk: &PublicKey,
        _plaintext: &[u8],
        _rng: &mut dyn RngCoreV6,
    ) -> Result<Ciphertext, FheError> {
        Err(FheError::Backend {
            reason: format!("Poulpy {:?} encrypt requires enable-ckks", self.scheme),
        })
    }

    #[cfg(feature = "enable-ckks")]
    fn encrypt(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        rng: &mut dyn RngCoreV6,
    ) -> Result<Ciphertext, FheError> {
        if self.scheme != Scheme::Ckks {
            return Err(FheError::Backend {
                reason: format!("encrypt only implemented for CKKS, got {:?}", self.scheme),
            });
        }

        let sk_bytes = {
            let keys = self
                .inner
                .secret_keys
                .lock()
                .map_err(|e| FheError::Backend {
                    reason: e.to_string(),
                })?;
            keys.values()
                .next()
                .ok_or(FheError::Backend {
                    reason: "no secret key available for encrypt".into(),
                })?
                .clone()
        };
        let ct_bytes = ckks_ops::encrypt(&self.inner, &sk_bytes, &pk.bytes, plaintext, rng)?;
        Ok(Ciphertext { bytes: ct_bytes })
    }

    #[cfg(not(feature = "enable-ckks"))]
    fn partial_decrypt(
        &self,
        _ct: &Ciphertext,
        _party_id: u32,
        _rng: &mut dyn RngCoreV6,
    ) -> Result<DecryptShare, FheError> {
        Err(FheError::Backend {
            reason: format!("Poulpy {:?} decrypt requires enable-ckks", self.scheme),
        })
    }

    #[cfg(feature = "enable-ckks")]
    fn partial_decrypt(
        &self,
        ct: &Ciphertext,
        party_id: u32,
        _rng: &mut dyn RngCoreV6,
    ) -> Result<DecryptShare, FheError> {
        if self.scheme != Scheme::Ckks {
            return Err(FheError::Backend {
                reason: format!("decrypt only implemented for CKKS, got {:?}", self.scheme),
            });
        }

        let sk_bytes = {
            let keys = self
                .inner
                .secret_keys
                .lock()
                .map_err(|e| FheError::Backend {
                    reason: e.to_string(),
                })?;
            keys.values()
                .next()
                .ok_or(FheError::Backend {
                    reason: "no secret key available for decrypt".into(),
                })?
                .clone()
        };
        let plaintext = ckks_ops::decrypt(&self.inner, &sk_bytes, &ct.bytes)?;

        Ok(DecryptShare {
            party_id,
            bytes: ProtocolBytes(plaintext),
            nizk_proof_bytes: None,
        })
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

impl PoulpyBackend {
    pub fn ckks_add(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        #[cfg(feature = "enable-ckks")]
        {
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
            return Ok(Ciphertext { bytes: result });
        }
        #[cfg(not(feature = "enable-ckks"))]
        {
            let _ = (ct0, ct1);
            Err(FheError::Backend {
                reason: "CKKS add requires enable-ckks feature".into(),
            })
        }
    }

    pub fn ckks_mul(&self, ct0: &Ciphertext, ct1: &Ciphertext) -> Result<Ciphertext, FheError> {
        #[cfg(feature = "enable-ckks")]
        {
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
            return Ok(Ciphertext { bytes: result });
        }
        #[cfg(not(feature = "enable-ckks"))]
        {
            let _ = (ct0, ct1);
            Err(FheError::Backend {
                reason: "CKKS mul requires enable-ckks feature".into(),
            })
        }
    }
}
