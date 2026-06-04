//! Internal mock implementation, always compiled.
//!
//! The public [`crate::mock`] module re-exports from here when the `mock`
//! feature is enabled. [`crate::fhers`] uses this as a fallback until T33.

use crate::{error::FheError, types::Params};

#[cfg(not(feature = "production-profile"))]
use crate::{
    types::{Ciphertext, DecryptShare, KeygenShare, PublicKey},
    FheBackend,
};
#[cfg(not(feature = "production-profile"))]
use pvthfhe_types::ProtocolBytes;
#[cfg(not(feature = "production-profile"))]
use rand_core::RngCore;

fn parse_u64_list(value: &str) -> Option<Vec<u64>> {
    let trimmed = value.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }

    inner
        .split(',')
        .map(|item| item.trim().parse::<u64>().ok())
        .collect()
}

pub(crate) fn parse_params(toml: &str) -> Result<Params, FheError> {
    let mut n: Option<u32> = None;
    let mut log2_q: Option<u32> = None;
    let mut t_plain: Option<u32> = None;
    let mut moduli: Option<Vec<u64>> = None;
    let mut variance: Option<usize> = None;
    let mut in_rlwe = false;

    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[rlwe]" {
            in_rlwe = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_rlwe = false;
        }
        if !in_rlwe {
            continue;
        }
        if let Some(val) = trimmed.strip_prefix("n =") {
            n = val.trim().parse().ok();
        } else if let Some(val) = trimmed.strip_prefix("log2_q =") {
            log2_q = val.trim().parse().ok();
        } else if let Some(val) = trimmed.strip_prefix("t_plain =") {
            t_plain = val.trim().parse().ok();
        } else if let Some(val) = trimmed.strip_prefix("plaintext_modulus =") {
            t_plain = val.trim().parse().ok();
        } else if let Some(val) = trimmed.strip_prefix("moduli =") {
            moduli = parse_u64_list(val);
        } else if let Some(val) = trimmed.strip_prefix("variance =") {
            variance = val.trim().parse().ok();
        }
    }

    if moduli.is_none() {
        return Err(FheError::InvalidParams {
            reason: "moduli required in [rlwe] section".into(),
        });
    }

    match (n, log2_q, t_plain, moduli, variance) {
        (Some(n), Some(log2_q), Some(t_plain), Some(moduli), Some(variance)) => Ok(Params {
            n,
            log2_q,
            t_plain,
            moduli,
            variance,
        }),
        _ => Err(FheError::InvalidParams {
            reason: "missing required [rlwe] fields: n, log2_q, t_plain, variance".into(),
        }),
    }
}

#[cfg(not(feature = "production-profile"))]
pub(crate) fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| {
            let ai = if i < a.len() { a[i] } else { 0 };
            let bi = if i < b.len() { b[i] } else { 0 };
            ai ^ bi
        })
        .collect()
}

/// Internal mock backend, always compiled.
#[cfg(not(feature = "production-profile"))]
#[derive(Clone, Debug)]
pub struct MockBackendInner {
    pub(crate) _params: Params,
}

#[cfg(not(feature = "production-profile"))]
impl FheBackend for MockBackendInner {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        let params = parse_params(toml)?;
        Ok(Self { _params: params })
    }

    fn keygen_share_with_session(
        &self,
        _session_id: &[u8; 32],
        party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<KeygenShare, FheError> {
        let bytes = party_id.to_le_bytes().to_vec();
        Ok(KeygenShare {
            party_id,
            bytes: ProtocolBytes(bytes),
        })
    }

    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut acc = vec![0u8; 4];
        for s in shares {
            if !seen.insert(s.party_id) {
                return Err(FheError::MalformedKeygenShare {
                    party_id: s.party_id,
                });
            }
            acc = xor_bytes(&acc, s.bytes.as_slice());
        }
        Ok(PublicKey { bytes: acc })
    }

    fn encrypt(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        _rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        let ct = xor_bytes(plaintext, &pk.bytes);
        Ok(Ciphertext { bytes: ct })
    }

    fn partial_decrypt(
        &self,
        _ct: &Ciphertext,
        party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        let bytes = party_id.to_le_bytes().to_vec();
        Ok(DecryptShare {
            party_id,
            bytes: ProtocolBytes(bytes),
            nizk_proof_bytes: None,
        })
    }

    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
        _session_id: &[u8],
    ) -> Result<Vec<u8>, FheError> {
        let mut seen = std::collections::BTreeSet::new();
        for s in shares {
            if !seen.insert(s.party_id) {
                return Err(FheError::MalformedDecryptShare {
                    party_id: s.party_id,
                });
            }
        }

        if shares.len() < threshold {
            return Err(FheError::InsufficientShares {
                have: shares.len(),
                need: threshold,
            });
        }

        let mut reconstructed_pk = vec![0u8; 4];
        for s in shares {
            reconstructed_pk = xor_bytes(&reconstructed_pk, s.bytes.as_slice());
        }

        Ok(xor_bytes(&ct.bytes, &reconstructed_pk))
    }

    fn decode_pk_polys(&self, _pk: &PublicKey) -> Result<(Vec<u8>, Vec<u8>), FheError> {
        let n = usize::try_from(self._params.n).unwrap_or(1024);
        let moduli = if self._params.moduli.is_empty() {
            vec![288_230_376_173_076_481u64]
        } else {
            self._params.moduli.clone()
        };
        let ctx = std::sync::Arc::new(fhe_math::rq::Context::new(&moduli, n).map_err(|e| {
            FheError::Backend {
                reason: format!("mock context creation failed: {e:?}"),
            }
        })?);

        use fhe_math::rq::{Poly, Representation};
        let zero_poly = Poly::zero(&ctx, Representation::PowerBasis);

        use fhe_traits::Serialize as _;
        let pk0_bytes = zero_poly.to_bytes();
        let pk1_bytes = zero_poly.to_bytes();
        Ok((pk0_bytes, pk1_bytes))
    }

    fn keygen_witness(&self, _party_id: u32) -> Result<Option<(Vec<i64>, Vec<u8>)>, FheError> {
        let n = usize::try_from(self._params.n).unwrap_or(1024);
        let sk = vec![0i64; n];
        let moduli = if self._params.moduli.is_empty() {
            vec![288_230_376_173_076_481u64]
        } else {
            self._params.moduli.clone()
        };
        let ctx = std::sync::Arc::new(fhe_math::rq::Context::new(&moduli, n).map_err(|e| {
            FheError::Backend {
                reason: format!("mock witness context creation failed: {e:?}"),
            }
        })?);
        let zero_poly = fhe_math::rq::Poly::zero(&ctx, fhe_math::rq::Representation::PowerBasis);
        use fhe_traits::Serialize as _;
        let err = zero_poly.to_bytes();
        Ok(Some((sk, err)))
    }

    fn supports_session_scoped_keygen(&self) -> bool {
        true
    }
}

#[cfg(all(test, not(feature = "production-profile")))]
mod unit_tests {
    use super::*;

    const TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

    #[test]
    fn t11_6_aggregate_decrypt_rejects_duplicate_party_id() {
        let backend = MockBackendInner::load_params(TOML).unwrap();
        let ct = Ciphertext {
            bytes: vec![0xAA; 4],
        };
        let share1 = DecryptShare {
            party_id: 1,
            bytes: ProtocolBytes(1u32.to_le_bytes().to_vec()),
            nizk_proof_bytes: None,
        };
        let shares = vec![share1.clone(), share1.clone()];
        let result = backend.aggregate_decrypt(&ct, &shares, 2, b"");
        assert!(
            matches!(result, Err(FheError::MalformedDecryptShare { party_id: 1 })),
            "expected MalformedDecryptShare for duplicate party_id 1, got: {result:?}"
        );
    }

    #[test]
    fn t11_6_aggregate_keygen_rejects_duplicate_party_id() {
        let backend = MockBackendInner::load_params(TOML).unwrap();
        let share1 = KeygenShare {
            party_id: 1,
            bytes: ProtocolBytes(1u32.to_le_bytes().to_vec()),
        };
        let shares = vec![share1.clone(), share1.clone()];
        let result = backend.aggregate_keygen(&shares);
        assert!(
            matches!(result, Err(FheError::MalformedKeygenShare { party_id: 1 })),
            "expected MalformedKeygenShare for duplicate party_id 1, got: {result:?}"
        );
    }

    #[test]
    fn parse_params_ok() {
        let p = match parse_params(TOML) {
            Ok(params) => params,
            Err(err) => unreachable!("parse: {err:?}"),
        };
        assert_eq!(p.n, 8192);
        assert_eq!(p.log2_q, 174);
        assert_eq!(p.t_plain, 65536);
        assert_eq!(
            p.moduli,
            [
                288230376173076481u64,
                288230376167047169,
                288230376161280001
            ]
        );
        assert_eq!(p.variance, 10);
    }

    #[test]
    fn parse_params_missing_field() {
        let result = parse_params("[rlwe]\nn = 8192\n");
        assert!(matches!(result, Err(FheError::InvalidParams { .. })));
    }
}
