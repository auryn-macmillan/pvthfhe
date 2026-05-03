//! Internal mock implementation, always compiled.
//!
//! The public [`crate::mock`] module re-exports from here when the `mock`
//! feature is enabled. [`crate::fhers`] uses this as a fallback until T33.

use crate::{
    error::FheError,
    types::{Ciphertext, DecryptShare, KeygenShare, Params, PublicKey},
    FheBackend,
};
use rand_core::RngCore;

pub(crate) fn parse_params(toml: &str) -> Result<Params, FheError> {
    let mut n: Option<u32> = None;
    let mut log2_q: Option<u32> = None;
    let mut t_plain: Option<u32> = None;
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
        }
    }

    match (n, log2_q, t_plain) {
        (Some(n), Some(log2_q), Some(t_plain)) => Ok(Params { n, log2_q, t_plain }),
        _ => Err(FheError::InvalidParams {
            reason: "missing required [rlwe] fields: n, log2_q, t_plain".into(),
        }),
    }
}

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
#[derive(Clone, Debug)]
pub struct MockBackendInner {
    #[allow(dead_code)]
    pub(crate) params: Params,
}

impl FheBackend for MockBackendInner {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        let params = parse_params(toml)?;
        Ok(Self { params })
    }

    fn keygen_share(&self, party_id: u32, _rng: &mut dyn RngCore) -> Result<KeygenShare, FheError> {
        let bytes = party_id.to_le_bytes().to_vec();
        Ok(KeygenShare { party_id, bytes })
    }

    fn aggregate_keygen(&self, shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        let mut acc = vec![0u8; 4];
        for s in shares {
            acc = xor_bytes(&acc, &s.bytes);
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
        Ok(DecryptShare { party_id, bytes })
    }

    fn aggregate_decrypt(
        &self,
        ct: &Ciphertext,
        shares: &[DecryptShare],
        threshold: usize,
    ) -> Result<Vec<u8>, FheError> {
        if shares.len() < threshold {
            return Err(FheError::InsufficientShares {
                received: shares.len(),
                threshold,
            });
        }

        let mut reconstructed_pk = vec![0u8; 4];
        for s in shares {
            reconstructed_pk = xor_bytes(&reconstructed_pk, &s.bytes);
        }

        Ok(xor_bytes(&ct.bytes, &reconstructed_pk))
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    const TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\n";

    #[test]
    fn parse_params_ok() {
        let p = match parse_params(TOML) {
            Ok(params) => params,
            Err(err) => unreachable!("parse: {err:?}"),
        };
        assert_eq!(p.n, 8192);
        assert_eq!(p.log2_q, 174);
        assert_eq!(p.t_plain, 65536);
    }

    #[test]
    fn parse_params_missing_field() {
        let result = parse_params("[rlwe]\nn = 8192\n");
        assert!(matches!(result, Err(FheError::InvalidParams { .. })));
    }
}
