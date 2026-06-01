#![allow(missing_docs)]

use pvthfhe_fhe::error::FheError;
use pvthfhe_fhe::types::Params;
use serde::{Deserialize, Serialize};

#[cfg(not(any(feature = "enable-ckks", feature = "enable-tfhe")))]
use {
    pvthfhe_fhe::types::{Ciphertext, DecryptShare, KeygenShare, PublicKey},
    pvthfhe_fhe::FheBackend,
    rand_core::RngCore,
};

#[cfg(feature = "enable-ckks")]
mod ckks_impl;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scheme {
    Ckks,
    Tfhe,
}

impl Scheme {
    #[allow(dead_code)]
    fn default_params_toml(&self) -> &str {
        match self {
            Scheme::Ckks => {
                "[rlwe]\nn = 8192\nlog2_q = 300\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n"
            }
            Scheme::Tfhe => {
                "[rlwe]\nn = 1\nlog2_q = 64\nt_plain = 2\nmoduli = [18446744073709551557]\nvariance = 10\n"
            }
        }
    }
}

#[cfg(any(feature = "enable-ckks", feature = "enable-tfhe"))]
mod poulpy_inner;

#[cfg(not(any(feature = "enable-ckks", feature = "enable-tfhe")))]
mod poulpy_inner {
    pub type PoulpyInner = ();
}

use poulpy_inner::PoulpyInner;

#[allow(dead_code)]
#[derive(Clone)]
pub struct PoulpyBackend {
    scheme: Scheme,
    params: Params,
    inner: PoulpyInner,
}

impl PoulpyBackend {
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn params(&self) -> &Params {
        &self.params
    }
}

fn parse_params(toml: &str) -> Result<Params, FheError> {
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

fn detect_scheme(params: &Params) -> Scheme {
    if params.n == 1 {
        Scheme::Tfhe
    } else {
        Scheme::Ckks
    }
}

#[cfg(not(any(feature = "enable-ckks", feature = "enable-tfhe")))]
impl FheBackend for PoulpyBackend {
    fn load_params(toml: &str) -> Result<Self, FheError> {
        let params = parse_params(toml)?;
        let scheme = detect_scheme(&params);
        Ok(Self {
            scheme,
            params,
            inner: (),
        })
    }

    fn keygen_share_with_session(
        &self,
        _session_id: &[u8; 32],
        _party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<KeygenShare, FheError> {
        Err(FheError::Backend {
            reason: format!(
                "Poulpy {:?} requires enable-ckks or enable-tfhe feature",
                self.scheme
            ),
        })
    }

    fn aggregate_keygen(&self, _shares: &[KeygenShare]) -> Result<PublicKey, FheError> {
        Err(FheError::Backend {
            reason: format!(
                "Poulpy {:?} requires enable-ckks or enable-tfhe feature",
                self.scheme
            ),
        })
    }

    fn encrypt(
        &self,
        _pk: &PublicKey,
        _plaintext: &[u8],
        _rng: &mut dyn RngCore,
    ) -> Result<Ciphertext, FheError> {
        Err(FheError::Backend {
            reason: format!(
                "Poulpy {:?} requires enable-ckks or enable-tfhe feature",
                self.scheme
            ),
        })
    }

    fn partial_decrypt(
        &self,
        _ct: &Ciphertext,
        _party_id: u32,
        _rng: &mut dyn RngCore,
    ) -> Result<DecryptShare, FheError> {
        Err(FheError::Backend {
            reason: format!(
                "Poulpy {:?} requires enable-ckks or enable-tfhe feature",
                self.scheme
            ),
        })
    }

    fn aggregate_decrypt(
        &self,
        _ct: &Ciphertext,
        _shares: &[DecryptShare],
        _threshold: usize,
        _session_id: &[u8],
    ) -> Result<Vec<u8>, FheError> {
        Err(FheError::Backend {
            reason: format!(
                "Poulpy {:?} requires enable-ckks or enable-tfhe feature",
                self.scheme
            ),
        })
    }
}

#[cfg(any(feature = "enable-ckks", feature = "enable-tfhe"))]
mod poulpy_backend_impl;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(any(feature = "enable-ckks", feature = "enable-tfhe")))]
    use pvthfhe_fhe::FheBackend;

    #[test]
    fn parse_params_ckks_default() {
        let toml = Scheme::Ckks.default_params_toml();
        let params = parse_params(toml).expect("should parse CKKS params");
        assert_eq!(params.n, 8192);
        assert_eq!(params.log2_q, 300);
    }

    #[test]
    fn parse_params_tfhe_default() {
        let toml = Scheme::Tfhe.default_params_toml();
        let params = parse_params(toml).expect("should parse TFHE params");
        assert_eq!(params.n, 1);
        assert_eq!(params.log2_q, 64);
    }

    #[test]
    fn detect_scheme_picks_ckks() {
        let params = parse_params(Scheme::Ckks.default_params_toml()).unwrap();
        assert_eq!(detect_scheme(&params), Scheme::Ckks);
    }

    #[test]
    fn detect_scheme_picks_tfhe() {
        let params = parse_params(Scheme::Tfhe.default_params_toml()).unwrap();
        assert_eq!(detect_scheme(&params), Scheme::Tfhe);
    }

    #[test]
    #[cfg(not(any(feature = "enable-ckks", feature = "enable-tfhe")))]
    fn load_params_without_features_returns_error_on_keygen() {
        let backend =
            PoulpyBackend::load_params(Scheme::Ckks.default_params_toml()).expect("load_params");
        let result = backend.keygen_share(1, &mut rand::thread_rng());
        assert!(result.is_err());
    }

    #[test]
    fn parse_params_rejects_missing_moduli() {
        let result = parse_params("[rlwe]\nn = 8192\nlog2_q = 300\n");
        assert!(matches!(result, Err(FheError::InvalidParams { .. })));
    }

    #[cfg(feature = "enable-ckks")]
    #[test]
    fn secret_key_coeffs_returns_ternary_polynomial() {
        use pvthfhe_fhe::FheBackend;
        use rand_core::RngCore;

        let backend =
            PoulpyBackend::load_params(Scheme::Ckks.default_params_toml()).expect("load_params");
        let mut rng = rand::thread_rng();
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);

        let _share = backend
            .keygen_share_with_session(&session_id, 1, &mut rng)
            .expect("keygen_share");

        let coeffs = backend.secret_key_coeffs(1).expect("secret_key_coeffs");
        assert_eq!(coeffs.len(), 8192, "CKKS N=8192 polynomial degree");
        let ones = coeffs.iter().filter(|&&c| c == 1).count();
        let neg_ones = coeffs.iter().filter(|&&c| c == -1).count();
        let zeros = coeffs.iter().filter(|&&c| c == 0).count();
        assert_eq!(ones + neg_ones, 192, "HW=192 ternary secret key");
        assert_eq!(zeros, 8192 - 192, "remaining coefficients must be zero");
    }
}
