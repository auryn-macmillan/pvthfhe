//! Key material helpers for the fhe.rs BFV backend: public-key decoding and
//! the DKG committed smudge-noise generator (B.2).

use super::{FhersBackend, SIGMA_SMUDGE};
use crate::{error::FheError, types::PublicKey as OpaquePublicKey, wire};
use fhe::bfv::{Ciphertext as BfvCiphertext, PublicKey as BfvPublicKey};
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};
use pvthfhe_foundations::domain_tags::Tag;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use rand_distr::{Distribution, Normal};
use sha2::{Digest, Sha256};

impl FhersBackend {
    pub(super) fn decode_public_key(&self, pk: &OpaquePublicKey) -> Result<BfvPublicKey, FheError> {
        let decoded =
            wire::decode_public_key(&pk.bytes).map_err(|_| FheError::MalformedPublicKey)?;
        let ctx = self
            .bfv_params
            .ctx_at_level(0)
            .map_err(|err| FheError::Backend {
                reason: err.to_string(),
            })?;
        let p0 = Poly::from_bytes(&decoded.p0, ctx).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let p1 = Poly::from_bytes(&decoded.p1, ctx).map_err(|err| FheError::Backend {
            reason: err.to_string(),
        })?;
        let c = BfvCiphertext::new(vec![p0, p1], &self.bfv_params).map_err(|err| {
            FheError::Backend {
                reason: err.to_string(),
            }
        })?;

        // L4: reject trivially-zero public keys (defense-in-depth)
        let all_zero = c.c.iter().all(|p| p.coefficients().iter().all(|&v| v == 0));
        if all_zero {
            return Err(FheError::MalformedPublicKey);
        }

        Ok(BfvPublicKey {
            par: self.bfv_params.clone(),
            c,
        })
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
        hasher.update(Tag::EsmNoise.as_bytes());
        hasher.update(party_id.to_be_bytes());
        hasher.update(seed.to_be_bytes());
        let seed_bytes: [u8; 32] = hasher.finalize().into();
        // allow-seeded-rng: deterministic committed smudge noise (C6) that must be reproducible per party; seed_bytes = SHA256(domain ‖ party_id ‖ operator-supplied seed)
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
            ctx,
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
}
