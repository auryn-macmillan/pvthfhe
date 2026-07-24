//! Homomorphic ciphertext operations for the fhe.rs BFV backend.

use super::FhersBackend;
use crate::{error::FheError, types::Ciphertext};
use fhe::bfv::Ciphertext as BfvCiphertext;
use fhe_traits::{DeserializeParametrized, DeserializeWithContext, Serialize};

impl FhersBackend {
    /// Add two ciphertexts component-wise (BFV ciphertext homomorphic addition).
    ///
    /// Deserializes both ciphertexts from bytes, performs `+` via the `fhe` crate,
    /// and re-serializes the result.
    pub fn ct_add(&self, ct_a: &Ciphertext, ct_b: &Ciphertext) -> Result<Ciphertext, FheError> {
        let a = BfvCiphertext::from_bytes(&ct_a.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;
        let b = BfvCiphertext::from_bytes(&ct_b.bytes, &self.bfv_params)
            .map_err(|_| FheError::MalformedCiphertext)?;
        let sum = &a + &b;
        Ok(Ciphertext {
            bytes: sum.to_bytes(),
        })
    }
}
