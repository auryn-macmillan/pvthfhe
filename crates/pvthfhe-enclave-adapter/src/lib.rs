#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "stub")]
pub mod stub {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vendor-stub/enclave_types.rs"
    ));
}

#[cfg(feature = "stub")]
pub use stub::{
    EnclaveAggregator, EnclaveCiphernode, EnclaveCiphertext, EnclaveDecryptShare, EnclaveKeyShare,
    EnclaveProof, EnclavePublicKey,
};

use pvthfhe_fhe::FheBackend;

pub struct PvthfheEnclaveCiphernode<B: FheBackend> {
    backend: B,
    party_id: u32,
}

impl<B: FheBackend> PvthfheEnclaveCiphernode<B> {
    pub fn new(backend: B, party_id: u32) -> Self {
        Self { backend, party_id }
    }
}

pub struct PvthfheEnclaveAggregator<B: FheBackend> {
    backend: B,
    threshold: usize,
}

impl<B: FheBackend> PvthfheEnclaveAggregator<B> {
    pub fn new(backend: B, threshold: usize) -> Self {
        Self { backend, threshold }
    }
}

#[cfg(feature = "stub")]
impl<B: FheBackend> EnclaveCiphernode for PvthfheEnclaveCiphernode<B> {
    fn generate_key_share(
        &self,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<EnclaveKeyShare, String> {
        let share = self
            .backend
            .keygen_share(self.party_id, rng)
            .map_err(|e| format!("{e:?}"))?;
        Ok(EnclaveKeyShare(share.bytes))
    }

    fn partial_decrypt(
        &self,
        ct: &EnclaveCiphertext,
        _key_share: &EnclaveKeyShare,
    ) -> Result<EnclaveDecryptShare, String> {
        let ciphertext = pvthfhe_fhe::Ciphertext {
            bytes: ct.0.clone(),
        };
        let mut rng = rand_core::OsRng;
        let share = self
            .backend
            .partial_decrypt(&ciphertext, self.party_id, &mut rng)
            .map_err(|e| format!("{e:?}"))?;
        Ok(EnclaveDecryptShare(share.bytes))
    }
}

#[cfg(feature = "stub")]
impl<B: FheBackend> EnclaveAggregator for PvthfheEnclaveAggregator<B> {
    fn aggregate_keys(
        &self,
        shares: &[EnclaveKeyShare],
    ) -> Result<EnclavePublicKey, String> {
        let fhe_shares: Vec<pvthfhe_fhe::KeygenShare> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| pvthfhe_fhe::KeygenShare {
                party_id: i as u32,
                bytes: s.0.clone(),
            })
            .collect();
        let pk = self
            .backend
            .aggregate_keygen(&fhe_shares)
            .map_err(|e| format!("{e:?}"))?;
        Ok(EnclavePublicKey(pk.bytes))
    }

    fn aggregate_decrypt(
        &self,
        ct: &EnclaveCiphertext,
        shares: &[EnclaveDecryptShare],
    ) -> Result<Vec<u8>, String> {
        let ciphertext = pvthfhe_fhe::Ciphertext {
            bytes: ct.0.clone(),
        };
        let fhe_shares: Vec<pvthfhe_fhe::DecryptShare> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| pvthfhe_fhe::DecryptShare {
                party_id: i as u32,
                bytes: s.0.clone(),
            })
            .collect();
        self.backend
            .aggregate_decrypt(&ciphertext, &fhe_shares, self.threshold)
            .map_err(|e| format!("{e:?}"))
    }

    fn verify_proof(
        &self,
        _proof: &EnclaveProof,
        _public_inputs: &[u8],
    ) -> Result<bool, String> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
