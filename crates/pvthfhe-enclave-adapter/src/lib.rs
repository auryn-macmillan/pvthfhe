//! pvthfhe-enclave-adapter — enclave integration adapter for PVTHFHE ciphernodes.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs, dead_code)]

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
#[cfg(feature = "stub")]
use pvthfhe_types::ProtocolBytes;

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
        Ok(EnclaveKeyShare(share.bytes.0))
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
        Ok(EnclaveDecryptShare(share.bytes.0))
    }
}

#[cfg(feature = "stub")]
impl<B: FheBackend> EnclaveAggregator for PvthfheEnclaveAggregator<B> {
    fn aggregate_keys(&self, shares: &[EnclaveKeyShare]) -> Result<EnclavePublicKey, String> {
        let fhe_shares: Vec<pvthfhe_fhe::KeygenShare> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| pvthfhe_fhe::KeygenShare {
                party_id: u32::try_from(i).unwrap_or(u32::MAX),
                bytes: ProtocolBytes(s.0.clone()),
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
                party_id: u32::try_from(i).unwrap_or(u32::MAX),
                bytes: ProtocolBytes(s.0.clone()),
            })
            .collect();
        self.backend
            .aggregate_decrypt(&ciphertext, &fhe_shares, self.threshold)
            .map_err(|e| format!("{e:?}"))
    }

    fn verify_proof(&self, proof: &EnclaveProof, _public_inputs: &[u8]) -> Result<bool, String> {
        // R10.1: Real attestation verification placeholder.
        //
        // Selected construction: Intel SGX DCAP (Data Center Attestation Primitives)
        // with multi-backend abstraction. See .sisyphus/design/enclave-construction.md.
        //
        // Full SGX DCAP verification flow (deferred to integration phase):
        //   1. Parse the quote header to extract attestation key type (ECDSA-256-P256)
        //   2. Validate the quote signature chain: QE report → attestation key → PCK cert
        //   3. Verify PCK certificate chain against Intel root CA (cached collateral)
        //   4. Check TCB status against minimum acceptable SVN level
        //   5. Extract MRENCLAVE from the quote body
        //   6. Compare MRENCLAVE against on-chain trusted measurement whitelist
        //      (fetched from SessionRegistry.attestorRoots[SGX_DCAP])
        //   7. Verify report_data binds to (session_id || party_id)
        //   8. Check collateral has not expired (collateral_expiration_status)
        //
        // Rust bindings: intel-tee-quote-verification or mc-sgx-dcap-quoteverify.
        // Trust roots loaded from on-chain SessionRegistry (R6.4).
        //
        // Until the Intel SGX SDK / DCAP QVL is integrated, this placeholder
        // rejects all evidence that does not carry a minimum attestation format
        // header. Real SGX ECDSA quotes begin with a 48-byte header (version,
        // attestation key type, reserved, QE vendor ID, user data).
        // See Intel SGX DCAP Spec (rev 1.22) §4.1 "Quote Structure".

        const MIN_ATTESTATION_QUOTE_LEN: usize = 48;
        const SGX_ECDSA_QUOTE_VERSION: u16 = 3;

        if proof.0.len() < MIN_ATTESTATION_QUOTE_LEN {
            return Ok(false);
        }

        let version = u16::from_le_bytes([proof.0[0], proof.0[1]]);
        if version != SGX_ECDSA_QUOTE_VERSION {
            return Ok(false);
        }

        // Attestation key type at offset 2-3: 0x0002 = ECDSA-256-with-P-256
        let att_key_type = u16::from_le_bytes([proof.0[2], proof.0[3]]);
        if att_key_type != 2 {
            return Ok(false);
        }

        // Full DCAP verification is deferred.
        // When integrated, this block will be replaced by a call to:
        //   sgx_dcap_quoteverify::verify(quote, collateral, trust_roots, expected_mrenclave)
        // which returns Result<AttestationResult, AttestationError>.

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
