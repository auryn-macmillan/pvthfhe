//! Shared compressor glue for CLI binaries.

use sha2::{Digest, Sha256};
#[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
use tracing::warn;
use tracing::info;

#[cfg(feature = "sonobe-compressor")]
use pvthfhe_compressor::{
    sonobe::SonobeCompressor, CompressedProof as SonobeProof, ProofCompressor, VerifierKey,
};

/// Surrogate compressor backend identifier.
#[cfg(feature = "surrogate-compressor")]
pub const SURROGATE_COMPRESSOR_ID: &str = "sha256-surrogate-compressor";

/// Sonobe compressor backend identifier.
#[cfg(feature = "sonobe-compressor")]
pub const SONOBE_COMPRESSOR_ID: &str = "sonobe-nova-bn254-grumpkin";

/// Compressed proof representation used by the e2e pipeline.
#[derive(Debug)]
pub struct E2eCompressedProof {
    /// Stable digest of the compressed proof bytes.
    pub digest: [u8; 32],
    #[cfg(feature = "sonobe-compressor")]
    sonobe_proof: Option<SonobeProof>,
}

/// Compressor backend selector.
pub enum Compressor {
    /// Real Sonobe compressor backend.
    #[cfg(feature = "sonobe-compressor")]
    Sonobe {
        /// Inner Sonobe compressor instance.
        inner: SonobeCompressor,
        /// Verifier key derived during compressor initialization.
        verifier_key: VerifierKey,
    },
    /// Surrogate SHA-256-based compressor backend.
    #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
    Surrogate,
}

impl Compressor {
    /// Construct a compressor for the active feature set.
    pub fn new(seed: u64) -> anyhow::Result<Self> {
        #[cfg(feature = "sonobe-compressor")]
        {
            let inner = SonobeCompressor::new(seed).map_err(compressor_error_to_anyhow)?;
            let verifier_key = inner.verifier_key();
            return Ok(Self::Sonobe {
                inner,
                verifier_key,
            });
        }

        #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
        {
            assert_surrogate_compressor_acknowledged();
            Ok(Self::Surrogate)
        }
    }

    /// Return the active compressor backend identifier.
    pub fn backend_id(&self) -> &'static str {
        match self {
            #[cfg(feature = "sonobe-compressor")]
            Self::Sonobe { .. } => SONOBE_COMPRESSOR_ID,
            #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
            Self::Surrogate => SURROGATE_COMPRESSOR_ID,
        }
    }

    /// Produce a compressed proof for the fold-all report.
    pub fn prove(
        &self,
        report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
    ) -> anyhow::Result<E2eCompressedProof> {
        match self {
            #[cfg(feature = "sonobe-compressor")]
            Self::Sonobe { inner, .. } => {
                let (acc, public_inputs) = compressor_inputs(report);
                let proof = inner
                    .prove(&acc, &public_inputs)
                    .map_err(compressor_error_to_anyhow)?;
                Ok(E2eCompressedProof {
                    digest: sha256_bytes(inner.compressed_proof_bytes(&proof)),
                    sonobe_proof: Some(proof),
                })
            }
            #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
            Self::Surrogate => {
                let mut hasher = Sha256::new();
                hasher.update(self.backend_id().as_bytes());
                for accumulator in report.accumulators() {
                    hasher.update(&accumulator.acc_commitment_bytes);
                    hasher.update(&accumulator.acc_public_io_bytes);
                    hasher.update(accumulator.fold_depth.to_le_bytes());
                }
                Ok(E2eCompressedProof {
                    digest: hasher.finalize().into(),
                    #[cfg(feature = "sonobe-compressor")]
                    sonobe_proof: None,
                })
            }
        }
    }

    /// Verify a compressed proof for the fold-all report.
    pub fn verify(
        &self,
        report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
        proof: &E2eCompressedProof,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(feature = "sonobe-compressor")]
            Self::Sonobe {
                inner,
                verifier_key,
            } => {
                let (_, public_inputs) = compressor_inputs(report);
                let Some(sonobe_proof) = proof.sonobe_proof.as_ref() else {
                    anyhow::bail!("missing sonobe compressed proof bytes");
                };
                let verified = inner
                    .verify(verifier_key, sonobe_proof, &public_inputs)
                    .map_err(compressor_error_to_anyhow)?;
                if !verified {
                    anyhow::bail!("sonobe compressed proof verification failed");
                }
                let expected_digest = sha256_bytes(inner.compressed_proof_bytes(sonobe_proof));
                if expected_digest != proof.digest {
                    anyhow::bail!("compressed proof digest mismatch");
                }
                Ok(())
            }
            #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
            Self::Surrogate => {
                let expected = self.prove(report)?;
                if expected.digest != proof.digest {
                    anyhow::bail!("compressed proof digest mismatch");
                }
                Ok(())
            }
        }
    }
}

/// Return the digest inputs expected by the real compressor backend.
#[cfg(feature = "sonobe-compressor")]
pub fn compressor_inputs(
    report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
) -> (Vec<u8>, Vec<u8>) {
    let mut acc_hasher = Sha256::new();
    let mut public_hasher = Sha256::new();
    for accumulator in report.accumulators() {
        acc_hasher.update(&accumulator.acc_commitment_bytes);
        public_hasher.update(&accumulator.acc_public_io_bytes);
        public_hasher.update(accumulator.fold_depth.to_le_bytes());
    }
    let acc: [u8; 32] = acc_hasher.finalize().into();
    let public_inputs: [u8; 32] = public_hasher.finalize().into();
    (acc.to_vec(), public_inputs.to_vec())
}

/// Convert compressor backend errors into anyhow errors.
#[cfg(feature = "sonobe-compressor")]
pub fn compressor_error_to_anyhow(error: pvthfhe_compressor::CompressorError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

/// Fail closed unless the surrogate path is explicitly acknowledged.
#[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
pub fn assert_surrogate_compressor_acknowledged() {
    if std::env::var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK").as_deref() != Ok("1") {
        eprintln!(
            "PVTHFHE: surrogate compressor requires PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 to be set in the environment. This path is a mock and fails closed by default."
        );
        std::process::exit(1);
    }
}

/// Return the active compressor backend identifier.
#[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
pub fn compressor_backend_id() -> &'static str {
    SURROGATE_COMPRESSOR_ID
}

/// Return the active compressor backend identifier.
#[cfg(feature = "sonobe-compressor")]
pub fn compressor_backend_id() -> &'static str {
    SONOBE_COMPRESSOR_ID
}

/// Emit the standard compressor-mode log line.
pub fn log_compressor_mode() {
    #[cfg(feature = "sonobe-compressor")]
    info!(
        compressor_backend_id = SONOBE_COMPRESSOR_ID,
        "sonobe-compressor active"
    );

    #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
    warn!(
        compressor_backend_id = SURROGATE_COMPRESSOR_ID,
        "surrogate-compressor active: SHA-256 scaffold is in use only with explicit mock acknowledgement"
    );
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
