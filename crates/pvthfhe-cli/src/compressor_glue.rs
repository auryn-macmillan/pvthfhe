//! Shared compressor glue for CLI binaries.

use sha2::{Digest, Sha256};
use tracing::info;
#[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
use tracing::warn;

#[cfg(feature = "sonobe-compressor")]
use {
    ark_bn254::Fr,
    ark_ff::PrimeField,
    pvthfhe_compressor::{
        nova::{encode_quad, encode_triple, CycloFoldStepCircuit, NovaCompressor},
        CompressedProof as NovaProof, ProofCompressor, VerifierKey,
    },
};

/// Surrogate compressor backend identifier.
#[cfg(feature = "surrogate-compressor")]
pub const SURROGATE_COMPRESSOR_ID: &str = "sha256-surrogate-compressor";

/// Nova compressor backend identifier.
#[cfg(feature = "sonobe-compressor")]
pub const SONOBE_COMPRESSOR_ID: &str = "nova-bn254-grumpkin";

/// Compressed proof representation used by the e2e pipeline.
#[derive(Debug)]
pub struct E2eCompressedProof {
    pub digest: [u8; 32],
    pub ivc_proof_hash: Option<[u8; 32]>,
    pub ivc_binding: Option<pvthfhe_compressor::nova::snark_bridge::IvcBindingData>,
    #[cfg(feature = "sonobe-compressor")]
    pub nova_proof: Option<NovaProof>,
}

/// Compressor backend selector.
pub enum Compressor {
    /// Real Nova compressor backend.
    #[cfg(feature = "sonobe-compressor")]
    Nova {
        /// Inner Nova compressor instance.
        inner: NovaCompressor<CycloFoldStepCircuit<Fr>>,
        /// Verifier key derived during compressor initialization.
        verifier_key: VerifierKey,
    },
    /// Surrogate SHA-256-based compressor backend.
    #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
    Surrogate,
}

impl Compressor {
    /// Construct a compressor for the active feature set.
    pub fn new(epoch_hash: [u8; 32], ivc_steps: usize) -> anyhow::Result<Self> {
        #[cfg(feature = "sonobe-compressor")]
        {
            // The CycloFoldStepCircuit performs field arithmetic on hashed accumulator
            // state (3 Fr elements: commitment_hash, norm, fold_count).  It does NOT perform
            // full Ajtai commitment folding — the design intentionally hashes the
            // accumulator down to 3 field elements before entering the IVC because
            // lattice-native folding is infeasible inside a Nova Nova step circuit.
            // Full Ajtai folding remains an open problem (P2).
            let inner = NovaCompressor::<CycloFoldStepCircuit<Fr>>::new(epoch_hash, ivc_steps)
                .map_err(compressor_error_to_anyhow)?;
            let verifier_key = inner.verifier_key();
            Ok(Self::Nova {
                inner,
                verifier_key,
            })
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
            Self::Nova { .. } => SONOBE_COMPRESSOR_ID,
            #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
            Self::Surrogate => SURROGATE_COMPRESSOR_ID,
        }
    }

    /// Produce a compressed proof for the fold-all report.
    /// `c7_final_hash` binds the C7 decrypt-aggregation final state to
    /// the CycloFold proof (G.16 hash chain).
    pub fn prove(
        &self,
        report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
        c7_final_hash: Fr,
    ) -> anyhow::Result<E2eCompressedProof> {
        match self {
            #[cfg(feature = "sonobe-compressor")]
            Self::Nova { inner, .. } => {
                let (acc, public_inputs) = compressor_inputs(report, c7_final_hash);
                let proof = inner
                    .prove(&acc, &public_inputs)
                    .map_err(compressor_error_to_anyhow)?;
                let ivc_hash = proof.ivc_proof_hash;
                let ivc_binding = proof.ivc_binding.clone();
                Ok(E2eCompressedProof {
                    digest: sha256_bytes(inner.compressed_proof_bytes(&proof)),
                    ivc_proof_hash: ivc_hash,
                    ivc_binding,
                    nova_proof: Some(proof),
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
                    ivc_proof_hash: None,
                    ivc_binding: None,
                    #[cfg(feature = "sonobe-compressor")]
                    nova_proof: None,
                })
            }
        }
    }

    /// Verify a compressed proof for the fold-all report.
    pub fn verify(
        &self,
        report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
        proof: &E2eCompressedProof,
        c7_final_hash: Fr,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(feature = "sonobe-compressor")]
            Self::Nova {
                inner,
                verifier_key,
            } => {
                let (acc, public_inputs) = compressor_inputs(report, c7_final_hash);
                let Some(nova_proof) = proof.nova_proof.as_ref() else {
                    anyhow::bail!("missing nova compressed proof bytes");
                };
                let verified = inner
                    .verify(verifier_key, nova_proof, &acc, &public_inputs)
                    .map_err(compressor_error_to_anyhow)?;
                if !verified {
                    anyhow::bail!("nova compressed proof verification failed");
                }
                let expected_digest = sha256_bytes(inner.compressed_proof_bytes(nova_proof));
                if expected_digest != proof.digest {
                    anyhow::bail!("compressed proof digest mismatch");
                }
                Ok(())
            }
            #[cfg(all(feature = "surrogate-compressor", not(feature = "sonobe-compressor")))]
            Self::Surrogate => {
                let expected = self.prove(report, c7_final_hash)?;
                if expected.digest != proof.digest {
                    anyhow::bail!("compressed proof digest mismatch");
                }
                Ok(())
            }
        }
    }
}

/// Return the digest inputs expected by the real compressor backend.
///
/// Produces 96-byte encodings: [commitment(32B) || norm(32B) || fold_count(32B)].
/// The third field is the initial fold count (zero; the IVC step circuit
/// increments fold_count internally by +1 per step). The total fold depth
/// from the CycloFoldAllReport is already incorporated into the accumulator
/// commitment hash; duplicating it in the initial fold count would cause a
/// permanent mismatch against `verification_count` during verification.
/// Step counter is hardcoded as `+1` inside
/// [`CycloFoldStepCircuit::generate_step_constraints`].
#[cfg(feature = "sonobe-compressor")]
pub fn compressor_inputs(
    report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
    c7_final_hash: Fr,
) -> (Vec<u8>, Vec<u8>) {
    let mut acc_hasher = Sha256::new();
    let mut public_hasher = Sha256::new();
    let mut total_fold_depth: u64 = 0;
    let mut total_norm: u64 = 0;
    // T4 domain-separator: hash accumulator count before the loop
    let num_accumulators = report.accumulators().len();
    acc_hasher.update((num_accumulators as u64).to_be_bytes());
    public_hasher.update((num_accumulators as u64).to_be_bytes());
    for accumulator in report.accumulators() {
        acc_hasher.update(&accumulator.acc_commitment_bytes);
        public_hasher.update(&accumulator.acc_public_io_bytes);
        total_fold_depth = total_fold_depth.saturating_add(accumulator.fold_depth as u64);
        total_norm = total_norm.saturating_add(accumulator.norm_bound_current);
    }
    let acc_commitment_hash: [u8; 32] = acc_hasher.finalize().into();
    let public_io_hash: [u8; 32] = public_hasher.finalize().into();

    let acc = encode_triple((
        Fr::from_le_bytes_mod_order(&acc_commitment_hash),
        Fr::from(total_norm),
        Fr::from(0u64),
    ))
    .to_vec();
    let public_inputs = encode_quad((
        Fr::from_le_bytes_mod_order(&public_io_hash),
        Fr::from(total_norm),
        Fr::from(1u64),
        c7_final_hash,
    ))
    .to_vec();
    (acc, public_inputs)
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

/// Run an independent external verification of the compressed proof.
///
/// Uses a separate deserialization path (NovaCompressor::verify_external) that
/// re-parses proof bytes and builds a fresh verifier from key bytes, providing a
/// second verification that does not share state with the primary `verify` call.
#[cfg(feature = "sonobe-compressor")]
pub fn external_verify_compressed_proof(
    compressor: &Compressor,
    proof: &E2eCompressedProof,
    report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
    c7_final_hash: Fr,
) -> anyhow::Result<()> {
    match compressor {
        Compressor::Nova { inner, .. } => {
            let (acc, public_inputs) = compressor_inputs(report, c7_final_hash);
            let Some(nova_proof) = proof.nova_proof.as_ref() else {
                anyhow::bail!("missing nova compressed proof bytes for external verification");
            };
            let proof_bytes = inner.compressed_proof_bytes(nova_proof);
            let verified = inner
                .verify_external(proof_bytes, &acc, &public_inputs)
                .map_err(compressor_error_to_anyhow)?;
            if !verified {
                anyhow::bail!("external nova compressed proof verification failed");
            }
            Ok(())
        }
    }
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
        "nova-compressor active"
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
