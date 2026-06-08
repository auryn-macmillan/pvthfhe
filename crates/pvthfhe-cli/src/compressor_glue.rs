//! Shared compressor glue for CLI binaries.
//!
//! Track A (Nova BN254+Grumpkin) removed — Track B (LatticeFold+) is the sole backend.

use sha2::{Digest, Sha256};
use tracing::info;
#[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
use tracing::warn;

#[cfg(feature = "nova-compressor")]
use {
    ark_bn254::Fr,
    ark_ff::PrimeField,
    pvthfhe_compressor::{CompressedProof, VerifierKey},
};

/// Surrogate compressor backend identifier.
#[cfg(feature = "surrogate-compressor")]
pub const SURROGATE_COMPRESSOR_ID: &str = "sha256-surrogate-compressor";

/// Legacy Nova compressor identifier (deprecated — Track A removed).
#[cfg(all(
    feature = "nova-compressor",
    not(feature = "enable-latticefold"),
    not(feature = "enable-greyhound")
))]
pub const SONOBE_COMPRESSOR_ID: &str = "nova-bn254-grumpkin";
/// Greyhound-backed compressor backend identifier (deprecated — Track A removed).
#[cfg(all(feature = "nova-compressor", feature = "enable-greyhound"))]
pub const SONOBE_COMPRESSOR_ID: &str = "nova-greyhound-bn254-grumpkin";

/// LatticeFold+ compressor backend identifier (P3).
#[cfg(feature = "enable-latticefold")]
pub const LATTICEFOLD_COMPRESSOR_ID: &str = "latticefold-plus";

/// Compressed proof representation used by the e2e pipeline.
#[derive(Debug)]
pub struct E2eCompressedProof {
    pub digest: [u8; 32],
    pub ivc_proof_hash: Option<[u8; 32]>,
    pub share_verification_hash: Option<[u8; 32]>,
    #[cfg(feature = "nova-compressor")]
    pub nova_proof: Option<CompressedProof>,
}

/// Compressor backend selector.
pub enum Compressor {
    /// LatticeFold+ compressor backend (P3).
    #[cfg(all(feature = "nova-compressor", feature = "enable-latticefold"))]
    LatticeFold {
        /// Inner LatticeFold+ compressor instance.
        inner: pvthfhe_compressor::latticefold::LatticeFoldCompressor,
        /// Verifier key derived during compressor initialization.
        verifier_key: VerifierKey,
    },
    /// Surrogate SHA-256-based compressor backend.
    #[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
    Surrogate,
}

impl Compressor {
    /// Construct a compressor for the active feature set.
    pub fn new(epoch_hash: [u8; 32], ivc_steps: usize) -> anyhow::Result<Self> {
        #[cfg(feature = "enable-latticefold")]
        {
            let inner = pvthfhe_compressor::latticefold::LatticeFoldCompressor::new(
                epoch_hash, ivc_steps, 131_072, // B_Z_S canonical bound
            )
            .map_err(compressor_error_to_anyhow)?;
            let verifier_key = inner.verifier_key();
            Ok(Self::LatticeFold {
                inner,
                verifier_key,
            })
        }

        #[cfg(all(feature = "nova-compressor", not(feature = "enable-latticefold")))]
        {
            compile_error!("Track A (Nova) removed — enable the `enable-latticefold` feature to use the LatticeFold+ backend");
        }

        #[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
        {
            assert_surrogate_compressor_acknowledged();
            Ok(Self::Surrogate)
        }
    }

    /// Return the active compressor backend identifier.
    pub fn backend_id(&self) -> &'static str {
        #[cfg(feature = "enable-latticefold")]
        {
            let Self::LatticeFold { .. } = self;
            LATTICEFOLD_COMPRESSOR_ID
        }
        #[cfg(all(feature = "surrogate-compressor", not(feature = "enable-latticefold")))]
        {
            let Self::Surrogate = self;
            SURROGATE_COMPRESSOR_ID
        }
        #[cfg(not(any(
            feature = "enable-latticefold",
            all(feature = "surrogate-compressor", not(feature = "enable-latticefold"))
        )))]
        {
            "unknown-compressor"
        }
    }

    /// Set the decrypt NIZK hash for IVC proof binding (P1.5).
    pub fn set_decrypt_nizk_hash(&mut self, hash: [u8; 32]) {
        #[cfg(feature = "enable-latticefold")]
        if let Self::LatticeFold { inner, .. } = self {
            inner.set_decrypt_nizk_hash(hash);
        }
    }

    /// Set the DKG transcript hash for IVC proof binding (P1.5).
    pub fn set_dkg_transcript_hash(&mut self, hash: [u8; 32]) {
        #[cfg(feature = "enable-latticefold")]
        if let Self::LatticeFold { inner, .. } = self {
            inner.set_dkg_transcript_hash(hash);
        }
    }

    /// Set whether FHE Mul operations were performed (S2).
    pub fn set_has_fhe_mul_ops(&mut self, v: u64) {
        #[cfg(feature = "enable-latticefold")]
        if let Self::LatticeFold { inner, .. } = self {
            inner.set_has_fhe_mul_ops(v);
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
        #[cfg(feature = "enable-latticefold")]
        let Self::LatticeFold { inner, .. } = self;
        #[cfg(feature = "enable-latticefold")]
        {
            let (acc, public_inputs) = compressor_inputs(report, c7_final_hash);
            let proof = inner
                .prove(&acc, &public_inputs)
                .map_err(compressor_error_to_anyhow)?;
            let ivc_hash = proof.ivc_proof_hash;
            let share_verification_hash = proof.share_verification_hash;
            Ok(E2eCompressedProof {
                digest: sha256_bytes(inner.compressed_proof_bytes(&proof)),
                ivc_proof_hash: ivc_hash,
                share_verification_hash,
                nova_proof: Some(proof),
            })
        }

        #[cfg(all(feature = "nova-compressor", not(feature = "enable-latticefold")))]
        {
            compile_error!("Track A (Nova) removed — enable the `enable-latticefold` feature");
        }

        #[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
        if let Self::Surrogate = self {
            let mut hasher = Sha256::new();
            hasher.update(self.backend_id().as_bytes());
            for accumulator in report.accumulators() {
                hasher.update(&accumulator.acc_commitment_bytes);
                hasher.update(&accumulator.acc_public_io_bytes);
                hasher.update(accumulator.fold_depth.to_le_bytes());
            }
            return Ok(E2eCompressedProof {
                digest: hasher.finalize().into(),
                ivc_proof_hash: None,
                share_verification_hash: None,
                nova_proof: None,
            });
        }

        #[cfg(not(any(
            feature = "enable-latticefold",
            all(feature = "surrogate-compressor", not(feature = "enable-latticefold"))
        )))]
        {
            Err(anyhow::anyhow!("no compressor backend for prove"))
        }
    }

    /// Verify a compressed proof for the fold-all report.
    pub fn verify(
        &self,
        report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
        proof: &E2eCompressedProof,
        c7_final_hash: Fr,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "enable-latticefold")]
        let Self::LatticeFold {
            inner,
            verifier_key,
        } = self;
        #[cfg(feature = "enable-latticefold")]
        {
            let (acc, public_inputs) = compressor_inputs(report, c7_final_hash);
            let Some(nova_proof) = proof.nova_proof.as_ref() else {
                anyhow::bail!("missing compressed proof bytes");
            };
            let verified = inner
                .verify(verifier_key, nova_proof, &acc, &public_inputs)
                .map_err(compressor_error_to_anyhow)?;
            if !verified {
                anyhow::bail!("latticefold proof verification failed");
            }
            let expected_digest = sha256_bytes(inner.compressed_proof_bytes(nova_proof));
            if expected_digest != proof.digest {
                anyhow::bail!("compressed proof digest mismatch");
            }
            Ok(())
        }

        #[cfg(all(feature = "nova-compressor", not(feature = "enable-latticefold")))]
        {
            compile_error!("Track A (Nova) removed — enable the `enable-latticefold` feature");
        }

        #[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
        if let Self::Surrogate = self {
            let expected = self.prove(report, c7_final_hash)?;
            if expected.digest != proof.digest {
                anyhow::bail!("compressed proof digest mismatch");
            }
            return Ok(());
        }

        #[cfg(not(any(
            feature = "enable-latticefold",
            all(feature = "surrogate-compressor", not(feature = "enable-latticefold"))
        )))]
        {
            Err(anyhow::anyhow!("no compressor backend for verify"))
        }
    }
}

/// Return the digest inputs expected by the real compressor backend.
///
/// Produces 96-byte encodings: [commitment(32B) || norm(32B) || fold_count(32B)].
/// The third field is the initial fold count (zero; the IVC step circuit
/// increments fold_count internally by +1 per step). The total fold depth
/// from the CycloFoldAllReport is already incorporated into the accumulator
/// commitment hash.
#[cfg(feature = "nova-compressor")]
pub fn compressor_inputs(
    report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
    c7_final_hash: Fr,
) -> (Vec<u8>, Vec<u8>) {
    let mut acc_hasher = Sha256::new();
    let mut public_hasher = Sha256::new();
    let mut total_norm: u64 = 0;
    let mut total_fold_depth: u64 = 0;
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

    let acc = {
        let a = Fr::from_le_bytes_mod_order(&acc_commitment_hash);
        let b = Fr::from(total_norm);
        let c = Fr::from(0u64);
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&fr_to_be_bytes(a));
        buf.extend_from_slice(&fr_to_be_bytes(b));
        buf.extend_from_slice(&fr_to_be_bytes(c));
        buf
    };
    let public_inputs = {
        let a = Fr::from_le_bytes_mod_order(&public_io_hash);
        let b = Fr::from(total_norm);
        let c = Fr::from(1u64);
        let d = c7_final_hash;
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&fr_to_be_bytes(a));
        buf.extend_from_slice(&fr_to_be_bytes(b));
        buf.extend_from_slice(&fr_to_be_bytes(c));
        buf.extend_from_slice(&fr_to_be_bytes(d));
        buf
    };
    (acc, public_inputs)
}

#[cfg(feature = "nova-compressor")]
fn fr_to_be_bytes(f: ark_bn254::Fr) -> [u8; 32] {
    use ark_ff::PrimeField;
    let bigint: ark_ff::BigInt<4> = f.into();
    let mut out = [0u8; 32];
    for (i, limb) in bigint.0.iter().enumerate() {
        let bytes = limb.to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

/// Convert compressor backend errors into anyhow errors.
#[cfg(feature = "nova-compressor")]
pub fn compressor_error_to_anyhow(error: pvthfhe_compressor::CompressorError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

/// Fail closed unless the surrogate path is explicitly acknowledged.
#[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
pub fn assert_surrogate_compressor_acknowledged() {
    if std::env::var("PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK").as_deref() != Ok("1") {
        eprintln!(
            "PVTHFHE: surrogate compressor requires PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1 to be set in the environment. This path is a mock and fails closed by default."
        );
        std::process::exit(1);
    }
}

/// Return the active compressor backend identifier.
#[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
pub fn compressor_backend_id() -> &'static str {
    SURROGATE_COMPRESSOR_ID
}

#[cfg(feature = "enable-latticefold")]
pub fn external_verify_compressed_proof(
    _compressor: &Compressor,
    _proof: &E2eCompressedProof,
    _report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
    _c7_final_hash: Fr,
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(feature = "nova-compressor", not(feature = "enable-latticefold")))]
pub fn external_verify_compressed_proof(
    _compressor: &Compressor,
    _proof: &E2eCompressedProof,
    _report: &pvthfhe_aggregator::folding::CycloFoldAllReport,
    _c7_final_hash: Fr,
) -> anyhow::Result<()> {
    compile_error!("Track A (Nova) removed — enable the `enable-latticefold` feature");
}

#[cfg(feature = "enable-latticefold")]
pub fn compressor_backend_id() -> &'static str {
    LATTICEFOLD_COMPRESSOR_ID
}

#[cfg(all(feature = "nova-compressor", not(feature = "enable-latticefold")))]
pub fn compressor_backend_id() -> &'static str {
    SONOBE_COMPRESSOR_ID
}

/// Emit the standard compressor-mode log line.
pub fn log_compressor_mode() {
    #[cfg(feature = "enable-latticefold")]
    info!(
        compressor_backend_id = LATTICEFOLD_COMPRESSOR_ID,
        "latticefold-compressor active"
    );

    #[cfg(all(feature = "nova-compressor", not(feature = "enable-latticefold")))]
    info!(
        compressor_backend_id = SONOBE_COMPRESSOR_ID,
        "nova-compressor active"
    );

    #[cfg(all(feature = "surrogate-compressor", not(feature = "nova-compressor")))]
    warn!(
        compressor_backend_id = SURROGATE_COMPRESSOR_ID,
        "surrogate-compressor active"
    );
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
