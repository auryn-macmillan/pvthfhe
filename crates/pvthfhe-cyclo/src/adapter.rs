//! Stub [`CycloAdapter`] implementation.
//!
//! All methods return errors until F2–F7 replace this skeleton.

use crate::{
    CcsPShareInstance, CycloAccumulator, CycloAdapter, CycloError, CycloParams, CYCLO_BACKEND_ID,
    PVTHFHE_CYCLO_PARAMS,
};

/// Zero-sized stub implementing [`CycloAdapter`].
///
/// Every method returns an appropriate [`CycloError`] until the real
/// LatticeFold+ logic is wired in by tasks F2–F7.
pub struct StubCycloAdapter;

impl CycloAdapter for StubCycloAdapter {
    fn backend_id(&self) -> &'static str {
        CYCLO_BACKEND_ID
    }

    fn params(&self) -> &CycloParams {
        &PVTHFHE_CYCLO_PARAMS
    }

    fn fold_one(
        &self,
        _acc: CycloAccumulator,
        _instance: &CcsPShareInstance,
        _rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloAccumulator, CycloError> {
        Err(CycloError::InvalidInstance("F2-F7 not yet implemented"))
    }

    fn verify_accumulator(
        &self,
        _acc: &CycloAccumulator,
        _instances: &[CcsPShareInstance],
    ) -> Result<(), CycloError> {
        Err(CycloError::AccumulatorVerificationFailed(
            "F2-F7 not yet implemented",
        ))
    }

    fn fold_all(
        &self,
        instances: &[CcsPShareInstance],
        session_id: &str,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloAccumulator, CycloError> {
        use sha2::{Digest, Sha256};

        let params_digest: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"pvthfhe-cyclo-params-v1");
            h.finalize().into()
        };

        let mut acc = CycloAccumulator {
            fold_depth: 0,
            acc_commitment_bytes: Vec::new(),
            acc_public_io_bytes: Vec::new(),
            norm_bound_current: PVTHFHE_CYCLO_PARAMS.norm_bound_b,
            session_id: session_id.to_owned(),
            params_digest,
        };

        for instance in instances {
            acc = self.fold_one(acc, instance, rng)?;
        }

        Ok(acc)
    }
}
