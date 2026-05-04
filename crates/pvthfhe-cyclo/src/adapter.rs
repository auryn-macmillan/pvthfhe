//! Real [`CycloAdapter`] implementation wired to the F7 fold driver.

use crate::{
    driver, fold, CcsPShareInstance, CycloAccumulator, CycloAdapter, CycloError, CycloParams,
    CYCLO_BACKEND_ID, PVTHFHE_CYCLO_PARAMS,
};

/// Production implementation of [`CycloAdapter`] backed by the F7 fold driver.
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
        acc: CycloAccumulator,
        instance: &CcsPShareInstance,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloAccumulator, CycloError> {
        fold::fold_one_step(acc, instance, rng)
    }

    fn verify_accumulator(
        &self,
        acc: &CycloAccumulator,
        instances: &[CcsPShareInstance],
    ) -> Result<(), CycloError> {
        fold::verify_fold(acc, instances)
    }

    fn fold_all(
        &self,
        instances: &[CcsPShareInstance],
        session_id: &str,
        rng: &mut dyn rand_core::RngCore,
    ) -> Result<CycloAccumulator, CycloError> {
        driver::fold_all(instances, session_id, rng)
    }
}
