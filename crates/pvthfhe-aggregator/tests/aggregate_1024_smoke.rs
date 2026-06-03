//! Smoke test for F9 aggregate_1024 support.
#![allow(missing_docs)]

use pvthfhe_aggregator::folding::HashChainCycloAdapter;
use pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES;
use pvthfhe_cyclo::CcsPShareInstance;
use pvthfhe_cyclo::CycloError;
use pvthfhe_types::CcsWitnessSecret;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

const N_SHARES: u16 = 1024;
const WALL_TIME_CAP_MS: u128 = 5_000;

fn make_share(participant_id: u16) -> CcsPShareInstance {
    let seed = participant_id.to_le_bytes();
    let ajtai_commitment_bytes = vec![seed[0]; AJTAI_COMMITMENT_BYTES];
    let public_io_bytes = vec![seed[1].wrapping_add(1); 32];
    let ccs_witness_bytes = vec![(seed[0] % 101).wrapping_add(seed[1] % 2); 32];
    let sha256_binding_bytes: [u8; 32] = Sha256::new()
        .chain_update(&ajtai_commitment_bytes)
        .chain_update(&public_io_bytes)
        .chain_update(&ccs_witness_bytes)
        .finalize()
        .into();

    CcsPShareInstance {
        participant_id,
        ajtai_commitment_bytes: ajtai_commitment_bytes.into(),
        public_io_bytes: public_io_bytes.into(),
        ccs_witness_bytes: CcsWitnessSecret::new(ccs_witness_bytes),
        sha256_binding_bytes: sha256_binding_bytes.to_vec().into(),
        ccs_matrix_bytes: vec![].into(),
    }
}

fn run_aggregate_smoke(
) -> Result<(pvthfhe_aggregator::folding::CycloFoldAllReport, u128), CycloError> {
    let adapter = HashChainCycloAdapter::new();
    let shares: Vec<CcsPShareInstance> = (1..=N_SHARES).map(make_share).collect();
    let mut rng = StdRng::from_seed([0xA5; 32]);

    let start = Instant::now();
    let report = adapter.fold_all(&shares, "aggregate-1024-smoke", &mut rng)?;
    let wall_ms = start.elapsed().as_millis();
    adapter.verify_fold_all(&report, &shares)?;

    Ok((report, wall_ms))
}

#[test]
fn aggregate_1024_smoke_completes_within_wall_time_cap() {
    let result = run_aggregate_smoke();
    assert!(
        result.is_ok(),
        "aggregate_1024 smoke should succeed: {:?}",
        result.err()
    );
    let (report, wall_ms) = match result {
        Ok(result) => result,
        Err(_) => return,
    };

    assert_eq!(report.share_count(), usize::from(N_SHARES));
    assert_eq!(report.batch_size(), 10);
    assert_eq!(report.batch_count(), 103);
    assert!(
        wall_ms <= WALL_TIME_CAP_MS,
        "aggregation exceeded wall-time cap: {wall_ms}ms > {WALL_TIME_CAP_MS}ms"
    );
}
