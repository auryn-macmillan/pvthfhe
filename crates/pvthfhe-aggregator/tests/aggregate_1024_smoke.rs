use pvthfhe_aggregator::folding::CycloFoldingAdapter;
use pvthfhe_cyclo::CcsPShareInstance;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::time::Instant;

const N_SHARES: u16 = 1024;
const WALL_TIME_CAP_MS: u128 = 5_000;

fn make_share(participant_id: u16) -> CcsPShareInstance {
    let seed = participant_id.to_le_bytes();
    let ajtai_commitment_bytes = vec![seed[0]; 32];
    let public_io_bytes = vec![seed[1].wrapping_add(1); 32];
    let ccs_witness_bytes = vec![seed[0].wrapping_add(seed[1]).wrapping_add(2); 32];
    let sha256_binding_bytes: [u8; 32] = Sha256::new()
        .chain_update(&ajtai_commitment_bytes)
        .chain_update(&public_io_bytes)
        .chain_update(&ccs_witness_bytes)
        .finalize()
        .into();

    CcsPShareInstance {
        participant_id,
        ajtai_commitment_bytes,
        public_io_bytes,
        ccs_witness_bytes,
        sha256_binding_bytes: sha256_binding_bytes.to_vec(),
    }
}

#[test]
fn aggregate_1024_smoke_completes_within_wall_time_cap() {
    let adapter = CycloFoldingAdapter::new();
    let shares: Vec<CcsPShareInstance> = (1..=N_SHARES).map(make_share).collect();
    let mut rng = StdRng::from_seed([0xA5; 32]);

    let start = Instant::now();
    let result = adapter.fold_all(&shares, "aggregate-1024-smoke", &mut rng);
    let wall_ms = start.elapsed().as_millis();

    assert!(
        result.is_ok(),
        "aggregating 1024 per-share NIZKs should succeed end-to-end"
    );
    assert!(
        wall_ms <= WALL_TIME_CAP_MS,
        "aggregation exceeded wall-time cap: {wall_ms}ms > {WALL_TIME_CAP_MS}ms"
    );
}
