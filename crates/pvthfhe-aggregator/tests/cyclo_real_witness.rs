#![cfg(all(feature = "real-folding", feature = "real-nizk"))]
#![allow(missing_docs, clippy::unwrap_used)]

//! FF1: verify that `fold_stmt_witness_to_cyclo_instance` uses real
//! CCS witness bytes extracted from the NIZK proof instead of the demo
//! zero-witness placeholder when `real-nizk` is active.

use pvthfhe_aggregator::folding::{
    demo_zero_witness_bytes, fold_stmt_witness_to_cyclo_instance, FoldAccumulator, FoldStatement,
    FoldWitness, NizkProof, NizkStatement,
};
use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::rlwe_n;
use pvthfhe_nizk::{NizkAdapter, NizkStatement as NizkCrateStatement};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn sample_ternary(rng: &mut ChaCha20Rng) -> Vec<i64> {
    let mut s = vec![0i64; rlwe_n()];
    for x in s.iter_mut() {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        *x = match b[0] % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }
    s
}

fn sample_error(rng: &mut ChaCha20Rng) -> Vec<i64> {
    const B_E: i64 = 16;
    const RANGE: u64 = 33;
    const THRESHOLD: u64 = u64::MAX - (u64::MAX % RANGE);
    let mut e = vec![0i64; rlwe_n()];
    for x in e.iter_mut() {
        loop {
            let v = rng.next_u64();
            if v < THRESHOLD {
                *x = i64::try_from(v % RANGE).unwrap() - B_E;
                break;
            }
        }
    }
    e
}

fn base_params() -> (u64, usize, u64) {
    (65_537, rlwe_n(), 16)
}

fn base_acc(session_id: &str) -> FoldAccumulator {
    FoldAccumulator::new(
        vec![0u8; 4],
        0,
        session_id.to_string(),
        base_params(),
        [0u8; 32],
    )
}

/// FF1-T1 (RED): `ccs_witness_bytes` produced by `fold_stmt_witness_to_cyclo_instance`
/// must NOT be the demo zero-witness placeholder.  The Cyclo fold path must consume
/// real sigma witness bytes extracted from the NIZK proof.
#[test]
fn cyclo_instance_uses_real_witness() {
    let session_id = "ff1-real-witness";
    let mut rng = ChaCha20Rng::seed_from_u64(0xFF01_0001);
    let adapter = CycloNizkAdapter;

    let s_i = sample_ternary(&mut rng);
    let e_i = sample_error(&mut rng);
    let secret_share: u64 = s_i[0].unsigned_abs();
    let pvss_commitment = hash_bridge::commit(session_id, 1, secret_share);

    let nizk_stmt = NizkCrateStatement {
        ciphertext_bytes: vec![0xAAu8; 32],
        decrypt_share_bytes: vec![0xBBu8; 32],
        pvss_commitment,
        params: base_params(),
        session_id: session_id.to_owned(),
        participant_id: 1,
        epoch: 0,
    };
    let nizk_witness = pvthfhe_nizk::NizkWitness {
        secret_share,
        secret_share_poly: s_i,
        error: e_i,
        randomness: vec![],
    };

    let nizk_proof = adapter
        .prove(&nizk_stmt, &nizk_witness, &mut rng)
        .expect("honest NIZK prove must succeed");

    let acc = base_acc(session_id);
    let stmt = FoldStatement {
        fold_index: 1,
        session_id: session_id.to_owned(),
        params: base_params(),
        nizk_statement: NizkStatement {
            session_id: session_id.to_owned(),
            params: base_params(),
            ciphertext_bytes: vec![0xAAu8; 32],
            decrypt_share_bytes: vec![0xBBu8; 32],
            pvss_commitment,
            multi_track_metadata: None,
        },
    };
    let witness = FoldWitness {
        nizk_proof: NizkProof {
            proof_bytes: nizk_proof.proof_bytes,
            nizk_backend_id: pvthfhe_nizk::BACKEND_ID,
        },
        fold_randomness: vec![0x42; 8],
    };

    let ccs_instance = fold_stmt_witness_to_cyclo_instance(&stmt, &witness, &acc)
        .expect("fold_stmt_witness_to_cyclo_instance must succeed");

    let ccs_witness_bytes = ccs_instance.base.ccs_witness_bytes.expose().to_vec();
    let demo_bytes = demo_zero_witness_bytes();

    assert_ne!(
        ccs_witness_bytes, demo_bytes,
        "FF1: ccs_witness_bytes must NOT be the demo zero-witness placeholder; \
         the Cyclo fold instance must use real sigma witness bytes extracted from the NIZK proof"
    );
}
