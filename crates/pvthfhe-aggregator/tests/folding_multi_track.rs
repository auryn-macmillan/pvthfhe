//! H.2 aggregator-facing multi-track folding surface tests.

#![cfg(feature = "real-folding")]
#![allow(missing_docs)]

use pvthfhe_aggregator::folding::{
    fold, FoldAccumulator, FoldStatement, FoldTrackCommitment, FoldTrackKind, FoldWitness,
    MultiTrackFoldMetadata, NizkProof, NizkStatement,
};

const SESSION: &str = "h2-aggregator-session";
const PARAMS: (u64, usize, u64) = (65_537, 1_024, 17);

#[cfg(feature = "real-nizk")]
const VALID_SYNTHETIC_PROOF_LEN: usize = 2 + 32 + 26624;

#[cfg(not(feature = "real-nizk"))]
const VALID_SYNTHETIC_PROOF_LEN: usize = 32;

fn track(
    kind: FoldTrackKind,
    slot_index: Option<u16>,
    fill: u8,
    bound: u64,
) -> FoldTrackCommitment {
    FoldTrackCommitment {
        kind,
        slot_index,
        commitment: vec![fill; 32],
        norm_bound: bound,
    }
}

fn metadata(fill_delta: u8) -> MultiTrackFoldMetadata {
    MultiTrackFoldMetadata {
        session_id: SESSION.to_string(),
        participant_id: 1,
        party_binding: vec![0xAA, 0x01],
        instance_count: 1,
        tracks: vec![
            track(FoldTrackKind::Sk, None, 0x10, 16),
            track(FoldTrackKind::ESm, Some(4), 0x20 ^ fill_delta, 16),
            track(FoldTrackKind::EncryptionWitness, Some(0), 0x30, 16),
        ],
    }
}

fn statement(meta: MultiTrackFoldMetadata) -> FoldStatement {
    FoldStatement {
        fold_index: 1,
        session_id: SESSION.to_string(),
        params: PARAMS,
        nizk_statement: NizkStatement {
            session_id: SESSION.to_string(),
            params: PARAMS,
            ciphertext_bytes: vec![0x05; 4],
            decrypt_share_bytes: vec![0u8; 32],
            pvss_commitment: [0u8; 32],
            multi_track_metadata: Some(meta),
        },
    }
}

fn witness() -> FoldWitness {
    FoldWitness {
        nizk_proof: NizkProof {
            nizk_backend_id: NizkProof::EXPECTED_BACKEND_ID,
            proof_bytes: vec![0u8; VALID_SYNTHETIC_PROOF_LEN],
        },
        fold_randomness: vec![0x11, 0x22],
    }
}

#[test]
fn fold_commitment_changes_when_only_esm_track_changes() {
    let base_acc = FoldAccumulator::new(vec![0x01; 32], 0, SESSION.to_string(), PARAMS, [0u8; 32]);

    let folded_a = fold(&base_acc, &witness(), &statement(metadata(0))).expect("fold a");
    let folded_b = fold(&base_acc, &witness(), &statement(metadata(1))).expect("fold b");

    assert_ne!(
        folded_a.acc_commitment(),
        folded_b.acc_commitment(),
        "aggregator fold commitment must bind e_sm independently of unchanged sk/ciphertext"
    );
    assert_ne!(
        folded_a.statement_hash_chain(),
        folded_b.statement_hash_chain(),
        "statement hash chain must include multi-track public metadata"
    );
}
