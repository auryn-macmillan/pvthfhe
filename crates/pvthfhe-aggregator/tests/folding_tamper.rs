#![allow(clippy::unwrap_used)]

use pvthfhe_aggregator::folding::{PartyProof, FoldingAccumulator, FoldingError};

#[test]
fn test_folding_tamper() {
    let mut accumulator = FoldingAccumulator::new();
    
    for i in 0..64 {
        let nizk = if i == 42 { vec![] } else { vec![1, 2, 3] };
        let proof = PartyProof {
            party_id: i as u32,
            share_hash: [i as u8; 32],
            nizk_bytes: nizk,
        };
        accumulator.add_proof(proof).unwrap();
    }
    
    let result = accumulator.finalize();
    match result {
        Err(FoldingError::InvalidLeaf(id)) => assert_eq!(id, 42),
        _ => panic!("Expected InvalidLeaf error"),
    }
}
