use pvthfhe_nizk::adapter::CycloNizkAdapter;
use pvthfhe_nizk::hash_bridge;
use pvthfhe_nizk::sigma::RLWE_N;
use pvthfhe_nizk::{NizkAdapter, NizkProof, NizkStatement, NizkWitness};
use rand_chacha::rand_core::SeedableRng;

fn minimal_valid_stmt() -> NizkStatement {
    let session_id = "dos-test";
    let participant_id: u16 = 1;
    let pvss_commitment = hash_bridge::commit(session_id, participant_id, 0u64);
    NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment,
        params: (65_537_u64, RLWE_N, 16_u64),
        session_id: session_id.to_owned(),
        participant_id,
        epoch: 0,
    }
}

#[test]
fn oversized_proof_bytes_rejected() {
    let adapter = CycloNizkAdapter;
    let stmt = minimal_valid_stmt();
    let proof = NizkProof {
        backend_id: pvthfhe_nizk::BACKEND_ID.to_owned(),
        proof_bytes: vec![0u8; 1_048_577],
    };
    let result = adapter.verify(&stmt, &proof);
    assert!(result.is_err(), "oversized proof must be rejected");
}

#[test]
fn oversized_session_id_rejected() {
    let adapter = CycloNizkAdapter;
    let long_sid = "x".repeat(257);
    let stmt = NizkStatement {
        ciphertext_bytes: vec![0u8; 32],
        decrypt_share_bytes: vec![0u8; 32],
        pvss_commitment: [0u8; 32],
        params: (65_537_u64, RLWE_N, 16_u64),
        session_id: long_sid,
        participant_id: 1,
        epoch: 0,
    };
    let witness = NizkWitness {
        secret_share: 0,
        secret_share_poly: vec![0i64; RLWE_N],
        error: vec![0i64; RLWE_N],
        randomness: vec![],
    };
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xD05_B0);
    let result = adapter.prove(&stmt, &witness, &mut rng);
    assert!(
        result.is_err(),
        "oversized session_id must be rejected on prove"
    );

    let proof = NizkProof {
        backend_id: pvthfhe_nizk::BACKEND_ID.to_owned(),
        proof_bytes: vec![0u8; 32],
    };
    let result2 = adapter.verify(&stmt, &proof);
    assert!(
        result2.is_err(),
        "oversized session_id must be rejected on verify"
    );
}

#[test]
fn batch_verify_excessive_count_rejected() {
    let adapter = CycloNizkAdapter;
    let stmt = minimal_valid_stmt();
    let proof = NizkProof {
        backend_id: pvthfhe_nizk::BACKEND_ID.to_owned(),
        proof_bytes: vec![0u8; 32],
    };
    let stmts: Vec<NizkStatement> = std::iter::repeat(stmt).take(1025).collect();
    let proofs: Vec<NizkProof> = std::iter::repeat(proof).take(1025).collect();
    let result = adapter.batch_verify(&stmts, &proofs);
    assert!(
        result.is_err(),
        "batch_verify with >1024 entries must be rejected"
    );
}
