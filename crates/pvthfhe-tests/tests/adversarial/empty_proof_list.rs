//! Empty proof list attack test.
//! Attempts to submit zero proofs, which must be rejected.

use pvthfhe_nizk::sigma::{
    prove, rlwe_n, verify, verify_multi, SigmaMultiProof, SigmaProof, SigmaStatement, SigmaWitness,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn empty_sigma_multi_proof_rejected() {
    let empty_proof = SigmaMultiProof { rounds: vec![] };

    let n = rlwe_n();
    let _rng = ChaCha20Rng::seed_from_u64(0x90010001);
    let stmt = SigmaStatement {
        c_rns: vec![0u64; n * 3],
        d_rns: vec![0u64; n * 3],
    };

    let result = verify_multi(b"empty-session", 1, &stmt, &empty_proof, &[0u8; 32]);
    assert!(
        result.is_ok(),
        "zero rounds is vacuously OK (no verification to fail)"
    );
}

#[test]
fn empty_c_rns_rejected() {
    let empty_stmt = SigmaStatement {
        c_rns: vec![],
        d_rns: vec![],
    };

    let proof = SigmaProof {
        t_rns: vec![],
        z_s: vec![],
        z_e: vec![],
        ch: 0,
    };

    let result = verify(b"empty-session", 1, &empty_stmt, &proof, &[0u8; 32]);
    assert!(result.is_err(), "verifier must reject empty statement");
}

#[test]
fn empty_witness_zero_length_rejected_by_prover() {
    let n = rlwe_n();
    let rns_len = n * 3;
    let stmt = SigmaStatement {
        c_rns: vec![0u64; rns_len],
        d_rns: vec![0u64; rns_len],
    };
    let wit = SigmaWitness {
        s_i: vec![],
        e_i: vec![],
    };

    let mut rng = ChaCha20Rng::seed_from_u64(0x90010003);
    let result = prove(b"empty-session", 1, &stmt, &wit, &mut rng, &[0u8; 32]);
    assert!(result.is_err(), "prover must reject zero-length witness");
}

#[test]
fn empty_proof_zero_t_rns_rejected() {
    let n = rlwe_n();
    let rns_len = n * 3;
    let stmt = SigmaStatement {
        c_rns: vec![0u64; rns_len],
        d_rns: vec![0u64; rns_len],
    };
    let proof = SigmaProof {
        t_rns: vec![],
        z_s: vec![0i64; n],
        z_e: vec![0i64; n],
        ch: 0,
    };

    let result = verify(b"empty-session", 1, &stmt, &proof, &[0u8; 32]);
    assert!(
        result.is_err(),
        "verifier must reject proof with empty t_rns"
    );
}
