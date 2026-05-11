use pvthfhe_aggregator::keygen::types::Round1Message;
use pvthfhe_cli::demo_nizk::build_demo_nizk_inputs;
use pvthfhe_fhe::PublicKey;

const RLWE_N: usize = pvthfhe_nizk::sigma::RLWE_N;

#[test]
fn cli_demo_nizk_statement_uses_canonical_params() {
    let message = Round1Message {
        party_id: 7,
        pk_i: PublicKey { bytes: vec![1, 2, 3, 4] },
        pk_i_hash: [9; 32],
        commitment: [8; 32],
        poly_commit: [7; 32],
        encrypted_shares: Default::default(),
        nizk: vec![],
    };
    let secret_key_bytes = vec![0u8; RLWE_N * 8];

    let (statement, _witness) =
        build_demo_nizk_inputs("session-1", &message, None, &secret_key_bytes).unwrap();

    assert_eq!(statement.params.1, pvthfhe_nizk::sigma::RLWE_N);
    assert_eq!(statement.params.2, pvthfhe_nizk::sigma::B_E as u64);
}
