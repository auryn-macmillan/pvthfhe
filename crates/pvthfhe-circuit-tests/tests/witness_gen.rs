//! Witness-generation regression test for the full decrypt-share circuit.

use pvthfhe_circuit_tests::witness_gen::{
    generate_decrypt_share_witness, rolling_digest, rolling_digest_8, B_E, N,
};

#[test]
fn generated_decrypt_share_witness_matches_circuit_invariants() {
    let witness = generate_decrypt_share_witness();

    assert_eq!(witness.sk_i.len(), N);
    assert_eq!(witness.e_i.len(), N);
    assert_eq!(witness.c1.len(), N);
    assert_eq!(witness.d_i.len(), N);
    assert_eq!(witness.party_id, "1");
    assert_eq!(witness.epoch, "1");
    assert_eq!(witness.c1_hash, rolling_digest(&witness.c1));
    assert_eq!(witness.d_i_hash, rolling_digest(&witness.d_i));
    assert_eq!(witness.pk_i_hash, rolling_digest(&witness.sk_i));
    assert_eq!(
        witness.compact_statement_hash,
        rolling_digest_8(&[
            witness.party_id.clone(),
            witness.pk_i_hash.clone(),
            witness.dkg_root.clone(),
            witness.ciphertext_hash.clone(),
            witness.epoch.clone(),
            witness.c1_hash.clone(),
            witness.d_i_hash.clone(),
            format!("{}", N + B_E as usize),
        ])
    );
    assert!(!witness.q.is_empty());

    for value in &witness.e_i {
        let parsed: u32 = value.parse().expect("e_i entry should parse as u32");
        assert!(parsed <= B_E);
    }
}
