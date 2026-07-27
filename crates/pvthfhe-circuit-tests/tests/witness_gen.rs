//! Witness-generation regression test for the full decrypt-share circuit.

use pvthfhe_circuit_tests::witness_gen::{
    generate_decrypt_share_witness, noir_bind_8_with_domain, noir_vector_hash, B_E,
    DECRYPT_SHARE_N,
};
use ark_bn254::Fr;

#[test]
fn generated_decrypt_share_witness_matches_circuit_invariants() {
    let witness = generate_decrypt_share_witness();

    assert_eq!(witness.sk_i.len(), DECRYPT_SHARE_N);
    assert_eq!(witness.e_i.len(), DECRYPT_SHARE_N);
    assert_eq!(witness.c1.len(), DECRYPT_SHARE_N);
    assert_eq!(witness.d_i.len(), DECRYPT_SHARE_N);
    assert_eq!(witness.party_id, "1");
    assert_eq!(witness.epoch, "1");
    let sk_fr: Vec<Fr> = witness.sk_i.iter().map(|v| v.parse::<Fr>().unwrap()).collect();
    let c1_fr: Vec<Fr> = witness.c1.iter().map(|v| v.parse::<Fr>().unwrap()).collect();
    let d_i_fr: Vec<Fr> = witness.d_i.iter().map(|v| v.parse::<Fr>().unwrap()).collect();
    // Circuit-exact constructions: vector hashes via the x5_5 sponge with
    // DOMAIN_VECTOR_MERKLE (=1); the statement binding via fixed-arity hash_9
    // with DOMAIN_STATEMENT_BINDING (=2).
    assert_eq!(witness.pk_i_hash, noir_vector_hash(&sk_fr, Fr::from(1u64)).to_string());
    assert_eq!(witness.c1_hash, noir_vector_hash(&c1_fr, Fr::from(1u64)).to_string());
    assert_eq!(witness.d_i_hash, noir_vector_hash(&d_i_fr, Fr::from(1u64)).to_string());
    let expected_statement = noir_bind_8_with_domain(
        [
            Fr::from(1u64),
            noir_vector_hash(&sk_fr, Fr::from(1u64)),
            witness.dkg_root.parse::<Fr>().unwrap(),
            witness.ciphertext_hash.parse::<Fr>().unwrap(),
            Fr::from(1u64),
            noir_vector_hash(&c1_fr, Fr::from(1u64)),
            noir_vector_hash(&d_i_fr, Fr::from(1u64)),
            Fr::from((DECRYPT_SHARE_N + B_E as usize) as u64),
        ],
        Fr::from(2u64),
    );
    assert_eq!(witness.compact_statement_hash, expected_statement.to_string());
    assert!(!witness.q.is_empty());

    for value in &witness.e_i {
        let parsed: u32 = value
            .parse()
            .unwrap_or_else(|err| panic!("e_i entry should parse as u32: {err}"));
        assert!(parsed <= B_E);
    }
}
