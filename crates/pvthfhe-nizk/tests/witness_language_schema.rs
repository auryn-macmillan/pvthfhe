use pvthfhe_types::witness_language::{
    BfvParameters, R3Relation, SchemaError, WitnessSchemaVersion, WitnessStatement,
};
use pvthfhe_types::ProtocolBytes;

fn make_share_wf_statement() -> WitnessStatement {
    WitnessStatement {
        version: WitnessSchemaVersion::V1,
        relation: R3Relation::ShareWellFormedness,
        session_id: ProtocolBytes::from(b"test-session-001".to_vec()),
        participant_id: 7u16,
        params: BfvParameters {
            q_log2: 174,
            degree: 8192,
            error_bound: 16,
        },
        public_key: ProtocolBytes::from(vec![0xABu8; 32]),
        ciphertext: ProtocolBytes::from(vec![0xCDu8; 64]),
        commitment: ProtocolBytes::from(vec![0xEFu8; 32]),
        dkg_root: ProtocolBytes::from(vec![0x11u8; 32]),
    }
}

#[test]
fn schema_round_trip_witness_statement_v1() {
    let stmt = make_share_wf_statement();
    let bytes = stmt
        .to_statement_bytes()
        .expect("valid V1 statement must serialize");
    let recovered =
        WitnessStatement::from_statement_bytes(&bytes).expect("valid V1 bytes must deserialize");

    assert_eq!(recovered.version, WitnessSchemaVersion::V1);
    assert_eq!(recovered.relation, R3Relation::ShareWellFormedness);
    assert_eq!(recovered.session_id.as_slice(), b"test-session-001");
    assert_eq!(recovered.participant_id, 7u16);
    assert_eq!(recovered.params.q_log2, 174);
    assert_eq!(recovered.params.degree, 8192);
    assert_eq!(recovered.params.error_bound, 16);
    assert_eq!(recovered.public_key.as_slice(), &[0xABu8; 32][..]);
    assert_eq!(recovered.ciphertext.as_slice(), &[0xCDu8; 64][..]);
    assert_eq!(recovered.commitment.as_slice(), &[0xEFu8; 32][..]);
    assert_eq!(recovered.dkg_root.as_slice(), &[0x11u8; 32][..]);
}

#[test]
fn schema_rejects_malformed_version() {
    let mut bad = vec![0xFFu8, 0xFFu8];
    bad.extend_from_slice(&[0x00u8; 100]);
    let result = WitnessStatement::from_statement_bytes(&bad);
    match result {
        Err(SchemaError::UnsupportedVersion(v)) => assert_eq!(v, 0xFFFF),
        other => panic!("expected UnsupportedVersion(0xFFFF), got: {other:?}"),
    }
}

#[test]
fn schema_relation_id_round_trip() {
    for relation in [
        R3Relation::ShareWellFormedness,
        R3Relation::PartialDecryption,
    ] {
        let mut stmt = make_share_wf_statement();
        stmt.relation = relation;
        let bytes = stmt.to_statement_bytes().expect("must serialize");
        let recovered = WitnessStatement::from_statement_bytes(&bytes).expect("must deserialize");
        assert_eq!(
            recovered.relation, relation,
            "relation {:?} should round-trip",
            relation
        );
    }
}

#[test]
fn schema_rejects_truncated_bytes() {
    let stmt = make_share_wf_statement();
    let bytes = stmt.to_statement_bytes().expect("must serialize");
    for cut in [0usize, 1, 2, 4, 12, bytes.len() / 2] {
        let truncated = &bytes[..cut.min(bytes.len())];
        assert!(
            WitnessStatement::from_statement_bytes(truncated).is_err(),
            "truncated to {cut} bytes should be rejected"
        );
    }
}

#[test]
fn schema_empty_session_id_allowed() {
    let mut stmt = make_share_wf_statement();
    stmt.session_id = ProtocolBytes::from(vec![]);
    let bytes = stmt.to_statement_bytes().expect("must serialize");
    let recovered = WitnessStatement::from_statement_bytes(&bytes).expect("must deserialize");
    assert!(recovered.session_id.is_empty());
}
