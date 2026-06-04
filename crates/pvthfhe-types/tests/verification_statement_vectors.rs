use pvthfhe_types::verification_statement::{
    field_elements_to_decimal_strings, field_elements_to_hex_strings, VerificationStatementV1,
    GOLDEN_STATEMENT_HASH_DECIMAL, GOLDEN_STATEMENT_HASH_HEX, POSEIDON_PREIMAGE_LEN,
};

fn bytes(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn golden_statement() -> VerificationStatementV1 {
    VerificationStatementV1 {
        protocol_version: 1,
        context_id: bytes(0x10),
        dkg_root: bytes(0x20),
        epoch: 42,
        participant_set_hash: bytes(0x30),
        aggregate_pk_hash: bytes(0x40),
        ciphertext_hash: bytes(0x50),
        plaintext_hash: bytes(0x60),
        d_commitment: bytes(0x70),
        c5_proof_root: bytes(0x80),
        c6_proof_set_root: bytes(0x90),
        cyclo_accumulator_root: bytes(0xa0),
        ivc_vk_hash: bytes(0xb0),
        ivc_pp_hash: bytes(0xc0),
        ivc_proof_hash: bytes(0xd0),
        z0_commitment: bytes(0xe0),
        zi_commitment: bytes(0xf0),
        ivc_steps: 7,
        bootstrap_result_hash: bytes(0x08),
        share_verification_hash: bytes(0x11),
        decrypt_nizk_hash: bytes(0x12),
        dkg_transcript_hash: bytes(0x13),
        nova_final_state_commitment: bytes(0x14),
    }
}

#[test]
fn verification_statement_vectors() {
    let statement = golden_statement();
    let canonical = statement
        .encode_canonical()
        .expect("canonical encoding succeeds");
    let decoded = VerificationStatementV1::decode_canonical(&canonical).expect("round-trip parses");
    assert_eq!(decoded, statement);

    let preimage = statement.poseidon_preimage();
    assert_eq!(preimage.len(), POSEIDON_PREIMAGE_LEN);

    let hash = statement.statement_hash().expect("Poseidon hash succeeds");
    assert_eq!(hash.decimal, GOLDEN_STATEMENT_HASH_DECIMAL);
    assert_eq!(hash.hex, GOLDEN_STATEMENT_HASH_HEX);

    let fixture = VerificationStatementV1::golden_fixture().expect("fixture generation succeeds");
    assert_eq!(fixture.canonical_bytes_hex, hex_encode(&canonical));
    assert_eq!(
        fixture.poseidon_preimage_decimal,
        field_elements_to_decimal_strings(&preimage)
    );
    assert_eq!(
        fixture.poseidon_preimage_hex,
        field_elements_to_hex_strings(&preimage)
    );
    assert_eq!(
        fixture.statement_hash_decimal,
        GOLDEN_STATEMENT_HASH_DECIMAL
    );
    assert_eq!(fixture.statement_hash_hex, GOLDEN_STATEMENT_HASH_HEX);

    let committed_fixture = include_str!("fixtures/verification_statement_v1_golden.json");
    assert!(committed_fixture.contains(&format!(
        "\"canonical_bytes_hex\": \"{}\"",
        fixture.canonical_bytes_hex
    )));
    assert!(committed_fixture.contains(GOLDEN_STATEMENT_HASH_DECIMAL));
    assert!(committed_fixture.contains(GOLDEN_STATEMENT_HASH_HEX));
}

#[test]
fn verification_statement_rejects_noncanonical_tlv() {
    let statement = golden_statement();
    let canonical = statement
        .encode_canonical()
        .expect("canonical encoding succeeds");

    let mut wrong_count = canonical.clone();
    let field_count_offset = 4 + b"pvthfhe-verification-stmt-v1".len() + 4;
    wrong_count[field_count_offset + 3] = 18;
    assert!(VerificationStatementV1::decode_canonical(&wrong_count).is_err());

    let mut wrong_id = canonical.clone();
    let first_id_offset = field_count_offset + 4;
    wrong_id[first_id_offset + 1] = 2;
    assert!(VerificationStatementV1::decode_canonical(&wrong_id).is_err());

    let mut wrong_len = canonical.clone();
    let first_len_offset = first_id_offset + 2;
    wrong_len[first_len_offset + 3] = 5;
    assert!(VerificationStatementV1::decode_canonical(&wrong_len).is_err());

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(VerificationStatementV1::decode_canonical(&trailing).is_err());

    let omitted = &canonical[..canonical.len() - (2 + 4 + 32)];
    assert!(VerificationStatementV1::decode_canonical(omitted).is_err());
}

#[test]
fn verification_statement_negative_hash_variants_differ() {
    let statement = golden_statement();
    let honest = statement
        .statement_hash()
        .expect("Poseidon hash succeeds")
        .decimal;

    let mut swapped_fields = statement.clone();
    core::mem::swap(&mut swapped_fields.context_id, &mut swapped_fields.dkg_root);
    assert_ne!(swapped_fields.statement_hash().unwrap().decimal, honest);

    let swapped_limbs = statement
        .statement_hash_with_swapped_hi_lo_limbs()
        .unwrap()
        .decimal;
    assert_ne!(swapped_limbs, honest);

    let little_endian = statement
        .statement_hash_with_little_endian_limbs()
        .unwrap()
        .decimal;
    assert_ne!(little_endian, honest);

    let mod_p_reduced = statement
        .statement_hash_with_mod_p_reduction()
        .unwrap()
        .decimal;
    assert_ne!(mod_p_reduced, honest);
}
