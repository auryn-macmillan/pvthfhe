//! R8.1 RED: assert fold instances are functions of the actual CCS witness
//! produced by the R3 NIZK layer, not synthetic constants like
//! `vec![1u8; 32]` or `vec![party_id; 32]`.
//!
//! This test verifies that `build_fold_instances` binds each `CcsPShareInstance`
//! to the real NIZK statement and witness, ensuring the Cyclo fold operates over
//! real cryptographic data rather than synthetic placeholders.

use pvthfhe_aggregator::folding::CcsPShareInstance;
use pvthfhe_cli::full_pipeline::{build_fold_instances, Track};
use pvthfhe_fhe::real_nizk::{NizkProof, NizkStatement, NizkWitness};

fn make_statement(party_id: u16, seed: u8) -> NizkStatement {
    let marker = vec![seed; 16];
    NizkStatement {
        ciphertext_bytes: marker.clone(),
        decrypt_share_bytes: marker,
        pvss_commitment: [seed; 32],
        params: (65_537, 8192, 16),
        session_id: format!("test-session-{seed}"),
        participant_id: party_id,
        epoch: 0,
    }
}

fn make_witness(party_id: u16, seed: u8) -> NizkWitness {
    let mut poly = vec![0_i64; 8_192];
    poly[0] = i64::from(seed);
    poly[1] = i64::from(party_id);
    NizkWitness {
        secret_share: u64::from(seed) * u64::from(party_id),
        secret_share_poly: poly,
        error: vec![i64::from(seed); 4],
        randomness: vec![seed; 32],
    }
}

/// Dummy NIZK proof for tests that call `build_fold_instances` without going
/// through the full pipeline (no real `RealNizkAdapter::prove` step).
fn dummy_proof() -> NizkProof {
    NizkProof {
        backend_id: "test-dummy".into(),
        proof_bytes: vec![0u8; 64],
    }
}

/// Returns false when instance fields match the old synthetic patterns:
/// - ajtai_commitment_bytes == [data_marker; 32]
/// - public_io_bytes == [pid as u8; 32]
/// - ccs_witness_bytes == [0u8; 32]
fn is_derived_from_data(instance: &CcsPShareInstance, expected_pid: u16, data_marker: u8) -> bool {
    let pid = instance.participant_id;
    let ajtai = instance.ajtai_commitment_bytes.as_slice();
    let pio = instance.public_io_bytes.as_slice();
    let wit = instance.ccs_witness_bytes.expose().to_vec();

    let looks_synthetic = pid == expected_pid
        && ajtai.len() == 32
        && ajtai.iter().all(|&b| b == data_marker)
        && pio.len() == 32
        && pio.iter().all(|&b| b == pid as u8)
        && wit.len() == 32
        && wit.iter().all(|&b| b == 0);

    !looks_synthetic
}

#[test]
fn instances_vary_with_witness_data() {
    let stmt_a = make_statement(1, 0xAB);
    let wit_a = make_witness(1, 0xAB);
    let stmt_b = make_statement(1, 0xCD);
    let wit_b = make_witness(1, 0xCD);

    let nizk_a = vec![(1u32, &stmt_a, &wit_a)];
    let nizk_b = vec![(1u32, &stmt_b, &wit_b)];

    let proof = dummy_proof();
    let instances_a = build_fold_instances(&nizk_a, &[proof.clone()], [0u8; 32], 0, Track::A)
        .expect("build_fold_instances");
    let instances_b = build_fold_instances(&nizk_b, &[proof], [0u8; 32], 0, Track::A)
        .expect("build_fold_instances");

    assert_eq!(instances_a.len(), 1);
    assert_eq!(instances_b.len(), 1);

    let ia = &instances_a[0];
    let ib = &instances_b[0];

    assert!(
        is_derived_from_data(ia, 1, 0xAB),
        "instance for party 1 seed A should be derived from witness data, not synthetic"
    );
    assert!(
        is_derived_from_data(ib, 1, 0xCD),
        "instance for party 1 seed B should be derived from witness data, not synthetic"
    );

    assert_ne!(
        ia.ajtai_commitment_bytes.as_slice(),
        ib.ajtai_commitment_bytes.as_slice(),
        "ajtai_commitment_bytes must differ for different witnesses"
    );

    assert_ne!(
        ia.public_io_bytes.as_slice(),
        ib.public_io_bytes.as_slice(),
        "public_io_bytes must differ for different statements"
    );

    assert_ne!(
        ia.ccs_witness_bytes.expose(),
        ib.ccs_witness_bytes.expose(),
        "ccs_witness_bytes must differ for different witnesses"
    );
}

#[test]
fn instances_differ_across_parties() {
    let stmt_p1 = make_statement(1, 0x01);
    let wit_p1 = make_witness(1, 0x01);
    let stmt_p2 = make_statement(2, 0x01);
    let wit_p2 = make_witness(2, 0x01);

    let nizk = vec![(1u32, &stmt_p1, &wit_p1), (2u32, &stmt_p2, &wit_p2)];

    let proof = dummy_proof();
    let instances = build_fold_instances(&nizk, &[proof.clone(), proof], [0u8; 32], 0, Track::A)
        .expect("build_fold_instances");

    assert_eq!(instances.len(), 2);
    let i1 = &instances[0];
    let i2 = &instances[1];

    assert_eq!(i1.participant_id, 1);
    assert_eq!(i2.participant_id, 2);

    assert!(
        is_derived_from_data(i1, 1, 0x01),
        "fold instance for party 1 must be derived from its witness, not synthetic"
    );
    assert!(
        is_derived_from_data(i2, 2, 0x01),
        "fold instance for party 2 must be derived from its witness, not synthetic"
    );

    assert_ne!(
        i1.ajtai_commitment_bytes.as_slice(),
        i2.ajtai_commitment_bytes.as_slice(),
        "different parties must have different ajtai commitments"
    );
    assert_ne!(
        i1.public_io_bytes.as_slice(),
        i2.public_io_bytes.as_slice(),
        "different parties must have different public_io_bytes"
    );
    assert_ne!(
        i1.ccs_witness_bytes.expose(),
        i2.ccs_witness_bytes.expose(),
        "different parties must have different ccs_witness_bytes"
    );
}

/// Calling `build_fold_instances` twice with identical inputs must produce
/// bit-for-bit identical outputs, proving the instance is a deterministic
/// function of the NIZK data.
#[test]
fn instances_are_deterministic() {
    let stmt = make_statement(1, 0x42);
    let wit = make_witness(1, 0x42);

    let nizk_a = vec![(1u32, &stmt, &wit)];
    let nizk_b = vec![(1u32, &stmt, &wit)];

    let proof = dummy_proof();
    let instances_a = build_fold_instances(&nizk_a, &[proof.clone()], [0xAA; 32], 99, Track::A)
        .expect("first build");
    let instances_b =
        build_fold_instances(&nizk_b, &[proof], [0xAA; 32], 99, Track::A).expect("second build");

    assert_eq!(instances_a.len(), instances_b.len());
    assert_eq!(instances_a.len(), 1);

    let ia = &instances_a[0];
    let ib = &instances_b[0];

    assert_eq!(
        ia.participant_id, ib.participant_id,
        "participant_id must be deterministic"
    );
    assert_eq!(
        ia.ajtai_commitment_bytes.as_slice(),
        ib.ajtai_commitment_bytes.as_slice(),
        "ajtai_commitment_bytes must be deterministic"
    );
    assert_eq!(
        ia.public_io_bytes.as_slice(),
        ib.public_io_bytes.as_slice(),
        "public_io_bytes must be deterministic"
    );
    assert_eq!(
        ia.ccs_witness_bytes.expose(),
        ib.ccs_witness_bytes.expose(),
        "ccs_witness_bytes must be deterministic"
    );
    assert_eq!(
        ia.sha256_binding_bytes.as_slice(),
        ib.sha256_binding_bytes.as_slice(),
        "sha256_binding_bytes must be deterministic"
    );
}

/// Verifies that `ccs_witness_bytes` contains actual polynomial coefficients
/// from the NIZK witness, not synthetic placeholder bytes.
///
/// `serialize_nizk_witness` takes the first 256 coefficients of `secret_share_poly`
/// and converts each to u64 LE bytes (total 2048 bytes). This test constructs
/// a witness with poly[0] = seed, poly[1] = party_id, and checks the bytes.
#[test]
fn witness_bytes_contain_poly_coefficients() {
    let seed: u8 = 0x7B;
    let party_id: u16 = 5;
    let stmt = make_statement(party_id, seed);
    let wit = make_witness(party_id, seed);

    let nizk = vec![(u32::from(party_id), &stmt, &wit)];
    let proof = dummy_proof();
    let instances = build_fold_instances(&nizk, &[proof], [0u8; 32], 0, Track::A)
        .expect("build_fold_instances");

    assert_eq!(instances.len(), 1);
    let inst = &instances[0];

    let witness_bytes = inst.ccs_witness_bytes.expose();

    assert!(
        !witness_bytes.is_empty(),
        "ccs_witness_bytes must not be empty"
    );
    assert!(
        witness_bytes.iter().any(|&b| b != 0),
        "ccs_witness_bytes must contain non-zero data (found all zeros)"
    );

    assert!(
        witness_bytes.len() >= 2048,
        "ccs_witness_bytes length {} should be >= 2048 (256 coeffs * 8 bytes)",
        witness_bytes.len()
    );

    let coeff0 = u64::from_le_bytes(witness_bytes[0..8].try_into().unwrap());
    assert_eq!(
        coeff0,
        u64::from(seed),
        "coefficient 0 in witness bytes should be seed value {seed}"
    );

    let coeff1 = u64::from_le_bytes(witness_bytes[8..16].try_into().unwrap());
    assert_eq!(
        coeff1,
        u64::from(party_id),
        "coefficient 1 in witness bytes should be party_id value {party_id}"
    );

    for i in 2..256 {
        let start = i * 8;
        let end = start + 8;
        let coeff = u64::from_le_bytes(witness_bytes[start..end].try_into().unwrap());
        assert_eq!(
            coeff, 0,
            "coefficient {i} in witness bytes should be zero, got {coeff}"
        );
    }
}

/// Verifies that `sha256_binding_bytes` changes when any constituent field changes,
/// proving it is a true binding over all instance data, not a constant.
#[test]
fn binding_is_function_of_all_fields() {
    let stmt = make_statement(1, 0x10);
    let wit = make_witness(1, 0x10);

    let nizk_base = vec![(1u32, &stmt, &wit)];
    let proof = dummy_proof();
    let instances_base =
        build_fold_instances(&nizk_base, &[proof.clone()], [0x00; 32], 0, Track::A)
            .expect("build_fold_instances base");
    let binding_base = instances_base[0].sha256_binding_bytes.as_slice().to_vec();

    let instances_ct = build_fold_instances(&nizk_base, &[proof.clone()], [0xFF; 32], 0, Track::A)
        .expect("build_fold_instances ct");
    assert_ne!(
        binding_base,
        instances_ct[0].sha256_binding_bytes.as_slice(),
        "sha256_binding must differ for different ct_hash"
    );

    let instances_seed =
        build_fold_instances(&nizk_base, &[proof.clone()], [0x00; 32], 1, Track::A)
            .expect("build_fold_instances seed");
    assert_ne!(
        binding_base,
        instances_seed[0].sha256_binding_bytes.as_slice(),
        "sha256_binding must differ for different seed"
    );

    let wit2 = make_witness(1, 0x20);
    let nizk_wit2 = vec![(1u32, &stmt, &wit2)];
    let instances_wit = build_fold_instances(&nizk_wit2, &[proof.clone()], [0x00; 32], 0, Track::A)
        .expect("build_fold_instances wit2");
    assert_ne!(
        binding_base,
        instances_wit[0].sha256_binding_bytes.as_slice(),
        "sha256_binding must differ for different witness"
    );

    let stmt2 = make_statement(1, 0x30);
    let nizk_stmt2 = vec![(1u32, &stmt2, &wit)];
    let instances_stmt = build_fold_instances(&nizk_stmt2, &[proof], [0x00; 32], 0, Track::A)
        .expect("build_fold_instances stmt2");
    assert_ne!(
        binding_base,
        instances_stmt[0].sha256_binding_bytes.as_slice(),
        "sha256_binding must differ for different statement"
    );
}

/// Verifies that the source code does not contain any of the old synthetic patterns
/// that were used before R8.1: `vec![1u8; 32]`, `vec![party_id; 32]`,
/// `vec![participant_id as u8; 32]`, and `vec![0u8; 32]`.
///
/// Doc comments acknowledging the old patterns are excluded (line 307 contains a
/// reference in a `///` doc comment, which is fine).
fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with("/// ")
                && !trimmed.starts_with("///")
                && !trimmed.starts_with("// ")
                && !trimmed.starts_with("//! ")
                && !line.starts_with("//")
                && !line.starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn synthetic_patterns_not_present_in_pipeline_source() {
    let source = include_str!("../src/full_pipeline.rs");
    let code_only = source_without_comments(source);

    assert!(
        !code_only.contains("vec![1u8; 32]"),
        "synthetic ajtai pattern 'vec![1u8; 32]' (F56) must be absent from full_pipeline.rs"
    );
    assert!(
        !code_only.contains("vec![party_id; 32]"),
        "synthetic public_io pattern 'vec![party_id; 32]' (F56) must be absent from full_pipeline.rs"
    );
    assert!(
        !code_only.contains("vec![participant_id as u8; 32]"),
        "alternate synthetic pattern 'vec![participant_id as u8; 32]' must be absent"
    );
    assert!(
        !code_only.contains("vec![0u8; 32]"),
        "synthetic witness pattern 'vec![0u8; 32]' must be absent from full_pipeline.rs"
    );
}

/// Verifies that `ajtai_commitment_bytes` is derived from the NIZK witness data,
/// not just a copy of `ct_hash` or a constant.
#[test]
fn ajtai_commitment_is_witness_derived() {
    let stmt = make_statement(1, 0x55);
    let wit_a = make_witness(1, 0x55);
    let wit_b = make_witness(1, 0xAA);

    let nizk_a = vec![(1u32, &stmt, &wit_a)];
    let nizk_b = vec![(1u32, &stmt, &wit_b)];

    let ct_hash = [0xDE; 32];
    let proof = dummy_proof();
    let instances_a = build_fold_instances(&nizk_a, &[proof.clone()], ct_hash, 0, Track::A)
        .expect("build_fold_instances a");
    let instances_b = build_fold_instances(&nizk_b, &[proof], ct_hash, 0, Track::A)
        .expect("build_fold_instances b");

    let ia = &instances_a[0];
    let ib = &instances_b[0];

    assert_ne!(
        ia.ajtai_commitment_bytes.as_slice(),
        ib.ajtai_commitment_bytes.as_slice(),
        "ajtai_commitment_bytes must differ when witness differs (statement unchanged)"
    );

    assert_ne!(
        ia.ajtai_commitment_bytes.as_slice(),
        ct_hash.as_slice(),
        "ajtai_commitment_bytes must not be a copy of ct_hash"
    );

    let ajtai_a = ia.ajtai_commitment_bytes.as_slice();
    assert!(
        !ajtai_a.iter().all(|&b| b == ajtai_a[0]),
        "ajtai_commitment_bytes must not be uniform (synthetic pattern)"
    );
}
