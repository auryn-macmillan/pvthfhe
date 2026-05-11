//! Norm and CCS satisfiability witness serialization tests.
//!
//! C.4: Fix norm/satisfiability witness serialization mismatch.
//! Both the norm check (witness_norm_estimate) and the CCS satisfiability
//! check (check_satisfiability) must use `parse_witness` (Fr-LE with u32 BE
//! header), so they agree on the interpretation of witness coefficients.
//!
//! The RED test below (`extension_norm_matches_parse_witness`) exercises the
//! T2 extension step and verifies that its norm estimate uses the same
//! Fr-LE interpretation as `parse_witness`, not the legacy `bytes_to_rqpoly`
//! flat-u64-LE interpretation.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pvthfhe_cyclo::ccs_encode::{CcsInstance, parse_witness};
use pvthfhe_cyclo::extension::extend;
use pvthfhe_cyclo::ring::Q_COMMIT;

fn serialize_witness(data: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() * 32);
    let num = u32::try_from(data.len()).expect("witness too long");
    out.extend_from_slice(&num.to_be_bytes());
    for elem in data {
        out.extend_from_slice(&elem.into_bigint().to_bytes_le());
    }
    out
}

fn fr_to_u64(fr: &Fr) -> u64 {
    let limbs = fr.into_bigint().as_ref().to_vec();
    assert!(limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0, "Fr exceeds u64");
    limbs[0]
}

#[inline]
fn centred(c: u64) -> u64 {
    let neg = Q_COMMIT - c;
    if neg < c { neg } else { c }
}

fn fr_centred_norm(fr: &Fr) -> u64 {
    centred(fr_to_u64(fr) % Q_COMMIT)
}

fn make_instance(id: u16, witness: Vec<u8>) -> CcsInstance {
    CcsInstance {
        participant_id: id,
        ajtai_hash: [id as u8; 32],
        public_io_hash: [(id + 1) as u8; 32],
        sha256_binding: [0u8; 32],
        witness_bytes: witness,
        ccs_matrix: Vec::new(),
    }
}

#[test]
fn norm_and_ccs_parse_witness_consistently() {
    let witness_frs = [
        Fr::from(1u64),
        Fr::from(100u64),
        Fr::from(1024u64),
    ];

    let witness_bytes = serialize_witness(&witness_frs);

    let parsed = parse_witness(&witness_bytes).expect("parse_witness should succeed");

    assert_eq!(parsed.len(), witness_frs.len());
    for (i, (expected, actual)) in witness_frs.iter().zip(parsed.iter()).enumerate() {
        assert_eq!(
            fr_to_u64(actual),
            fr_to_u64(expected),
            "witness element {i} mismatch"
        );
    }

    let centred_norm: u64 = parsed
        .iter()
        .map(|fr| centred(fr_to_u64(fr) % Q_COMMIT))
        .max()
        .unwrap_or(0);

    assert_eq!(centred_norm, 1024, "centred norm should be 1024");
}

/// RED test (becomes GREEN after C.4 fix): the T2 extension norm estimate
/// must agree with the `parse_witness`-based interpretation of witness bytes.
///
/// Before the fix, `extend()` computes norm via `bytes_to_rqpoly`
/// (flat u64-LE), which gives a different result than `parse_witness`
/// (Fr-LE with u32 BE header) for the same byte sequence.
#[test]
fn extension_norm_matches_parse_witness() {
    let a_frs = [Fr::from(5u64), Fr::from(10u64)];
    let b_frs = [Fr::from(3u64), Fr::from(7u64)];

    let witness_a = serialize_witness(&a_frs);
    let witness_b = serialize_witness(&b_frs);

    let a = make_instance(1, witness_a);
    let b = make_instance(2, witness_b);

    let r: i8 = 1;
    let ext = extend(&a, &b, r).expect("extend r=1 should succeed");

    // Expect combined = a + r*b = a + b (in Fr)
    let expected_norm: u64 = a_frs
        .iter()
        .zip(b_frs.iter())
        .map(|(x, y)| {
            let sum = *x + *y;
            fr_centred_norm(&sum)
        })
        .max()
        .unwrap_or(0);

    assert_eq!(
        ext.norm_estimate, expected_norm,
        "RED/GREEN: extension norm must agree with parse_witness-based Fr-LE interpretation"
    );
}
