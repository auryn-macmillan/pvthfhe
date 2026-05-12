use crate::ccs_encode::CcsRqInstance;
use crate::ring::{
    ntt_mul, ring_add_poly, rqpoly_to_bytes, RqPoly, PHI_COMMIT, Q_COMMIT,
};
use crate::CycloError;
use sha2::{Digest, Sha256};

fn zero_poly() -> RqPoly {
    RqPoly::zero()
}

fn one_poly() -> RqPoly {
    let mut coeffs = vec![0u64; PHI_COMMIT];
    coeffs[0] = 1;
    RqPoly(coeffs)
}

fn neg_poly(p: &RqPoly) -> RqPoly {
    RqPoly(
        p.0.iter()
            .map(|&c| if c == 0 { 0 } else { Q_COMMIT - c })
            .collect(),
    )
}

fn serialize_matrix_rq(rows: u32, cols: u32, data: &[RqPoly]) -> Vec<u8> {
    let entry_bytes = PHI_COMMIT * 8;
    let mut out = Vec::with_capacity(8 + data.len() * entry_bytes);
    out.extend_from_slice(&rows.to_be_bytes());
    out.extend_from_slice(&cols.to_be_bytes());
    for poly in data {
        out.extend_from_slice(&rqpoly_to_bytes(poly));
    }
    out
}

/// Encodes the RLWE decryption-share relation `d_i = c · s_i + e_i` as a `CcsRqInstance`.
///
/// Uses the 3-matrix CCS encoding (wire version 2):
///   `(M₁·z) ⊙ (M₂·z) == M₃·z`
///
/// **Witness**: `z = [c, s_i, e_i, d_i, one]` (5 elements, no separate `cs`).
///
/// **Row 0** encodes `c · s_i == d_i - e_i`:
///   M₁[row 0] = [1, 0, 0, 0, 0]  → selects c
///   M₂[row 0] = [0, 1, 0, 0, 0]  → selects s_i
///   M₃[row 0] = [0, 0, -1, 1, 0] → selects d_i - e_i
///
/// **Row 1** (sanity check) ensures the constant `one` is idempotent:
///   M₁[row 1] = [0, 0, 0, 0, 1]  → selects one
///   M₂[row 1] = [0, 0, 0, 0, 1]  → selects one
///   M₃[row 1] = [0, 0, 0, 0, 1]  → selects one
///
/// `party_id` is metadata (not used in the constraint) — incorporated into the
/// `ajtai_hash` and `public_io_hash`.
pub fn encode_rlwe_share_relation(
    ciphertext: &RqPoly,
    secret_key: &RqPoly,
    error_poly: &RqPoly,
    party_id: u16,
) -> Result<CcsRqInstance, CycloError> {
    let cs = ntt_mul(ciphertext, secret_key)?;
    let decryption_share = ring_add_poly(&cs, error_poly);

    let witness = vec![
        ciphertext.clone(),
        secret_key.clone(),
        error_poly.clone(),
        decryption_share,
        one_poly(),
    ];

    let zero = zero_poly();
    let one = one_poly();
    let neg_one = neg_poly(&one);

    // Matrix M₁ (2 rows × 5 cols)
    // Row 0: [1, 0, 0, 0, 0] → selects c
    // Row 1: [0, 0, 0, 0, 1] → selects one
    let m1 = vec![
        one.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone(),
        zero.clone(), zero.clone(), zero.clone(), zero.clone(), one.clone(),
    ];

    // Matrix M₂ (2 rows × 5 cols)
    // Row 0: [0, 1, 0, 0, 0] → selects s_i
    // Row 1: [0, 0, 0, 0, 1] → selects one
    let m2 = vec![
        zero.clone(), one.clone(), zero.clone(), zero.clone(), zero.clone(),
        zero.clone(), zero.clone(), zero.clone(), zero.clone(), one.clone(),
    ];

    // Matrix M₃ (2 rows × 5 cols)
    // Row 0: [0, 0, -1, 1, 0] → selects d_i - e_i
    // Row 1: [0, 0, 0, 0, 1]  → selects one
    let m3 = vec![
        zero.clone(), zero.clone(), neg_one,     one.clone(), zero.clone(),
        zero.clone(), zero.clone(), zero.clone(), zero.clone(), one.clone(),
    ];

    let m1_bytes = serialize_matrix_rq(2, 5, &m1);
    let m2_bytes = serialize_matrix_rq(2, 5, &m2);
    let m3_bytes = serialize_matrix_rq(2, 5, &m3);

    let party_bytes: Vec<u8> = party_id.to_be_bytes().iter().cycle().take(32).copied().collect();
    let ajtai_hash: [u8; 32] = Sha256::new()
        .chain_update(&party_bytes)
        .chain_update(b"rlwe_ajtai")
        .finalize()
        .into();
    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(&party_bytes)
        .chain_update(b"rlwe_public_io")
        .finalize()
        .into();

    Ok(CcsRqInstance {
        ajtai_hash,
        public_io_hash,
        witness,
        matrix_data: Vec::new(),
        m1_bytes,
        m2_bytes,
        m3_bytes,
    })
}
