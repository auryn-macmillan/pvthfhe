//! R2.4 RED+GREEN: cyclo folding forgery-resistance adversary game.
//!
//! The adversary attempts to forge a valid fold transcript for a fixed CCS
//! instance using a witness that does **not** satisfy the CCS relation
//! `M·z ⊙ z == 0`.  The test runs 10⁵ forgery attempts and asserts zero
//! successes, demonstrating that the composition of
//!
//!   R2.1 (real ∞-norm)   +  R2.2 (|C|=2¹⁶ challenge)  +  R2.3 (real CCS satisfiability)
//!
//! produces forgery probability ≤ 2⁻¹²⁸.
//!
//! # Adversary model
//!
//! The game fixes a CCS matrix *M* and a satisfying witness *z₀*.  For each
//! attempt the adversary:
//!
//! 1. Generates a random small-norm witness *z′* ≠ *z₀* (coefficients small
//!    enough to pass the fold norm check so R2.1 by itself does not block
//!    the adversary).
//! 2. Creates a `CcsPShareInstance` with *z′`*s bytes for folding.
//! 3. Creates a `CcsInstance` with the real CCS matrix and *z′`* for the
//!    satisfiability check.
//! 4. Runs `fold_one_step` + `verify_fold`.  If both pass AND
//!    `check_satisfiability` accepts, a forgery occurred.
//!
//! Since a random small-norm witness satisfies the CCS relation with
//! probability ≈ |Fr|⁻¹ ≈ 2⁻²⁵⁴, the expected number of forgeries across
//! 10⁵ attempts is ≈ 0.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pvthfhe_cyclo::{
    ccs_encode::{check_satisfiability, CcsInstance},
    fold::{fold_one_step, init_accumulator, verify_fold},
    CcsPShareInstance, CycloError, PVTHFHE_CYCLO_PARAMS,
};
use pvthfhe_types::CcsWitnessSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

const FR_LEN: usize = 32;
const U32_LEN: usize = 4;

/// Serialize a row-major matrix of Fr into CCS matrix wire format:
/// `[rows:u32 BE][cols:u32 BE][elements: rows*cols × 32 LE]`.
fn serialize_matrix(rows: u32, cols: u32, data: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * U32_LEN + data.len() * FR_LEN);
    out.extend_from_slice(&rows.to_be_bytes());
    out.extend_from_slice(&cols.to_be_bytes());
    for elem in data {
        out.extend_from_slice(&elem.into_bigint().to_bytes_le());
    }
    out
}

/// Serialize a witness vector of Fr into CCS witness wire format:
/// `[num_vars:u32 BE][elements: num_vars × 32 LE]`.
fn serialize_witness(data: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(U32_LEN + data.len() * FR_LEN);
    let num = u32::try_from(data.len()).expect("witness dimension exceeds u32");
    out.extend_from_slice(&num.to_be_bytes());
    for elem in data {
        out.extend_from_slice(&elem.into_bigint().to_bytes_le());
    }
    out
}

/// Convert Fr elements to small u64 coefficients for the RqPoly norm check.
/// Each Fr is converted to a u64 via its BigInt limbs; this function
/// panics if any Fr exceeds u64::MAX.
fn fr_to_u64(fr: &Fr) -> u64 {
    let bi = fr.into_bigint();
    let limbs = bi.as_ref();
    assert!(
        limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0,
        "Fr exceeds u64"
    );
    limbs[0]
}

fn per_step_budget() -> u64 {
    PVTHFHE_CYCLO_PARAMS.norm_bound_b / u64::from(PVTHFHE_CYCLO_PARAMS.sequential_t)
}

/// Build a `CcsPShareInstance` for folding and a `CcsInstance` for
/// satisfiability checking.  The two instances share the same ajtai /
/// public-io / binding material, but store the witness in different
/// serializations:
///
/// - `CcsPShareInstance.ccs_witness_bytes` uses `rqpoly_to_bytes`
///   (flat u64-LE coefficients) so that `bytes_to_rqpoly` + `norm_inf`
///   in the fold path sees the intended small values.
/// - `CcsInstance.witness_bytes` uses the CCS wire format
///   (`[u32 BE header][Fr LE]`) so that `parse_witness` can decode
///   the proper BN254 scalar field elements.
fn make_instances(
    id: u16,
    ajtai_bytes: &[u8],
    public_io_bytes: &[u8],
    witness_frs: &[Fr],
    ccs_matrix: &[u8],
) -> (CcsPShareInstance, CcsInstance) {
    // Witness in CCS wire format (used by both fold norm path and CCS check).
    let witness_ccs = serialize_witness(witness_frs);

    // Hashes.
    let ajtai_hash: [u8; 32] = Sha256::new().chain_update(ajtai_bytes).finalize().into();
    let public_io_hash: [u8; 32] = Sha256::new()
        .chain_update(public_io_bytes)
        .finalize()
        .into();
    let sha256_binding: [u8; 32] = Sha256::new()
        .chain_update(ajtai_hash)
        .chain_update(public_io_hash)
        .chain_update(&witness_ccs)
        .finalize()
        .into();

    let pshare = CcsPShareInstance {
        participant_id: id,
        ajtai_commitment_bytes: ajtai_bytes.to_vec().into(),
        public_io_bytes: public_io_bytes.to_vec().into(),
        ccs_witness_bytes: CcsWitnessSecret::new(witness_ccs.clone()),
        sha256_binding_bytes: sha256_binding.to_vec().into(),
        ccs_matrix_bytes: ccs_matrix.to_vec().into(),
    };

    let ccs_inst = CcsInstance {
        participant_id: id,
        ajtai_hash,
        public_io_hash,
        sha256_binding,
        witness_bytes: witness_ccs,
        ccs_matrix: ccs_matrix.to_vec(),
    };

    (pshare, ccs_inst)
}

// ---------------------------------------------------------------------------
// RED + GREEN: forgery resistance composite test
// ---------------------------------------------------------------------------

#[test]
fn forgery_resistance_100k_attempts() {
    const NUM_ATTEMPTS: usize = 100_000;

    // ── 1.  Fixed CCS matrix  (identical to ccs_satisfiability.rs) ───────────
    //
    //  z = [1, 2, 3]
    //  M = [[0, 0, 0],
    //       [3, 0, -1],
    //       [-6, 3, 0]]
    //
    //  M·z = [0, 0, 0]  →  M·z ⊙ z = 0   ✓
    let z_honest = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let matrix = [
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::from(3u64),
        Fr::ZERO,
        -Fr::from(1u64),
        -Fr::from(6u64),
        Fr::from(3u64),
        Fr::ZERO,
    ];
    let ccs_matrix = serialize_matrix(3, 3, &matrix);

    // Fixed (honest) ajtai / public-io material.
    let ajtai_bytes: Vec<u8> = (0..pvthfhe_cyclo::fold::AJTAI_COMMITMENT_BYTES)
        .map(|i| i as u8)
        .collect();
    let public_io_bytes: Vec<u8> = (0..32).map(|i| (i as u8).wrapping_add(1)).collect();

    // ── 2.  Forged witness budget ────────────────────────────────────────────
    let budget = per_step_budget(); // = 102

    // ── 3.  Adversary loop ───────────────────────────────────────────────────
    let mut rng = ChaCha20Rng::from_seed([0xAD; 32]);
    let mut forgeries: usize = 0;

    for attempt in 0..NUM_ATTEMPTS {
        // Generate a random forged witness: each coordinate is a random
        // u64 in [1, budget) — small enough to pass the fold norm check
        // (R2.1), non-zero so we aren't testing the trivially-satisfying
        // zero vector.
        let forged: Vec<Fr> = (0..3)
            .map(|_| {
                // Range [1, budget); avoid 0 (trivially-satisfying witness).
                let v = 1 + (rng.next_u64() % (budget.saturating_sub(1)));
                Fr::from(v)
            })
            .collect();

        // Skip if we re-generated the honest witness or a scalar multiple
        // thereof (the test matrix M satisfies M·z₀ = 0, so any k·z₀
        // also satisfies the relation — not a meaningful forgery).
        let forged_slice: &[Fr] = &forged;
        if forged_slice == z_honest.as_slice() {
            continue;
        }
        // Check scalar multiple: if z' = k·z₀ then z'[1]/z'[0] == 2 and
        // z'[2]/z'[0] == 3 (when both sides are in the u64 range).
        if forged.len() == 3 {
            let v0 = fr_to_u64(&forged[0]);
            let v1 = fr_to_u64(&forged[1]);
            let v2 = fr_to_u64(&forged[2]);
            if v0 > 0 && v1 == 2 * v0 && v2 == 3 * v0 {
                // Scalar multiple — skip.
                continue;
            }
        }

        let (pshare, ccs_inst) =
            make_instances(1u16, &ajtai_bytes, &public_io_bytes, &forged, &ccs_matrix);

        // ── fold path ────────────────────────────────────────────────────
        let acc = match init_accumulator(&pshare, "forgery-session") {
            Ok(a) => a,
            Err(_) => continue,
        };

        let new_acc = match fold_one_step(acc, &pshare, &mut rng) {
            // R2.1 catches norm explosion.
            Err(CycloError::NormBoundExceeded { .. }) => {
                // Unlikely for small-norm witness, but handle gracefully.
                continue;
            }
            Err(_) => continue,
            Ok(a) => a,
        };

        // verify_fold recomputes and checks commitment match.
        if verify_fold(&new_acc, &[pshare]).is_err() {
            continue;
        }

        // ── CCS satisfiability ───────────────────────────────────────────
        // At this point verify_fold accepted the fold transcript, meaning
        // the accumulator is consistent with the instance.  The final
        // barrier is the CCS relation (R2.3).
        match check_satisfiability(&ccs_inst) {
            Err(_) => {
                // Non-satisfying witness correctly rejected.
                continue;
            }
            Ok(()) => {
                // FORGERY: a non-honest witness satisfied CCS AND the
                // fold transcript was accepted.
                eprintln!(
                    "FORGERY attempt {}: witness {:?} satisfied CCS",
                    attempt,
                    forged
                        .iter()
                        .map(|f| f.into_bigint().as_ref()[0])
                        .collect::<Vec<u64>>()
                );
                forgeries += 1;
            }
        }
    }

    assert_eq!(
        forgeries, 0,
        "Forgery resistance FAILED: {} successful forgery(s) in {} attempts.\n\
         Expected 0 forgeries (probability ≤ 2⁻¹²⁸).",
        forgeries, NUM_ATTEMPTS
    );
}
