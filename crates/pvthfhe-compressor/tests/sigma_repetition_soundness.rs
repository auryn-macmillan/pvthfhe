//! G1.3: RED test — 90-step sigma fold chain with corrupted witness MUST REJECT.
//!
//! Tests the soundness of the 90-step Nova IVC for sigma verification.
//! Each step verifies 1 sigma round (SIGMA_REPETITIONS = 1).
//! With 90 steps, total sigma rounds = 90 (~142 bits soundness).

use ark_bn254::Fr;
use ark_ff::Zero;
use pvthfhe_compressor::nova::{
    encode_triple, set_sigma_data, CycloFoldStepCircuit, ExternalInputs3, NovaCompressor,
    SigmaWitness, SBIND_CYCLO_FOLD,
};

fn build_honest_sigma_witness(i: usize) -> SigmaWitness<Fr> {
    // Build a valid sigma witness where the S-Z equation holds:
    //   c(γ)·z_s(γ) + z_e(γ) == t(γ) + ch·d_i(γ) + Q·r1(γ)
    //
    // Simple satisfying assignment:
    //   c=1, zs=1, ze=0, t=1, di=0, ch=0, r1=0
    // Check: 1*1 + 0 == 1 + 0*0 + Q*0  →  1 == 1 ✓
    //
    // Each witness is slightly varied by `i` to ensure distinct entries.

    let base = (i + 1) as u64; // 1..90

    let n_ntt_coeffs = 8192; // SIGMA_VERIFY_COEFFS
    let z_s_ntt: Vec<Vec<Fr>> = (0..3).map(|_| vec![Fr::from(base); n_ntt_coeffs]).collect();
    let z_e_ntt: Vec<Vec<Fr>> = (0..3).map(|_| vec![Fr::zero(); n_ntt_coeffs]).collect();
    let t_ntt: Vec<Vec<Fr>> = (0..3).map(|_| vec![Fr::from(base); n_ntt_coeffs]).collect();
    let d_i_ntt: Vec<Vec<Fr>> = (0..3).map(|_| vec![Fr::zero(); n_ntt_coeffs]).collect();
    let c_ntt: Vec<Vec<Fr>> = (0..3).map(|_| vec![Fr::from(base); n_ntt_coeffs]).collect();

    // Schwartz-Zippel evaluation data: 3 points × 3 limbs = 9 entries each
    let sz_c_eval = vec![base; 9];
    let sz_zs_eval = vec![1u64; 9]; // z_s(γ) = 1
    let sz_ze_eval = vec![0u64; 9]; // z_e(γ) = 0
    let sz_t_eval = vec![base; 9]; // t(γ) = base = c(γ)
    let sz_di_eval = vec![0u64; 9]; // d_i(γ) = 0
    let sz_r1_eval = vec![0u64; 9]; // r1(γ) = 0

    // Norm data: z_s and z_e in power basis (satisfy norm bounds B_Z_S=131072)
    // Empty vectors → norm check skipped (n_power=0), which is fine.
    let z_s_power: Vec<i64> = vec![];
    let z_e_power: Vec<i64> = vec![];

    SigmaWitness {
        z_s_ntt,
        z_e_ntt,
        t_ntt,
        d_i_ntt,
        c_ntt,
        ch: Fr::zero(), // challenge = 0
        transcript_commitment: [0u8; 32],
        z_s_power,
        z_e_power,
        sz_gamma: [12345 + i as u64, 23456 + i as u64, 34567 + i as u64],
        sz_c_eval,
        sz_zs_eval,
        sz_ze_eval,
        sz_t_eval,
        sz_di_eval,
        sz_r1_eval,
        sz_r2_eval: vec![0u64; 9],
    }
}

fn build_corrupted_sigma_witness(i: usize) -> SigmaWitness<Fr> {
    let mut w = build_honest_sigma_witness(i);
    // Corrupt z_s evaluation — breaks the S-Z equation
    // Honest: c*zs + ze = base*1 + 0 = base = t + ch*di + Q*r1
    // Corrupted: c*zs + ze = base*2 + 0 = 2*base ≠ base
    w.sz_zs_eval[0] = 2;
    w
}

#[test]
fn sigma_repetition_soundness_90_steps_honest_accepts() {
    // Build 90 honest sigma witnesses
    let witnesses: Vec<SigmaWitness<Fr>> = (0..90).map(build_honest_sigma_witness).collect();
    set_sigma_data(witnesses);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 90, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("create compressor with ivc_steps=90");

    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero())).to_vec();
    let steps = vec![ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero()); 90];

    let result = compressor.prove_steps(&acc, &steps);
    assert!(
        result.is_ok(),
        "90-step honest sigma prove must succeed: {result:?}"
    );
}

#[test]
fn sigma_repetition_soundness_one_corrupted_rejects() {
    // Build 90 witnesses, but corrupt witness #45 (one in the middle)
    let mut witnesses: Vec<SigmaWitness<Fr>> = (0..90).map(build_honest_sigma_witness).collect();
    witnesses[45] = build_corrupted_sigma_witness(45);
    set_sigma_data(witnesses);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 90, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("create compressor with ivc_steps=90");

    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero())).to_vec();
    let steps = vec![ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero()); 90];

    let result = compressor.prove_steps(&acc, &steps);
    // The corrupted witness should cause either:
    // - prove_steps failure (constraint violation detected during synthesis), OR
    // - proof verification failure
    // Either outcome is acceptable for the RED test.
    match result {
        Err(e) => {
            // Constraint violation during synthesis — test passes
            eprintln!("corrupted witness correctly rejected during prove: {e:?}");
        }
        Ok(proof) => {
            // Proof was generated (vacuously?); verify it and ensure it FAILS
            let vk = compressor.verifier_key();
            let verify_result = compressor.verify_steps(&vk, &proof, &acc, &steps);
            assert!(
                verify_result.is_err() || verify_result == Ok(false),
                "corrupted sigma witness MUST be rejected, got: {verify_result:?}"
            );
        }
    }
}

#[test]
fn sigma_repetition_soundness_first_corrupted_rejects() {
    // Corrupt the FIRST witness to verify detection early in the chain
    let mut witnesses: Vec<SigmaWitness<Fr>> = (0..90).map(build_honest_sigma_witness).collect();
    witnesses[0] = build_corrupted_sigma_witness(0);
    set_sigma_data(witnesses);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 90, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("create compressor with ivc_steps=90");

    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero())).to_vec();
    let steps = vec![ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero()); 90];

    let result = compressor.prove_steps(&acc, &steps);
    match result {
        Err(e) => {
            eprintln!("first witness corruption correctly rejected during prove: {e:?}");
        }
        Ok(proof) => {
            let vk = compressor.verifier_key();
            let verify_result = compressor.verify_steps(&vk, &proof, &acc, &steps);
            assert!(
                verify_result.is_err() || verify_result == Ok(false),
                "corrupted first sigma witness MUST be rejected, got: {verify_result:?}"
            );
        }
    }
}

#[test]
fn sigma_repetition_soundness_last_corrupted_rejects() {
    // Corrupt the LAST witness to verify detection at end of chain
    let mut witnesses: Vec<SigmaWitness<Fr>> = (0..90).map(build_honest_sigma_witness).collect();
    witnesses[89] = build_corrupted_sigma_witness(89);
    set_sigma_data(witnesses);

    let compressor =
        NovaCompressor::<CycloFoldStepCircuit<Fr>>::new([0u8; 32], 90, [0u8; 32], SBIND_CYCLO_FOLD)
            .expect("create compressor with ivc_steps=90");

    let acc = encode_triple((Fr::zero(), Fr::zero(), Fr::zero())).to_vec();
    let steps = vec![ExternalInputs3(Fr::zero(), Fr::zero(), Fr::zero()); 90];

    let result = compressor.prove_steps(&acc, &steps);
    match result {
        Err(e) => {
            eprintln!("last witness corruption correctly rejected during prove: {e:?}");
        }
        Ok(proof) => {
            let vk = compressor.verifier_key();
            let verify_result = compressor.verify_steps(&vk, &proof, &acc, &steps);
            assert!(
                verify_result.is_err() || verify_result == Ok(false),
                "corrupted last sigma witness MUST be rejected, got: {verify_result:?}"
            );
        }
    }
}
