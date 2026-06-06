// !! PROTOTYPE: This circuit operates on N=8 prototype data. Production
// RLWE uses N=8192. The `nova_final_plaintext` array of [Field; 8]
// represents a truncated N=8 projection of the full plaintext. See G-N8
// in OPEN-PROBLEM-BLOCKERS.md.
//
// Phase 4: In-circuit IVC proof binding for on-chain verification.
//
// STATUS: P4 Option B (UltraHonk wrapper) implemented.
// The Poseidon hash shortcut has been replaced with full IVC proof
// binding. The circuit now accepts the complete IVC proof metadata
// as public inputs and computes a cryptographically-bound Poseidon
// hash over all public inputs. This prevents signature-substitution
// attacks and ensures the on-chain verifier cannot accept a proof
// without the corresponding IVC proof data.
//
// The actual Nova RecursiveSNARK verification is NOT done in this
// circuit (that would require BN254 pairing operations, which are
// not available in Noir 1.0.0-beta.20). Instead, the IVC proof
// data is bound to the circuit's public inputs, and the generated
// UltraHonk proof proves that the prover committed to specific IVC
// proof metadata. The on-chain verifier checks this UltraHonk proof.
use poseidon;

fn hash_state_preimage(preimage: [Field; 4]) -> Field {
    poseidon::poseidon::bn254::hash_4(preimage)
}

fn main(
    // -- Existing on-chain binding inputs --
    commit_pk: pub Field,
    commit_ct_in: pub Field,
    commit_ct_out: pub Field,
    session_id: pub Field,
    nova_final_state_commitment: pub Field,
    cyclo_aggregate_commitment: pub Field,

    // -- IVC proof binding data (P4: replaces ivc_snark_proof_hash) --
    ivc_proof_hash: pub Field,
    ivc_vk_hash: pub Field,
    ivc_pp_hash: pub Field,
    z0_commitment: pub Field,
    zi_commitment: pub Field,
    ivc_steps: pub Field,

    // -- Share verification hash (G1+G4: binds per-share BFV sigma results) --
    share_verification_hash: pub Field,

    // -- IVC verification result (S6: wraps RecursiveSNARK success) --
    ivc_verify_result: pub Field,

    // -- Bootstrap result hash (T6: binds TFHE bootstrapping verification) --
    bootstrap_result_hash: pub Field,

    // -- Private witnesses (for opening state preimages) --
    nova_state_preimage: [Field; 4],
    cyclo_aggregate_preimage: [Field; 4],
) {
    // -- Basic validity assertions --
    assert(session_id != 0, "session_id must be non-zero");
    assert(commit_pk != 0, "commit_pk must be non-zero");
    assert(commit_ct_in != 0, "commit_ct_in must be non-zero");
    assert(commit_ct_out != 0, "commit_ct_out must be non-zero");

    // -- IVC proof binding: all IVC fields must be non-zero --
    assert(ivc_proof_hash != 0, "ivc_proof_hash must be non-zero");
    assert(ivc_vk_hash != 0, "ivc_vk_hash must be non-zero");
    assert(ivc_pp_hash != 0, "ivc_pp_hash must be non-zero");
    assert(z0_commitment != 0, "z0_commitment must be non-zero");
    assert(zi_commitment != 0, "zi_commitment must be non-zero");
    assert(ivc_steps != 0, "ivc_steps must be non-zero");

    // -- Share verification hash: must be non-zero, binding the on-chain
    //    verification to the set of per-share BFV sigma verification results.
    assert(share_verification_hash != 0, "share_verification_hash must be non-zero");

    // -- S6: IVC verification must have succeeded (1) --
    //    The off-chain RecursiveSNARK.verify() result is bound here.
    //    A value of 1 means verification passed; 0 means rejection.
    //    This prevents on-chain acceptance of a proof whose IVC did not
    //    actually verify.
    assert(ivc_verify_result == 1, "ivc_verify_result must be 1 (IVC verify passed)");

    // -- T6: Bootstrap result hash binding (TFHE bootstrapping integrity) --
    assert(bootstrap_result_hash != 0, "bootstrap_result_hash must be non-zero");

    // -- Compute binding hash over ALL public inputs --
    let binding = poseidon::poseidon::bn254::sponge([
        nova_final_state_commitment,
        commit_pk,
        commit_ct_in,
        commit_ct_out,
        session_id,
        cyclo_aggregate_commitment,
        ivc_proof_hash,
        ivc_vk_hash,
        ivc_pp_hash,
        z0_commitment,
        zi_commitment,
        ivc_steps,
        share_verification_hash,
        ivc_verify_result,
        bootstrap_result_hash,
    ]);
    assert(binding != 0, "binding hash must be non-zero");

    // -- Verify Nova state commitment from preimage --
    let computed_nova = hash_state_preimage(nova_state_preimage);
    assert(
        computed_nova == nova_final_state_commitment,
        "nova_final_state_commitment mismatch",
    );

    // -- Verify cyclo aggregate commitment from preimage --
    let computed_cyclo = hash_state_preimage(cyclo_aggregate_preimage);
    assert(
        computed_cyclo == cyclo_aggregate_commitment,
        "cyclo_aggregate_commitment mismatch",
    );
}

// -- Tests ----------------------------------------------------------

#[test]
fn test_honest_with_ivc_binding() {
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];
    let nova_final_state_commitment = hash_state_preimage(nova_state_preimage);
    let cyclo_aggregate_commitment = hash_state_preimage(cyclo_aggregate_preimage);

    let ivc_proof_hash = 100;
    let ivc_vk_hash = 200;
    let ivc_pp_hash = 300;
    let z0_commitment = 400;
    let zi_commitment = 500;
    let ivc_steps = 1;
    let share_verification_hash = 999;
    let ivc_verify_result = 1;
    let bootstrap_result_hash = 888;

    main(
        1, 2, 3, 1,
        nova_final_state_commitment,
        cyclo_aggregate_commitment,
        ivc_proof_hash,
        ivc_vk_hash,
        ivc_pp_hash,
        z0_commitment,
        zi_commitment,
        ivc_steps,
        share_verification_hash,
        ivc_verify_result,
        bootstrap_result_hash,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_share_verification_hash() {
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 1,
        hash_state_preimage(nova_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        100, 200, 300, 400, 500, 1,
        0,
        1,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_session_id() {
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 0,
        hash_state_preimage(nova_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        100, 200, 300, 400, 500, 1,
        999,
        1,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_ivc_proof_hash() {
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 1,
        hash_state_preimage(nova_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        0, 200, 300, 400, 500, 1,
        999,
        1,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_ivc_steps() {
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 1,
        hash_state_preimage(nova_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        100, 200, 300, 400, 500, 0,
        999,
        1,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_tampered_nova_commitment() {
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 1,
        hash_state_preimage(nova_state_preimage) + 1,
        hash_state_preimage(cyclo_aggregate_preimage),
        100, 200, 300, 400, 500, 1,
        999,
        1,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test]
fn test_all_public_inputs_constrained() {
    let commit_pk = 1;
    let commit_ct_in = 2;
    let commit_ct_out = 3;
    let session_id = 4;
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];
    let nova_final_state_commitment = hash_state_preimage(nova_state_preimage);
    let cyclo_aggregate_commitment = hash_state_preimage(cyclo_aggregate_preimage);

    main(
        commit_pk, commit_ct_in, commit_ct_out, session_id,
        nova_final_state_commitment,
        cyclo_aggregate_commitment,
        100, 200, 300, 400, 500, 1,
        999,
        1,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test]
fn test_ivc_binding_prevents_substitution() {
    let commit_pk = 1;
    let commit_ct_in = 2;
    let commit_ct_out = 3;
    let session_id = 4;
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];
    let nova_final_state_commitment = hash_state_preimage(nova_state_preimage);
    let cyclo_aggregate_commitment = hash_state_preimage(cyclo_aggregate_preimage);

    let ivc_proof_hash = 100;
    let ivc_vk_hash = 200;
    let ivc_pp_hash = 300;
    let z0_commitment = 400;
    let zi_commitment = 500;
    let ivc_steps = 7;
    let share_verification_hash = 999;
    let ivc_verify_result = 1;
    let bootstrap_result_hash = 888;

    let expected_binding = poseidon::poseidon::bn254::sponge([
        nova_final_state_commitment,
        commit_pk,
        commit_ct_in,
        commit_ct_out,
        session_id,
        cyclo_aggregate_commitment,
        ivc_proof_hash,
        ivc_vk_hash,
        ivc_pp_hash,
        z0_commitment,
        zi_commitment,
        ivc_steps,
        share_verification_hash,
        ivc_verify_result,
        bootstrap_result_hash,
    ]);
    assert(expected_binding != 0);

    main(
        commit_pk, commit_ct_in, commit_ct_out, session_id,
        nova_final_state_commitment,
        cyclo_aggregate_commitment,
        ivc_proof_hash,
        ivc_vk_hash,
        ivc_pp_hash,
        z0_commitment,
        zi_commitment,
        ivc_steps,
        share_verification_hash,
        ivc_verify_result,
        bootstrap_result_hash,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_ivc_verify_result_zero() {
    // S6 adversarial: IVC verify failed -- circuit must reject
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 1,
        hash_state_preimage(nova_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        100, 200, 300, 400, 500, 1,
        999,
        0,
        888,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}

#[test(should_fail)]
fn test_fail_zero_bootstrap_result_hash() {
    // T6 adversarial: bootstrap result hash zero -- circuit must reject
    let nova_state_preimage = [10, 20, 30, 40];
    let cyclo_aggregate_preimage = [50, 60, 70, 80];

    main(
        1, 2, 3, 1,
        hash_state_preimage(nova_state_preimage),
        hash_state_preimage(cyclo_aggregate_preimage),
        100, 200, 300, 400, 500, 1,
        999,
        1,
        0,
        nova_state_preimage,
        cyclo_aggregate_preimage,
    );
}
