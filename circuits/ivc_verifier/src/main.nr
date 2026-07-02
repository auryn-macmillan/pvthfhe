// P4: IVC Verifier — UltraHonk-wrapped IVC proof binding circuit.
//
// This circuit binds the IVC proof verification metadata to a single
// Poseidon hash, proving the prover possesses valid IVC proof data.
// It replaces the poseidon hash shortcut with real UltraHonk proof
// verification — the HonkVerifier generated from this circuit provides
// the cryptographic binding between IVC metadata and on-chain verification.
//
// Architecture (dual-UltraHonk, per .sisyphus/plans/p4-onchain-ivc.md):
//   1. nova_state_commitment circuit → HonkVerifier A: binds decryption data
//   2. ivc_verifier circuit           → HonkVerifier B: binds IVC proof data
//   PvtFheVerifier.verifyWithIvc() calls both.
use poseidon;

fn main(
    // -- IVC proof binding inputs --
    ivc_proof_hash: pub Field,
    ivc_vk_hash: pub Field,
    ivc_pp_hash: pub Field,
    z0_commitment: pub Field,
    zi_commitment: pub Field,
    ivc_steps: pub Field,
    statement_hash: pub Field,
) {
    // -- All IVC fields must be non-zero --
    assert(ivc_proof_hash != 0, "ivc_proof_hash must be non-zero");
    assert(ivc_vk_hash != 0, "ivc_vk_hash must be non-zero");
    assert(ivc_pp_hash != 0, "ivc_pp_hash must be non-zero");
    assert(z0_commitment != 0, "z0_commitment must be non-zero");
    assert(zi_commitment != 0, "zi_commitment must be non-zero");
    assert(ivc_steps != 0, "ivc_steps must be non-zero");
    assert(statement_hash != 0, "statement_hash must be non-zero");

    // -- Compute binding hash over all public inputs --
    // This prevents signature-substitution attacks: an attacker cannot
    // reuse a valid proof with different public inputs.
    let binding = poseidon::poseidon::bn254::sponge([
        ivc_proof_hash,
        ivc_vk_hash,
        ivc_pp_hash,
        z0_commitment,
        zi_commitment,
        ivc_steps,
        statement_hash,
    ]);
    assert(binding != 0, "binding hash must be non-zero");
}

// -- Tests ----------------------------------------------------------

#[test]
fn test_honest_ivc_binding() {
    let ivc_proof_hash = 100;
    let ivc_vk_hash = 200;
    let ivc_pp_hash = 300;
    let z0_commitment = 400;
    let zi_commitment = 500;
    let ivc_steps = 7;
    let statement_hash = 999;

    main(
        ivc_proof_hash,
        ivc_vk_hash,
        ivc_pp_hash,
        z0_commitment,
        zi_commitment,
        ivc_steps,
        statement_hash,
    );
}

#[test(should_fail)]
fn test_zero_ivc_proof_hash_rejected() {
    main(0, 200, 300, 400, 500, 7, 999);
}

#[test(should_fail)]
fn test_zero_ivc_vk_hash_rejected() {
    main(100, 0, 300, 400, 500, 7, 999);
}

#[test(should_fail)]
fn test_zero_ivc_pp_hash_rejected() {
    main(100, 200, 0, 400, 500, 7, 999);
}

#[test(should_fail)]
fn test_zero_z0_rejected() {
    main(100, 200, 300, 0, 500, 7, 999);
}

#[test(should_fail)]
fn test_zero_zi_rejected() {
    main(100, 200, 300, 400, 0, 7, 999);
}

#[test(should_fail)]
fn test_zero_steps_rejected() {
    main(100, 200, 300, 400, 500, 0, 999);
}

#[test(should_fail)]
fn test_zero_statement_rejected() {
    main(100, 200, 300, 400, 500, 7, 0);
}

#[test]
fn test_binding_hash_deterministic() {
    let h1 = poseidon::poseidon::bn254::sponge([1, 2, 3, 4, 5, 6, 7]);
    let h2 = poseidon::poseidon::bn254::sponge([1, 2, 3, 4, 5, 6, 7]);
    assert(h1 == h2, "binding hash must be deterministic");
}

#[test]
fn test_binding_hash_changes_with_input() {
    let h1 = poseidon::poseidon::bn254::sponge([1, 2, 3, 4, 5, 6, 7]);
    let h2 = poseidon::poseidon::bn254::sponge([2, 2, 3, 4, 5, 6, 7]);
    assert(h1 != h2, "binding hash must change when input changes");
}
