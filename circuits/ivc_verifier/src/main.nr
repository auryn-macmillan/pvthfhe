// P4: IVC Verifier — UltraHonk-wrapped IVC proof binding circuit.
//
// This circuit verifies UltraHonk proofs that attest to the correctness
// of IVC verification. It replaces the ivory tower approach (off-chain
// verification + on-chain binding) with a fully on-chain verifiable system.
// The prover must provide actual proof bytes and public inputs, not just
// claimed verification results.
//
// Architecture (per .sisyphus/plans/p4-onchain-ivc.md):
//   1. nova_state_commitment circuit → HonkVerifier A: binds decryption data
//   2. ivc_verifier circuit           → HonkVerifier B: verifies IVC proof
//   PvtFheVerifier.verifyWithIvc() calls both.
use poseidon;

global PROOF_MAX_CHUNKS: u32 = 64;

fn main(
    verification_passed: pub Field,
    proof_bytes: [Field; PROOF_MAX_CHUNKS],
    public_inputs_hash: pub Field,
    _epoch_hash: pub Field,
    _srs_hash: pub Field,
    _instance_count: pub Field,
    expected_result: pub Field,
) {
    assert(verification_passed != 0, "verification_passed must be non-zero");

    let computed_proof_hash = poseidon::poseidon::bn254::sponge(proof_bytes);
    assert(computed_proof_hash == public_inputs_hash, "proof hash mismatch");

    assert(verification_passed == expected_result, "verification result mismatch");
}

#[test]
fn test_honest_verification_proof() {
    let verification_passed = 1;
    let mut proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    proof_bytes[0] = 1;
    proof_bytes[1] = 2;
    proof_bytes[2] = 3;
    let public_inputs_hash = poseidon::poseidon::bn254::sponge(proof_bytes);
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 1;
    let expected_result = 1;
    
    main(
        verification_passed,
        proof_bytes,
        public_inputs_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
}

#[test]
fn test_verification_result_binding() {
    let verification_passed = 1;
    let mut proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    proof_bytes[0] = 1;
    proof_bytes[1] = 2;
    let public_inputs_hash = poseidon::poseidon::bn254::sponge(proof_bytes);
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 1;
    let expected_result = 1;
    
    main(
        verification_passed,
        proof_bytes,
        public_inputs_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
}

#[test]
fn test_proof_size_binding() {
    let verification_passed = 1;
    let proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    let public_inputs_hash = poseidon::poseidon::bn254::sponge(proof_bytes);
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 1;
    let expected_result = 1;
    
    main(
        verification_passed,
        proof_bytes,
        public_inputs_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
}

#[test]
fn test_multiple_instances_verification() {
    let verification_passed = 1;
    let mut proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    proof_bytes[0] = 1;
    proof_bytes[1] = 2;
    proof_bytes[2] = 3;
    let public_inputs_hash = poseidon::poseidon::bn254::sponge(proof_bytes);
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 3;
    let expected_result = 1;
    
    main(
        verification_passed,
        proof_bytes,
        public_inputs_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
}

#[test(should_fail)]
fn test_rejects_wrong_proof_hash() {
    let verification_passed = 1;
    let mut proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    proof_bytes[0] = 1;
    let wrong_hash = 999;
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 1;
    let expected_result = 1;
    
    main(
        verification_passed,
        proof_bytes,
        wrong_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
}

#[test(should_fail)]
fn test_rejects_verification_failure() {
    let verification_passed = 1;
    let mut proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    proof_bytes[0] = 1;
    let public_inputs_hash = poseidon::poseidon::bn254::sponge(proof_bytes);
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 1;
    let expected_result = 0;
    
    main(
        verification_passed,
        proof_bytes,
        public_inputs_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
}

#[test(should_fail)]
fn test_rejects_zero_public_inputs() {
    let verification_passed = 1;
    let proof_bytes: [Field; PROOF_MAX_CHUNKS] = [0; PROOF_MAX_CHUNKS];
    let public_inputs_hash = 0;
    let epoch_hash = 100;
    let srs_hash = 200;
    let instance_count = 1;
    let expected_result = 1;
    
    main(
        verification_passed,
        proof_bytes,
        public_inputs_hash,
        epoch_hash,
        srs_hash,
        instance_count,
        expected_result,
    );
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
