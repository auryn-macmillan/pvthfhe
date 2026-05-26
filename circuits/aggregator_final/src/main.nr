// aggregator_final: Simplified C7 circuit.
//
// Lagrange recombination is now done in Nova (LagrangeFoldStepCircuit).
// This circuit only needs to:
// 1. Receive the Nova final state (plaintext, share_chain_hash)
// 2. Verify plaintext_commitment = Poseidon(plaintext)
// 3. Bind ivc_snark_proof_hash (from transparent IVC)
// 4. Keep existing non-zero checks

use poseidon;
use protocol_constants;

global N: u32 = 8;

fn vector_hash<let M: u32>(values: [Field; M], domain_tag: Field) -> Field {
    let mut preimage = [0; M + 1];
    preimage[0] = domain_tag;
    for i in 0..M {
        preimage[i + 1] = values[i];
    }
    poseidon::poseidon::bn254::sponge(preimage)
}

fn main(
    ciphertext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    decrypt_nizk_hash: pub Field,
    dkg_transcript_hash: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    n_participants: pub Field,
    threshold: pub Field,
    plaintext_commitment: pub Field,
    ivc_snark_proof_hash: pub Field,

    // Nova final state (from LagrangeFoldStepCircuit):
    nova_final_plaintext: pub [Field; N],
    nova_share_chain_hash: pub Field,
) -> pub [Field; N] {
    // --- Basic validity checks ---
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(participant_set_hash != 0, "participant set hash must be non-zero");
    assert(threshold as u32 > 0, "threshold must be positive");
    assert(threshold as u32 <= n_participants as u32, "threshold must not exceed n_participants");
    assert(aggregate_pk_hash != 0, "aggregate public key hash must be non-zero");
    assert(decrypt_nizk_hash != 0, "decrypt_nizk_hash must be non-zero");
    assert(dkg_transcript_hash != 0, "dkg_transcript_hash must be non-zero");

    // --- Bind plaintext to Nova Lagrange output ---
    let computed_pt_hash = vector_hash(nova_final_plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(plaintext_commitment == computed_pt_hash, "plaintext commitment mismatch");

    // ciphertext_hash must differ from plaintext hash
    assert(ciphertext_hash != computed_pt_hash, "ciphertext and plaintext hash must differ");

    // --- Bind the transparent IVC proof ---
    assert(ivc_snark_proof_hash != 0, "IVC proof hash must be non-zero");

    // --- Share provenance is verified in Nova (LagrangeFoldStepCircuit) ---
    // nova_share_chain_hash is the Poseidon chain over all (lambda_i, share_hash_i) pairs.
    // The on-chain verifier can additionally check this value if needed.
    assert(nova_share_chain_hash != 0, "Nova share chain hash must be non-zero");

    nova_final_plaintext
}

// -- Tests -----------------------------------------------------------

#[test]
fn test_simplified_honest() {
    let plaintext = [42, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_commitment = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let ciphertext_hash = 99;

    let result = main(
        ciphertext_hash,
        100,  // aggregate_pk_hash
        500,  // decrypt_nizk_hash
        999,  // dkg_transcript_hash
        1,    // epoch
        300,  // participant_set_hash
        3,    // n_participants
        2,    // threshold
        plaintext_commitment,
        777,  // ivc_snark_proof_hash
        plaintext,
        888,  // nova_share_chain_hash
    );
    assert(result[0] == 42);
}

#[test(should_fail)]
fn test_plaintext_mismatch() {
    let plaintext = [1, 0, 0, 0, 0, 0, 0, 0];
    let wrong_commitment = 0;
    let _ = main(
        99, 100, 500, 999, 1, 300, 3, 2, wrong_commitment, 777, plaintext, 888,
    );
}

#[test(should_fail)]
fn test_ivc_hash_zero() {
    let plaintext = [0; N];
    let pt_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let _ = main(
        pt_hash + 1, 100, 500, 999, 1, 300, 3, 2, pt_hash, 0, plaintext, 888,
    );
}
