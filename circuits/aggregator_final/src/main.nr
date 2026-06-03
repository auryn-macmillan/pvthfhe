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

fn verification_statement_v1_hash(preimage: [Field; 76]) -> Field {
    poseidon::poseidon::bn254::sponge(preimage)
}

fn verification_statement_v1_golden_preimage() -> [Field; 76] {
    [
        11843706111462126810235743653006615712282455314701937352287001081393,
        1,
        19,
        1,
        4,
        1,
        2,
        32,
        21356283574076891493948969979685445151,
        42707334047547540181846984563639529007,
        3,
        32,
        42707334047547540181846984563639529007,
        64058384521018188869744999147593612863,
        4,
        8,
        42,
        5,
        32,
        64058384521018188869744999147593612863,
        85409434994488837557643013731547696719,
        6,
        32,
        85409434994488837557643013731547696719,
        106760485467959486245541028315501780575,
        7,
        32,
        106760485467959486245541028315501780575,
        128111535941430134933439042899455864431,
        8,
        32,
        128111535941430134933439042899455864431,
        149462586414900783621337057483409948287,
        9,
        32,
        149462586414900783621337057483409948287,
        170813636888371432309235072067364032143,
        10,
        32,
        170813636888371432309235072067364032143,
        192164687361842080997133086651318115999,
        11,
        32,
        192164687361842080997133086651318115999,
        213515737835312729685031101235272199855,
        12,
        32,
        213515737835312729685031101235272199855,
        234866788308783378372929115819226283711,
        13,
        32,
        234866788308783378372929115819226283711,
        256217838782254027060827130403180367567,
        14,
        32,
        256217838782254027060827130403180367567,
        277568889255724675748725144987134451423,
        15,
        32,
        277568889255724675748725144987134451423,
        298919939729195324436623159571088535279,
        16,
        32,
        298919939729195324436623159571088535279,
        320270990202665973124521174155042619135,
        17,
        32,
        320270990202665973124521174155042619135,
        5233100606242806050955395731361295,
        18,
        8,
        7,
        19,
        32,
        10680758337341567149999962687708403223,
        32031808810812215837897977271662487079,
    ]
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
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(participant_set_hash != 0, "participant set hash must be non-zero");
    assert(threshold as u32 > 0, "threshold must be positive");
    assert(threshold as u32 <= n_participants as u32, "threshold must not exceed n_participants");
    assert(aggregate_pk_hash != 0, "aggregate public key hash must be non-zero");
    assert(decrypt_nizk_hash != 0, "decrypt_nizk_hash must be non-zero");
    assert(dkg_transcript_hash != 0, "dkg_transcript_hash must be non-zero");

    let computed_pt_hash = vector_hash(nova_final_plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(plaintext_commitment == computed_pt_hash, "plaintext commitment mismatch");

    assert(ciphertext_hash != computed_pt_hash, "ciphertext and plaintext hash must differ");

    assert(ivc_snark_proof_hash != 0, "IVC proof hash must be non-zero");

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

#[test]
fn test_verification_statement_v1_poseidon_parity_hash_2717525839999002672616025848791696639911259589570414897881626410761076250408() {
    let preimage = verification_statement_v1_golden_preimage();
    let statement_hash_decimal = 2717525839999002672616025848791696639911259589570414897881626410761076250408;
    let computed = verification_statement_v1_hash(preimage);
    assert(computed == statement_hash_decimal, "statement_hash_decimal=2717525839999002672616025848791696639911259589570414897881626410761076250408");
}

#[test]
fn test_verification_statement_v1_each_field_mutation_changes_hash() {
    let golden = verification_statement_v1_golden_preimage();
    let golden_hash = 2717525839999002672616025848791696639911259589570414897881626410761076250408;
    let value_indices = [5, 8, 9, 12, 13, 16, 19, 20, 23, 24, 27, 28, 31, 32, 35, 36, 39, 40, 43, 44, 47, 48, 51, 52, 55, 56, 59, 60, 63, 64, 67, 68, 71, 74, 75];

    for i in 0..35 {
        let mut mutated = golden;
        let index = value_indices[i];
        mutated[index] = mutated[index] + 1;
        let mutated_hash = verification_statement_v1_hash(mutated);
        assert(mutated_hash != golden_hash, "mutating any value limb must change the statement hash");
    }
}

#[test(should_fail)]
fn test_verification_statement_v1_hash_mismatch_rejects_mutated_statement() {
    let mut mutated = verification_statement_v1_golden_preimage();
    mutated[5] = mutated[5] + 1;
    let golden_hash = 2717525839999002672616025848791696639911259589570414897881626410761076250408;
    assert(verification_statement_v1_hash(mutated) == golden_hash, "mutated statement hash must reject");
}
