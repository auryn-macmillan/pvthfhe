// Surrogate circuit for NizkWellFormed (P1: LatticeFold+ NIZK placeholder)
// Proves: Exists s_i in Rq^k short such that for all j: Enc(pk_j, s_{i,j}) = encrypted_shares[j]

use poseidon;

fn main(
    pk_hash: pub Field,
    share_commitment: pub Field,
    party_id: pub Field,
    secret_share: [Field; 4],
    randomness: Field,
) {
    let _ = pk_hash;
    // 1. Party binding check
    assert(party_id != 0, "party_id must be non-zero");

    // 2. Shortness check: assert each coefficient is in range [0, 255]
    for i in 0..4 {
        let val = secret_share[i] as u8;
        assert(val as Field == secret_share[i], "secret_share coefficient out of bounds");
    }

    // 3. Commitment check
    // Poseidon is the canonical in-circuit hash (Keccak-256 is reserved for on-chain/EVM use).
    let mut input = [0; 5];
    for i in 0..4 {
        input[i] = secret_share[i];
    }
    input[4] = randomness;
    
    let computed_hash = poseidon::poseidon::bn254::hash_5(input);
    assert(computed_hash == share_commitment, "commitment mismatch");
}

#[test]
fn test_honest() {
    let pk_hash = 1;
    let party_id = 1;
    let secret_share = [1, 255, 3, 4];
    let randomness = 42;
    
    let mut input = [0; 5];
    for i in 0..4 {
        input[i] = secret_share[i];
    }
    input[4] = randomness;
    let share_commitment = poseidon::poseidon::bn254::hash_5(input);

    main(pk_hash, share_commitment, party_id, secret_share, randomness);
}

#[test(should_fail)]
fn rejects_tamper_a_out_of_range() {
    let pk_hash = 1;
    let party_id = 1;
    let secret_share = [1, 256, 3, 4]; // 256 is out of range
    let randomness = 42;
    
    let mut input = [0; 5];
    for i in 0..4 {
        input[i] = secret_share[i];
    }
    input[4] = randomness;
    let share_commitment = poseidon::poseidon::bn254::hash_5(input);

    main(pk_hash, share_commitment, party_id, secret_share, randomness);
}

#[test(should_fail)]
fn rejects_tamper_b_wrong_commitment() {
    let pk_hash = 1;
    let party_id = 1;
    let secret_share = [1, 2, 3, 4];
    let randomness = 42;
    
    let share_commitment = 999; // Wrong commitment

    main(pk_hash, share_commitment, party_id, secret_share, randomness);
}

#[test(should_fail)]
fn rejects_tamper_c_party_zero() {
    let pk_hash = 1;
    let party_id = 0; // Fails party binding
    let secret_share = [1, 2, 3, 4];
    let randomness = 42;
    
    let mut input = [0; 5];
    for i in 0..4 {
        input[i] = secret_share[i];
    }
    input[4] = randomness;
    let share_commitment = poseidon::poseidon::bn254::hash_5(input);

    main(pk_hash, share_commitment, party_id, secret_share, randomness);
}

#[test(should_fail)]
fn rejects_tamper_d_zero_wrong_commitment() {
    let pk_hash = 1;
    let party_id = 1;
    let secret_share = [0, 0, 0, 0];
    let randomness = 42;
    
    let share_commitment = 999; // Wrong commitment

    main(pk_hash, share_commitment, party_id, secret_share, randomness);
}

#[test(should_fail)]
fn rejects_tamper_e_modified_randomness() {
    let pk_hash = 1;
    let party_id = 1;
    let secret_share = [1, 2, 3, 4];
    let randomness = 42;
    
    let mut input = [0; 5];
    for i in 0..4 {
        input[i] = secret_share[i];
    }
    input[4] = randomness;
    let share_commitment = poseidon::poseidon::bn254::hash_5(input);

    // Modify randomness before passing to circuit
    main(pk_hash, share_commitment, party_id, secret_share, 43);
}

#[test(should_fail)]
fn rejects_tamper_f_two_out_of_range() {
    let pk_hash = 1;
    let party_id = 1;
    let secret_share = [256, 2, 3, 500]; // Two out of range
    let randomness = 42;
    
    let mut input = [0; 5];
    for i in 0..4 {
        input[i] = secret_share[i];
    }
    input[4] = randomness;
    let share_commitment = poseidon::poseidon::bn254::hash_5(input);

    main(pk_hash, share_commitment, party_id, secret_share, randomness);
}
