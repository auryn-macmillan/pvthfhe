// aggregator_final: Verifies Lagrange recombination of decryption shares.
//
// This circuit replaces the old rolling_digest (non-CRH linear accumulator)
// with Poseidon, a collision-resistant hash, using domain-separation tags
// to prevent cross-context collision attacks.
//
// N=8 is the research-prototype ring dimension; production uses N=8192.
// The R3 relation check uses Q from protocol_constants (NOT prover-supplied).

use poseidon;
use protocol_constants;

global N: u32 = 8;
global LOG_N: u32 = 3;
global MAX_PARTICIPANTS: u32 = 8;

// -- Poseidon CRH helpers with domain-separation tags ----------------

fn vector_hash<let M: u32>(values: [Field; M], domain_tag: Field) -> Field {
    let mut preimage = [0; M + 1];
    preimage[0] = domain_tag;
    for i in 0..M {
        preimage[i + 1] = values[i];
    }
    poseidon::poseidon::bn254::sponge(preimage)
}

fn bind_8_with_domain(values: [Field; 8], domain_tag: Field) -> Field {
    let mut preimage = [0; 9];
    preimage[0] = domain_tag;
    for i in 0..8 {
        preimage[i + 1] = values[i];
    }
    poseidon::poseidon::bn254::hash_9(preimage)
}

fn combine_hashes<let M: u32>(hashes: [Field; M], n_active: Field) -> Field {
    let mut acc = 0;
    for i in 0..M {
        if (i as u32) < (n_active as u32) {
            acc = poseidon::poseidon::bn254::sponge([acc, hashes[i]]);
        }
    }
    acc
}

// -- Polynomial utilities --------------------------------------------

fn eval_poly(coeffs: [Field; N], r: Field) -> Field {
    let mut result = 0;
    for i in 0..N {
        result = result * r + coeffs[N - 1 - i];
    }
    result
}

fn r_pow_n(r: Field) -> Field {
    let mut result = r;
    for _ in 0..LOG_N {
        result = result * result;
    }
    result
}

// -- Main circuit ----------------------------------------------------

fn main(
    ciphertext_hash: pub Field,
    plaintext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    dkg_root: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    d_commitment: pub Field,
    n_participants: pub Field,
    threshold: pub Field,
    lagrange_coeffs: [Field; MAX_PARTICIPANTS],
    participant_shares: [[Field; N]; MAX_PARTICIPANTS],
    plaintext: [Field; N],
    z_q: Field,
) {
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(ciphertext_hash != plaintext_hash, "ciphertext and plaintext hash must differ");
    assert(participant_set_hash != 0, "participant set hash must be non-zero");
    assert(n_participants as u32 <= MAX_PARTICIPANTS, "n_participants exceeds MAX_PARTICIPANTS");
    assert(threshold as u32 > 0, "threshold must be positive");
    assert(threshold as u32 <= n_participants as u32, "threshold must not exceed n_participants");

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(participant_shares[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);

    let plaintext_check = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    assert(plaintext_check == plaintext_hash, "plaintext hash mismatch");

    let d_commitment_computed = bind_8_with_domain([
        combined_share_hash,
        dkg_root,
        participant_set_hash,
        epoch,
        n_participants,
        threshold,
        0,
        0,
    ], protocol_constants::DOMAIN_AGGREGATOR_D_COMMIT);
    assert(d_commitment_computed == d_commitment, "d_commitment mismatch");

    let r = bind_8_with_domain([
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        0,
    ], protocol_constants::DOMAIN_CHALLENGE_DERIVE);

    let lhs = eval_poly(plaintext, r);
    let mut rhs = 0;
    let mut lagrange_sum = 0;
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            rhs = rhs + lagrange_coeffs[i] * eval_poly(participant_shares[i], r);
            lagrange_sum = lagrange_sum + lagrange_coeffs[i];
        }
    }
    assert(lagrange_sum == 1, "Lagrange coefficients must sum to 1");

    let r_to_n_plus_one = r_pow_n(r) + 1;
    assert(r_to_n_plus_one != 0, "r^n+1 must be non-zero (r is not a root)");
    assert(rhs - lhs == protocol_constants::Q * z_q, "Lagrange recombination R3 violation");

    assert(aggregate_pk_hash != 0, "aggregate public key hash must be non-zero");
}

// -- Tests -----------------------------------------------------------

fn make_zero_shares() -> [[Field; N]; MAX_PARTICIPANTS] {
    let mut shares = [[0; N]; MAX_PARTICIPANTS];
    shares
}

#[test]
fn test_honest_lagrange_recombination() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;

    let lagrange_coeffs = [3, -3, 1, 0, 0, 0, 0, 0];

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let dkg_root = 200;
    let participant_set_hash = 300;

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);
    let plaintext_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let d_commitment = bind_8_with_domain([
        combined_share_hash,
        dkg_root, participant_set_hash, epoch,
        n_participants, threshold,
        0, 0,
    ], protocol_constants::DOMAIN_AGGREGATOR_D_COMMIT);

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        n_participants,
        threshold,
        lagrange_coeffs,
        d,
        plaintext,
        z_q,
    );
}

#[test(should_fail)]
fn test_collision_different_vectors_same_hash() {
    let d1 = [1, 0, 0, 0, 0, 0, 0, 0];
    let d1_mutated = [1, 1, 0, 0, 0, 0, 0, 0];

    let h1 = vector_hash(d1, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let h2 = vector_hash(d1_mutated, protocol_constants::DOMAIN_VECTOR_MERKLE);

    assert(h1 == h2, "hash collision found (should NOT happen with Poseidon)");
}

#[test(should_fail)]
fn test_collision_domain_tag_separation() {
    let values = [1, 2, 3, 4, 5, 6, 7, 8];

    let h1 = vector_hash(values, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let h2 = vector_hash(values, protocol_constants::DOMAIN_CHALLENGE_DERIVE);

    assert(h1 == h2, "domain tag separation failed (collision)");
}

#[test(should_fail)]
fn test_tamper_wrong_plaintext_hash() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;

    let lagrange_coeffs = [3, -3, 1, 0, 0, 0, 0, 0];

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let dkg_root = 200;
    let participant_set_hash = 300;

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);

    let plaintext_hash = 99999;

    let d_commitment = bind_8_with_domain([
        combined_share_hash,
        dkg_root, participant_set_hash, epoch,
        n_participants, threshold,
        0, 0,
    ], protocol_constants::DOMAIN_AGGREGATOR_D_COMMIT);

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        n_participants,
        threshold,
        lagrange_coeffs,
        d,
        plaintext,
        z_q,
    );
}

#[test(should_fail)]
fn test_tamper_relation_violation() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [0; 8];
    let z_q = 0;

    let lagrange_coeffs = [3, -3, 1, 0, 0, 0, 0, 0];

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let dkg_root = 200;
    let participant_set_hash = 300;

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);
    let plaintext_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let d_commitment = bind_8_with_domain([
        combined_share_hash,
        dkg_root, participant_set_hash, epoch,
        n_participants, threshold,
        0, 0,
    ], protocol_constants::DOMAIN_AGGREGATOR_D_COMMIT);

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        n_participants,
        threshold,
        lagrange_coeffs,
        d,
        plaintext,
        z_q,
    );
}

#[test(should_fail)]
fn test_tamper_wrong_q_relation() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 1;

    let lagrange_coeffs = [3, -3, 1, 0, 0, 0, 0, 0];

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let dkg_root = 200;
    let participant_set_hash = 300;

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);
    let plaintext_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let d_commitment = bind_8_with_domain([
        combined_share_hash,
        dkg_root, participant_set_hash, epoch,
        n_participants, threshold,
        0, 0,
    ], protocol_constants::DOMAIN_AGGREGATOR_D_COMMIT);

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        n_participants,
        threshold,
        lagrange_coeffs,
        d,
        plaintext,
        z_q,
    );
}

#[test(should_fail)]
fn test_tamper_d_commitment_mismatch() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;

    let lagrange_coeffs = [3, -3, 1, 0, 0, 0, 0, 0];

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let dkg_root = 200;
    let participant_set_hash = 300;

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);
    let plaintext_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let d_commitment = 999;

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        n_participants,
        threshold,
        lagrange_coeffs,
        d,
        plaintext,
        z_q,
    );
}

#[test(should_fail)]
fn test_tamper_wrong_lagrange_sum() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext = [3, 0, 0, 0, 0, 0, 0, 0];
    let z_q = 0;

    let lagrange_coeffs = [3, -3, 2, 0, 0, 0, 0, 0];

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let dkg_root = 200;
    let participant_set_hash = 300;

    let mut share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < (n_participants as u32) {
            share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_VECTOR_MERKLE);
        }
    }
    let combined_share_hash = combine_hashes(share_hashes, n_participants);
    let plaintext_hash = vector_hash(plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    let d_commitment = bind_8_with_domain([
        combined_share_hash,
        dkg_root, participant_set_hash, epoch,
        n_participants, threshold,
        0, 0,
    ], protocol_constants::DOMAIN_AGGREGATOR_D_COMMIT);

    main(
        ciphertext_hash,
        plaintext_hash,
        aggregate_pk_hash,
        dkg_root,
        epoch,
        participant_set_hash,
        d_commitment,
        n_participants,
        threshold,
        lagrange_coeffs,
        d,
        plaintext,
        z_q,
    );
}
