// aggregator_final: Verifies Lagrange recombination of decryption shares.
//
// This circuit replaces the old prover-trusted Lagrange coefficients and
// plaintext with in-circuit computation. Lagrange coefficients are
// derived from committee party IDs (public input), and the plaintext is
// reconstructed from participant shares via Lagrange interpolation.
//
// N=8 is the research-prototype ring dimension; production uses N=8192.
// The R3 relation check uses Q from protocol_constants (NOT prover-supplied).

use poseidon;
use protocol_constants;

global N: u32 = 8;
global MAX_PARTICIPANTS: u32 = 128;

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

// -- Lagrange coefficient computation --------------------------------
//
// lambda_i = prod_{j != i} party_ids[j] / prod_{j != i} (party_ids[i] - party_ids[j])
// This is the Lagrange basis polynomial l_i(0) for evaluation point 0,
// up to a sign factor. The circuit verifies that sum of lambdas = 1.
// NOTE: party_ids MUST be non-zero and pairwise distinct, otherwise
// division by zero or lagrange_sum != 1 will cause constraint failure.

fn lagrange_coeff_at(i: u32, party_ids: [Field; MAX_PARTICIPANTS], n: u32) -> Field {
    let mut num = 1;
    let mut den = 1;
    for j in 0..MAX_PARTICIPANTS {
        if (j as u32) < n {
            if (j as u32) != i {
                num = num * party_ids[j];
                den = den * (party_ids[i] - party_ids[j]);
            }
        }
    }
    let lambda = num / den;
    // Sign correction: l_i(0) = (-1)^{n-1} * prod x_j / prod (x_i - x_j)
    if (n % 2 == 0) {
        -lambda
    } else {
        lambda
    }
}

// -- Main circuit ----------------------------------------------------

fn main(
    ciphertext_hash: pub Field,
    aggregate_pk_hash: pub Field,
    decrypt_nizk_hash: pub Field,
    dkg_transcript_hash: pub Field,
    epoch: pub Field,
    participant_set_hash: pub Field,
    n_participants: pub Field,
    threshold: pub Field,

    committee_party_ids: pub [Field; MAX_PARTICIPANTS],
    participant_shares: [[Field; N]; MAX_PARTICIPANTS],
    registered_share_hashes: pub [Field; MAX_PARTICIPANTS],
) -> pub [Field; N] {
    assert(epoch as u64 > 0, "epoch must be positive");
    assert(participant_set_hash != 0, "participant set hash must be non-zero");
    // n_participants is bounded by MAX_PARTICIPANTS at the Prover.toml level
    // (first MAX_PARTICIPANTS party IDs/shares are used)
    assert(threshold as u32 > 0, "threshold must be positive");
    assert(threshold as u32 <= n_participants as u32, "threshold must not exceed n_participants");


    let n = if (n_participants as u32) < MAX_PARTICIPANTS { n_participants as u32 } else { MAX_PARTICIPANTS };
    // But Lagrange requires distinct non-zero IDs. Cap n to the count of
    // non-zero committee_party_ids (zeros are padding from Prover.toml).
    let mut n_nonzero = 0;
    for i in 0..MAX_PARTICIPANTS {
        if committee_party_ids[i] != 0 {
            n_nonzero = n_nonzero + 1;
        }
    }
    let n = if n_nonzero < n { n_nonzero } else { n };

    // Party IDs must be non-zero (prevents prover from giving one party all weight)
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < n {
            assert(committee_party_ids[i] != 0, "party ID must be non-zero");
        }
    }

    // G.7: Bind committee_party_ids to participant_set_hash
    // Ensure unused committee_party_ids slots are zero
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) >= n {
            assert(committee_party_ids[i] == 0, "unused party_id must be zero");
        }
    }
    // Hash the full array (zeros for unused slots are consistent)
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let computed_participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);
    assert(computed_participant_set_hash == participant_set_hash,
        "committee_party_ids must hash to participant_set_hash");

    // --- Compute Lagrange coefficients from committee party IDs ---
    let mut lagrange_coeffs = [0; MAX_PARTICIPANTS];
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < n {
            lagrange_coeffs[i] = lagrange_coeff_at(i, committee_party_ids, n);
        }
    }

    // Verify Lagrange coefficients sum to 1 (catches zero or duplicate IDs)
    let mut lagrange_sum = 0;
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < n {
            lagrange_sum = lagrange_sum + lagrange_coeffs[i];
        }
    }
    assert(lagrange_sum == 1, "Lagrange coefficients must sum to 1");

    // G.8: Enforce exactly threshold+1 non-zero shares
    let mut share_non_zero_count = 0;
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < n {
            if participant_shares[i][0] != 0 {
                share_non_zero_count = share_non_zero_count + 1;
            } else {
                // All elements must be zero if first element is zero
                for j in 1..N {
                    assert(participant_shares[i][j] == 0, "zero-first share must be all zeros");
                }
            }
        }
    }
    assert(share_non_zero_count == threshold + 1,
        "exactly threshold+1 shares must be non-zero");

    // G.SHARE-PROVENANCE: verify each share matches the DKG-registered commitment.
    // This proves s_i came from the correct DKG polynomial: the dealer publishes
    // hash(s_i) during DKG setup, and the circuit verifies the received share matches.
    for i in 0..MAX_PARTICIPANTS {
        if (i as u32) < n {
            let share_hash = vector_hash(participant_shares[i], protocol_constants::DOMAIN_DKG_SHARE_COMMIT);
            assert(share_hash == registered_share_hashes[i],
                "share does not match DKG registration");
        }
    }

    // --- Reconstruct plaintext from shares via Lagrange interpolation ---
    let mut computed_plaintext = [0; N];
    for j in 0..N {
        let mut coeff = 0;
        for i in 0..MAX_PARTICIPANTS {
            if (i as u32) < n {
                coeff = coeff + lagrange_coeffs[i] * participant_shares[i][j];
            }
        }
        computed_plaintext[j] = coeff;
    }

    // Hash the computed plaintext (used for ciphertext distinction check)
    let plaintext_hash = vector_hash(computed_plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);

    // Constrain ciphertext_hash: must differ from plaintext_hash
    assert(ciphertext_hash != plaintext_hash, "ciphertext and plaintext hash must differ");

    // --- d_commitment is verified on-chain (HonkVerifier.sol), not in-circuit.
    // The circuit verifies internal consistency (shares -> plaintext).

    assert(aggregate_pk_hash != 0, "aggregate public key hash must be non-zero");

    // G7: decrypt_nizk_hash must be non-zero. On-chain verifier MUST check
    // against the DKG-registered decrypt NIZK proof hash to prevent garbage proofs.
    assert(decrypt_nizk_hash != 0, "decrypt_nizk_hash must be non-zero");

    // DKG key aggregation: transcript hash must be non-zero.
    // On-chain verifier checks against DKG ceremony output.
    assert(dkg_transcript_hash != 0);

    computed_plaintext
}

// -- Tests -----------------------------------------------------------

fn make_zero_shares() -> [[Field; N]; MAX_PARTICIPANTS] {
    let shares = [[0; N]; MAX_PARTICIPANTS];
    shares
}

#[test]
fn test_honest_lagrange_recombination() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[1] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[2] = [1, 0, 0, 0, 0, 0, 0, 0];

    // Party IDs [1, 2, 3] -- Lagrange coeffs at x=0: [3, -3, 1]
    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    let mut registered_share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..3 {
        registered_share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_DKG_SHARE_COMMIT);
    }

    let plaintext = main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,

        committee_party_ids,
        d,
        registered_share_hashes,
    );

    // Verify plaintext = [1, 0, 0, 0, 0, 0, 0, 0]
    // (shares: d0=[1,0,...], d1=[1,0,...], d2=[1,0,...]; lambda=[3,-3,1])
    assert(plaintext[0] == 1);
    assert(plaintext[1] == 0);
    assert(plaintext[2] == 0);
    assert(plaintext[3] == 0);
    assert(plaintext[4] == 0);
    assert(plaintext[5] == 0);
    assert(plaintext[6] == 0);
    assert(plaintext[7] == 0);
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
fn test_tamper_zero_party_id() {
    // Party ID 0 causes lambda_i = 0 for all i, so lagrange_sum = 0 != 1
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 0;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let participant_set_hash = 300;

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        [0; MAX_PARTICIPANTS],
    );
}

#[test(should_fail)]
fn test_tamper_duplicate_party_ids() {
    // Duplicate party IDs cause division by zero in Lagrange computation
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 1;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        [0; MAX_PARTICIPANTS],
    );
}

#[test(should_fail)]
fn test_ciphertext_equals_plaintext_hash() {
    // ciphertext_hash must differ from plaintext_hash
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[1] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[2] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    // Compute what plaintext would be to get its hash
    let expected_plaintext = [1, 0, 0, 0, 0, 0, 0, 0];
    let plaintext_hash = vector_hash(expected_plaintext, protocol_constants::DOMAIN_VECTOR_MERKLE);
    let ciphertext_hash = plaintext_hash;  // Should fail: ciphertext == plaintext hash

    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        [0; MAX_PARTICIPANTS],
    );
}

#[test(should_fail)]
fn test_tamper_wrong_threshold() {
    // threshold > n_participants should fail
    let n_participants = 3;
    let threshold = 5;  // threshold exceeds n_participants
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let participant_set_hash = 300;

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        [0; MAX_PARTICIPANTS],
    );
}

#[test(should_fail)]
fn test_tamper_epoch_zero() {
    // epoch must be positive
    let n_participants = 3;
    let threshold = 2;
    let epoch = 0;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let participant_set_hash = 300;

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        [0; MAX_PARTICIPANTS],
    );
}

#[test(should_fail)]
fn test_tamper_aggregate_pk_hash_zero() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[1] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[2] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 0;
    let decrypt_nizk_hash = 500;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    let mut registered_share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..3 {
        registered_share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_DKG_SHARE_COMMIT);
    }

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        registered_share_hashes,
    );
}

#[test(should_fail)]
fn test_tamper_decrypt_nizk_hash_zero() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[1] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[2] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 0;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    let mut registered_share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..3 {
        registered_share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_DKG_SHARE_COMMIT);
    }

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        registered_share_hashes,
    );
}

#[test(should_fail)]
fn test_tamper_dkg_transcript_hash_zero() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[1] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[2] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    let mut registered_share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..3 {
        registered_share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_DKG_SHARE_COMMIT);
    }

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        0,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        registered_share_hashes,
    );
}

#[test(should_fail)]
fn test_tamper_registered_share_hashes() {
    let n_participants = 3;
    let threshold = 2;
    let epoch = 1;

    let mut d = make_zero_shares();
    d[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[1] = [1, 0, 0, 0, 0, 0, 0, 0];
    d[2] = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut committee_party_ids = [0; MAX_PARTICIPANTS];
    committee_party_ids[0] = 1;
    committee_party_ids[1] = 2;
    committee_party_ids[2] = 3;

    let ciphertext_hash = 42;
    let aggregate_pk_hash = 100;
    let decrypt_nizk_hash = 500;
    let mut ps_hash_inputs = [0; MAX_PARTICIPANTS + 1];
    ps_hash_inputs[0] = protocol_constants::DOMAIN_VECTOR_MERKLE;
    for i in 0..MAX_PARTICIPANTS {
        ps_hash_inputs[i + 1] = committee_party_ids[i];
    }
    let participant_set_hash = poseidon::poseidon::bn254::sponge(ps_hash_inputs);

    let mut registered_share_hashes = [0; MAX_PARTICIPANTS];
    for i in 0..3 {
        registered_share_hashes[i] = vector_hash(d[i], protocol_constants::DOMAIN_DKG_SHARE_COMMIT) + 1;
    }

    main(
        ciphertext_hash,
        aggregate_pk_hash,
        decrypt_nizk_hash,
        999,
        epoch,
        participant_set_hash,
        n_participants,
        threshold,
        
        committee_party_ids,
        d,
        registered_share_hashes,
    );
}
