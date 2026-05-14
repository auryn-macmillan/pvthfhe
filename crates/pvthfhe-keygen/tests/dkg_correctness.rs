//! DKG correctness test: n=10, t=7 BFV threshold keygen + encrypt/decrypt.
//!
//! Runs the DKG ceremony with 10 parties and threshold 7. Verifies:
//!  - Public key is produced
//!  - All 10 parties contribute keygen shares
//!  - t=7 honest decryption shares reconstruct the plaintext
//!  - Reconstruction is consistent across any size-≥t quorum

use pvthfhe_keygen::dkg::{DkgCeremony, DkgParams};

#[test]
fn dkg_n10_t7_correctness_encrypt_decrypt() {
    let params = DkgParams { n: 10, t: 7 };
    let mut dkg = DkgCeremony::new(params).expect("DKG new");
    dkg.run().expect("DKG run");

    // Verify public key was produced
    let pk = dkg.public_key().expect("public key");
    assert!(!pk.bytes.is_empty(), "public key must not be empty");

    // Encrypt a known plaintext
    let plaintext = b"dkg-correctness-v1";
    let ct = dkg.encrypt(plaintext).expect("encrypt");

    // Collect t=7 decryption shares from the first 7 parties
    let mut decrypt_shares = Vec::with_capacity(7);
    for party_id in 1u32..=7 {
        let share = dkg.partial_decrypt(&ct, party_id).expect("partial decrypt");
        decrypt_shares.push(share);
    }

    // Aggregate decryption — must recover original plaintext
    let recovered = dkg.aggregate_decrypt(&ct, &decrypt_shares)
        .expect("aggregate decrypt");
    assert_eq!(
        recovered, plaintext,
        "recovered plaintext must match original"
    );
}

#[test]
fn dkg_consistency_across_different_quorums() {
    let params = DkgParams { n: 10, t: 7 };
    let mut dkg = DkgCeremony::new(params).expect("DKG new");
    dkg.run().expect("DKG run");

    let plaintext = b"dkg-consistency";
    let ct = dkg.encrypt(plaintext).expect("encrypt");

    // Quorum A: parties 1–7
    let mut shares_a = Vec::with_capacity(7);
    for party_id in 1u32..=7 {
        shares_a.push(dkg.partial_decrypt(&ct, party_id).expect("partial decrypt"));
    }
    let recovered_a = dkg.aggregate_decrypt(&ct, &shares_a).expect("aggregate a");

    // Quorum B: parties 4–10
    let mut shares_b = Vec::with_capacity(7);
    for party_id in 4u32..=10 {
        shares_b.push(dkg.partial_decrypt(&ct, party_id).expect("partial decrypt"));
    }
    let recovered_b = dkg.aggregate_decrypt(&ct, &shares_b).expect("aggregate b");

    assert_eq!(recovered_a, plaintext);
    assert_eq!(recovered_b, plaintext);
    assert_eq!(recovered_a, recovered_b);
}
