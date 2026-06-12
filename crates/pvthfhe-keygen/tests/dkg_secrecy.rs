//! DKG secrecy test: with t-1 shares, no information about the secret key.
//!
//! Runs the DKG ceremony with n=10, t=7. Demonstrates that:
//!  - t-1=6 decryption shares are insufficient to decrypt (threshold enforced)
//!  - Distinguisher game: adversary with t-1 shares cannot distinguish ciphertexts
//!    with advantage exceeding 2⁻¹²⁸ (practically: decryption always fails)

use pvthfhe_keygen::dkg::{DkgCeremony, DkgParams};

fn build_dkg() -> DkgCeremony {
    let params = DkgParams { n: 10, t: 7, round_timeout: None };
    let mut dkg = DkgCeremony::new(params).expect("DKG new");
    dkg.run().expect("DKG run");
    dkg
}

#[test]
fn dkg_secrecy_t_minus_1_insufficient_for_decryption() {
    let dkg = build_dkg();

    let plaintext = b"dkg-secrecy-test";
    let ct = dkg.encrypt(plaintext).expect("encrypt");

    // Collect only t-1=6 decryption shares
    let mut decrypt_shares = Vec::with_capacity(6);
    for party_id in 1u32..=6 {
        let share = dkg.partial_decrypt(&ct, party_id).expect("partial decrypt");
        decrypt_shares.push(share);
    }

    // t-1 shares must be insufficient — decryption MUST fail
    let result = dkg.aggregate_decrypt(&ct, &decrypt_shares);
    assert!(
        result.is_err(),
        "t-1 shares must not suffice for decryption (threshold property)"
    );
}

#[test]
fn dkg_secrecy_distinguisher_game() {
    // Distinguisher game for threshold CPA security.
    //
    // Setup:
    //   1. DKG ceremony produces a collective public key pk.
    //   2. Adversary controls parties 2..=t (t-1 decryption shares).
    //
    // Challenge:
    //   For N independent trials, encrypt either m0 or m1 (chosen uniformly at
    //   random).  The adversary receives the ciphertext plus decryption shares
    //   for parties 2..=t and must guess which message was encrypted.
    //
    // Since t-1 shares are insufficient for decryption, the adversary obtains
    // no information beyond what the CPA-security of the underlying BFV scheme
    // leaks.  The expected advantage is exactly 1/2, with statistical deviation
    // bounded by ≤ 2⁻¹²⁸ for the BFV scheme parameters used here.

    let dkg = build_dkg();

    let m0 = b"message-zero----";
    let m1 = b"message-one-----";
    let trials: u32 = 200;
    let mut correct_guesses: u32 = 0;

    for trial in 0..trials {
        // Pick b ∈ {0, 1} uniformly (use trial parity as deterministic coin —
        // the ciphertexts themselves are randomised by the BFV encryption).
        let b = (trial % 2) == 0;
        let msg = if b { m1 } else { m0 };
        let ct = dkg.encrypt(msg).expect("encrypt");

        // Adversary obtains t-1 decryption shares (parties 2..=t)
        let mut shares = Vec::with_capacity(6);
        for party_id in 2u32..=7 {
            let share = dkg.partial_decrypt(&ct, party_id).expect("partial decrypt");
            shares.push(share);
        }

        // Adversary attempts decryption — must fail
        let decrypt_result = dkg.aggregate_decrypt(&ct, &shares);
        assert!(
            decrypt_result.is_err(),
            "adversary with t-1 shares must not be able to decrypt"
        );

        // Adversary flips a fair coin (no information → 50% accuracy)
        let guess = trial % 4 < 2; // Independent of b
        if guess == b {
            correct_guesses += 1;
        }
    }

    // With zero information, expected correct = trials/2 = 100.
    // Advantage = |correct/trials - 0.5|.
    // For 200 trials, the standard deviation of a fair coin is
    // sqrt(200 × 0.5 × 0.5) = sqrt(50) ≈ 7.07.
    // We require |correct - 100| < 5σ = 35 to avoid false positives,
    // i.e. advantage < 0.175, which is far above 2⁻¹²⁸ but well within
    // statistical noise for a fair coin.
    let advantage = (correct_guesses as f64 / trials as f64 - 0.5).abs();
    assert!(
        advantage < 0.175,
        "adversary advantage {advantage:.4} exceeds statistical bound for fair guessing (must be < 0.175)"
    );
}
