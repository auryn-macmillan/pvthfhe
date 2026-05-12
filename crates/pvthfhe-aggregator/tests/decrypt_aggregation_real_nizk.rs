//! R3.2 RED: Assert the aggregator's `verify_partial` path uses real NIZK
//! verification, not the `nizk[0] == 1` tautology.
//!
//! Currently `aggregate_decrypt` checks `payload.nizk.as_slice()[0] != 1` —
//! a trivial check that always passes for `nizk: ProtocolBytes(vec![1])`.
//! After GREEN, the aggregator must call `DecryptNizkVerifier::verify` and
//! the partial-decrypt function must produce a real NIZK proof.

use std::fs;

const DECRYPT_MOD_PATH: &str = "src/decrypt/mod.rs";

/// The source code must NOT contain the trivial `nizk[0]` byte-check pattern
/// that was the old surrogate NIZK verification.
///
/// After GREEN, the aggregator must call the real NIZK verifier instead.
#[test]
fn no_trivial_nizk_byte_check_in_source() {
    let src =
        fs::read_to_string(DECRYPT_MOD_PATH).expect("aggregator decrypt/mod.rs must be readable");

    // Look for the old surrogate check: nizk[...] == 1 or nizk[...] != 1
    let lines_with_old_check: Vec<_> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            line.contains("nizk")
                && (line.contains("[0]") || line.contains(".as_slice()[0]"))
                && (line.contains("== 1") || line.contains("!= 1"))
        })
        .collect();

    assert!(
        lines_with_old_check.is_empty(),
        "Found {} line(s) with `nizk[0] ==/!= 1` surrogate check in {}. \
         Lines: {:?}. \
         Must be replaced with real DecryptNizkVerifier::verify call.",
        lines_with_old_check.len(),
        DECRYPT_MOD_PATH,
        lines_with_old_check
            .iter()
            .map(|(n, l)| format!("L{}: {}", n + 1, l.trim()))
            .collect::<Vec<_>>()
    );
}

/// `partial_decrypt` must produce a real NIZK proof, not
/// `nizk: ProtocolBytes(vec![1])`.
///
/// After GREEN, `pk_i_hash` must also be a real commitment (not `[0u8; 32]`).
#[test]
fn no_hardcoded_nizk_or_zero_pk_hash_in_source() {
    let src =
        fs::read_to_string(DECRYPT_MOD_PATH).expect("aggregator decrypt/mod.rs must be readable");

    // Check for the hardcoded nizk surrogate
    let nizk_surrogate = src.contains("vec![1]");
    let pk_zero = src.contains("[0u8; 32]");

    assert!(
        !nizk_surrogate,
        "Hardcoded NIZK surrogate `vec![1]` found in {}. \
         partial_decrypt must produce a real DecryptNizkProof.",
        DECRYPT_MOD_PATH
    );

    assert!(
        !pk_zero,
        "Hardcoded zero pk_i_hash `[0u8; 32]` found in {}. \
         Must be replaced with a real pk_i commitment.",
        DECRYPT_MOD_PATH
    );
}
