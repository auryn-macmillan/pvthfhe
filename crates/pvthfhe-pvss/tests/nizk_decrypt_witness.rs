//! R3.2 RED: Assert `derive_secret_share` is absent from nizk_decrypt.rs.
//!
//! The witness for the partial-decryption NIZK must carry `sk_i` (or a value
//! derived from it), not a value derivable from the public statement alone.
//! `derive_secret_share` is a surrogacy that derives the secret share from
//! public statement fields, making the NIZK binding vacuous.

use std::fs;

const SOURCE_PATH: &str = "src/nizk_decrypt.rs";

/// The function `derive_secret_share` must not exist in the source.
/// It currently derives a u64 secret-share scalar from public statement
/// fields — anyone can compute it, defeating the NIZK binding.
#[test]
#[ignore = "RED: R3.2 decrypt NIZK — derive_secret_share must be removed"]
fn derive_secret_share_is_absent() {
    let src = fs::read_to_string(SOURCE_PATH).expect("nizk_decrypt.rs must be readable");

    // Block-lines grep: look for fn derive_secret_share definition.
    let found = src
        .lines()
        .filter(|line| line.contains("fn derive_secret_share"))
        .count();

    assert_eq!(
        found, 0,
        "derive_secret_share found {found} time(s) in {SOURCE_PATH}; \
         must be removed: the secret share should be derived from sk_i (the witness), \
         not from public statement fields"
    );
}

/// The witness must contain the actual secret key material; the NIZK statement
/// should NOT contain any field that allows the verifier to derive the secret
/// share from public data alone.  After GREEN, `DecryptNizkStatement` fields
/// must not suffice to reconstruct the `secret_share` value used in the proof.
#[test]
#[ignore = "RED: R3.2 decrypt NIZK — secret share derivable from public statement"]
fn secret_share_not_derivable_from_statement() {
    // Construct a sample statement and show that the secret_share used in
    // the proof commitment must depend on secret key bytes (witness), not
    // only on public statement fields.
    //
    // This is a documentation-level check: the RED phase merely confirms
    // that derive_secret_share exists and makes the binding vacuous.
    // The GREEN phase will remove it and the behavioral assertion will
    // be that two provers with different sk_i produce different commitments.

    // For now: the RED test is the source-grep above.  This test serves as
    // a placeholder for the GREEN-phase behavioral check.
    let src = fs::read_to_string(SOURCE_PATH).expect("nizk_decrypt.rs must be readable");
    let has_derive = src.contains("fn derive_secret_share");
    assert!(
        !has_derive,
        "derive_secret_share must not exist: secret_share is derivable from public statement"
    );
}
