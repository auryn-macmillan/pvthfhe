//! D.1 regression: `ShareNizkOpenedProof` must not contain witness openings.
//!
//! A public share proof must not serialize Shamir share plaintext, relation
//! plaintext, deterministic encryption seeds, or encryption randomness under
//! exact names or semantic aliases.

use syn::parse_file;

const SOURCE_PATH: &str = "src/nizk_share.rs";

const FORBIDDEN_EXACT_FIELDS: &[&str] = &[
    "share_bytes",
    "encryption_randomness",
    "share_coeffs",
    "relation_plaintext",
    "relation_randomness",
    "opened_plaintext",
    "opened_randomness",
];

const FORBIDDEN_FIELD_TOKENS: &[&str] = &["plaintext", "randomness", "seed", "share"];

const PUBLIC_STATEMENT_FIELDS_ALLOWED_ON_OPENED_PROOF: &[&str] = &["statement", "commitment_seed"];

#[test]
fn share_nizk_opened_proof_has_no_witness_fields() {
    let content =
        std::fs::read_to_string(SOURCE_PATH).expect("Failed to read nizk_share.rs source");
    let file = parse_file(&content).expect("Failed to parse nizk_share.rs");

    let target_struct = file
        .items
        .iter()
        .find_map(|item| {
            if let syn::Item::Struct(item_struct) = item {
                if item_struct.ident == "ShareNizkOpenedProof" {
                    return Some(item_struct);
                }
            }
            None
        })
        .expect("ShareNizkOpenedProof struct not found in nizk_share.rs");

    let violations: Vec<String> = target_struct
        .fields
        .iter()
        .filter_map(|field| {
            let name = field
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default();
            let normalized = name.to_ascii_lowercase();
            let exact_violation = FORBIDDEN_EXACT_FIELDS.contains(&normalized.as_str());
            let alias_violation = FORBIDDEN_FIELD_TOKENS
                .iter()
                .any(|token| normalized.contains(token))
                && !PUBLIC_STATEMENT_FIELDS_ALLOWED_ON_OPENED_PROOF.contains(&normalized.as_str());
            exact_violation
                .then_some(format!("{name} (exact witness field)"))
                .or_else(|| alias_violation.then_some(format!("{name} (semantic witness alias)")))
        })
        .collect();

    if !violations.is_empty() {
        panic!(
            "D.1 regression: ShareNizkOpenedProof contains public witness-opening fields: {:?}. \
             Do not serialize share plaintext, opened plaintext, randomness, or seeds in the public proof.",
            violations
        );
    }
}
