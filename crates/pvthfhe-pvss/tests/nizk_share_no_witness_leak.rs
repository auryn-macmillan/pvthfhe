//! R3.1 RED: Asserts `ShareNizkOpenedProof` does NOT contain witness fields.
//!
//! The current proof envelope leaks `share_bytes`, `encryption_randomness`,
//! and `share_coeffs` — these are witness material that must be removed.

use syn::parse_file;

const SOURCE_PATH: &str = "src/nizk_share.rs";

const FORBIDDEN_WITNESS_FIELDS: &[&str] = &[
    "share_bytes",
    "encryption_randomness",
    "share_coeffs",
];

#[test]
fn share_nizk_opened_proof_has_no_witness_fields() {
    let content = std::fs::read_to_string(SOURCE_PATH)
        .expect("Failed to read nizk_share.rs source");
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
            let name = field.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
            if FORBIDDEN_WITNESS_FIELDS.contains(&name.as_str()) {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    if !violations.is_empty() {
        panic!(
            "R3.1 RED: ShareNizkOpenedProof still contains witness fields: {:?}. \
             These must be removed per the Greco NIZK construction.",
            violations
        );
    }
}
