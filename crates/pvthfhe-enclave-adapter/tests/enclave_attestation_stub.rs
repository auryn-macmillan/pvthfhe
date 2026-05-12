//! R10.1 RED: Attestation stub detection tests.
//!
//! These tests detect the current stub state of `verify_proof`
//! (audit finding F64). They must FAIL on current main and
//! GREEN after R10.1 real attestation verification is wired.
#![cfg(feature = "stub")]
#![allow(clippy::unwrap_used)]

use pvthfhe_enclave_adapter::{EnclaveAggregator, EnclaveProof, PvthfheEnclaveAggregator};
use pvthfhe_fhe::fhers::FhersBackend;
use pvthfhe_fhe::FheBackend;

const TOML: &str = "[rlwe]\nn = 8192\nlog2_q = 174\nt_plain = 65536\nmoduli = [288230376173076481, 288230376167047169, 288230376161280001]\nvariance = 10\n";

#[test]
fn verify_proof_rejects_invalid_attestation_proof() {
    let backend = FhersBackend::load_params(TOML).unwrap();
    let agg = PvthfheEnclaveAggregator::new(backend, 3);
    let invalid_proof = EnclaveProof(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let public_inputs: Vec<u8> = vec![];

    let result = agg.verify_proof(&invalid_proof, &public_inputs);

    assert!(result.is_ok(), "verify_proof should return Ok");
    let accepted = result.unwrap();
    assert!(
        !accepted,
        "R10.1 RED: verify_proof stub accepts an invalid attestation proof. \
         Replace with real attestation verification per .sisyphus/design/enclave-construction.md."
    );
}

#[test]
fn verify_proof_rejects_malformed_attestation_evidence() {
    let backend = FhersBackend::load_params(TOML).unwrap();
    let agg = PvthfheEnclaveAggregator::new(backend, 3);
    let garbage_evidence = EnclaveProof(b"THIS_IS_NOT_A_VALID_ATTESTATION_QUOTE".to_vec());
    let public_inputs = b"session_01".to_vec();

    let result = agg.verify_proof(&garbage_evidence, &public_inputs);

    assert!(result.is_ok(), "verify_proof should return Ok");
    let accepted = result.unwrap();
    assert!(
        !accepted,
        "R10.1 RED: verify_proof stub accepts malformed attestation evidence."
    );
}

#[test]
fn verify_proof_has_no_unconditional_accept() {
    let source_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");
    let source =
        std::fs::read_to_string(&source_path).unwrap_or_else(|e| panic!("Cannot read lib.rs: {e}"));

    // Find the verify_proof function body and check it does not contain
    // an unconditional Ok(true). We use the syn AST to locate the function,
    // then extract the body text by substring matching on the source.
    let file: syn::File =
        syn::parse_file(&source).unwrap_or_else(|e| panic!("Cannot parse lib.rs: {e}"));

    let body_str = find_verify_proof_body(&file, &source);

    let body_no_comments: String = body_str
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with("//") && !trimmed.starts_with("/*")
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !body_no_comments.contains("Ok(true)"),
        "R10.1 RED: verify_proof contains unconditional Ok(true) — audit finding F64. \
         See .sisyphus/design/enclave-construction.md."
    );
}

/// Locate the body text of `fn verify_proof` in the source by
/// bracketing from the function's opening brace. Returns an empty
/// string if no verify_proof is found (which falls through to the
/// assertion — an implementation with no verify_proof at all would
/// need a different test).
fn find_verify_proof_body(file: &syn::File, source: &str) -> String {
    for item in &file.items {
        if let syn::Item::Impl(impl_item) = item {
            for impl_item in &impl_item.items {
                if let syn::ImplItem::Fn(method) = impl_item {
                    if method.sig.ident == "verify_proof" {
                        // Find the `fn verify_proof` text in the source
                        let fn_start = source.find("fn verify_proof");
                        if let Some(pos) = fn_start {
                            // Find the opening brace after the function signature
                            let after_sig = &source[pos..];
                            if let Some(brace_pos) = after_sig.find('{') {
                                let body_start = pos + brace_pos + 1;
                                // Simple brace-counting to find the closing brace
                                let mut depth = 1u32;
                                let mut body_end = body_start;
                                for (i, ch) in source[body_start..].char_indices() {
                                    match ch {
                                        '{' => depth += 1,
                                        '}' => {
                                            depth -= 1;
                                            if depth == 0 {
                                                body_end = body_start + i;
                                                break;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                return source[body_start..body_end].to_string();
                            }
                        }
                        return String::new();
                    }
                }
            }
        }
    }
    String::new()
}
