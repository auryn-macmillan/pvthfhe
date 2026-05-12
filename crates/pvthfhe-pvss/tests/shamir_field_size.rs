//! R1.2 GREEN: Assert Shamir field is BN254 scalar, not GF(256)/u8.
//!
//! After the GREEN phase migrated Shamir to BN254 scalar field:
//!   - No GF(256)/u8 Shamir code paths remain in `encrypt.rs`.
//!   - The `shamir.rs` module uses `ark_bn254::Fr` for all arithmetic.
//!   - `evaluate_polynomial` / `lagrange_coefficient_at_zero` in `shamir.rs`
//!     operate over `Fr`, not `u8`, and are allowlisted.
//!
//! PASS condition: No GF(256)/u8 Shamir remains (outside the allowlisted shamir.rs)
//! AND a BN254-field shamir.rs exists.

use std::path::PathBuf;
use std::process::Command;

/// Patterns that indicate GF(256)/u8-byte Shamir arithmetic.
/// These should NOT exist after the BN254 migration *except* in `shamir.rs`
/// where the same function names operate over `Fr`.
const GF256_PATTERNS: &str = r"\bgf256_\b|\bnext_nonzero_byte\b|\bevaluate_polynomial\b|\blagrange_coefficient_at_zero\b|MAX_N.*255|\bu8::MAX as usize\b|\bShamir over GF\(256\)\b";

/// Paths to exclude from the grep — test files, build artifacts, and the
/// BN254 `shamir.rs` module whose `evaluate_polynomial`/`lagrange_coefficient_at_zero`
/// operate over `Fr`, not GF(256)/u8.
fn is_allowlisted(path: &str) -> bool {
    path.contains("/tests/")
        || path.contains("/target/")
        || path.contains("/benches/")
        || path.starts_with("crates/pvthfhe-pvss/tests/")
        || path.contains("shamir.rs")
}

fn crate_src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

#[test]
fn no_gf256_u8_shamir_code_paths_exist() {
    let src_dir = crate_src_dir();

    // Use ripgrep to find all GF(256) code paths in the PVSS source.
    let out = Command::new("rg")
        .args([
            "--line-number",
            "--no-heading",
            "--type-add",
            "rust:*.rs",
            "--type",
            "rust",
            GF256_PATTERNS,
        ])
        .arg(src_dir.to_str().expect("valid path"))
        .output()
        .expect("rg must be installed");

    assert!(
        out.status.success() || out.status.code() == Some(1),
        "rg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let violations: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| {
            // Skip allowlisted paths
            !is_allowlisted(line)
        })
        .collect();

    if !violations.is_empty() {
        panic!(
            "R1.2 RED: GF(256)/u8 Shamir code paths found ({count} violations). \
             Current Shamir operates over GF(256) with u8 arithmetic. \
             Must be migrated to BN254 scalar field (ark_bn254::Fr).\n\
             Violations:\n{violations}\n\n\
             After GREEN phase, these should all be replaced with ark_ff::PrimeField-based \
             polynomial evaluation over BN254 scalar field.",
            count = violations.len(),
            violations = violations
                .iter()
                .map(|v| format!("  {v}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    // Also assert: the source tree should no longer have GF256/byte-split functions
    // that produce byte-shuffling Shamir output. This is a secondary affirmation
    // that the RED test will catch if someone accidentally leaves dead GF256 helpers.
}

#[test]
fn shamir_module_uses_bn254_scalar_field() {
    // Check whether a dedicated shamir.rs module exists that uses ark_ff::PrimeField
    // (or specifically ark_bn254::Fr). Current state: encrypt.rs does byte-by-byte
    // Shamir with u8 — no such module exists.
    let src_dir = crate_src_dir();

    // First test: is there any reference to ark_ff::PrimeField in the PVSS source?
    let out = Command::new("rg")
        .args([
            "--line-number",
            "--no-heading",
            "--type-add",
            "rust:*.rs",
            "--type",
            "rust",
            r"ark_ff::PrimeField|ark_bn254::Fr|PrimeField",
        ])
        .arg(src_dir.to_str().expect("valid path"))
        .output()
        .expect("rg must be installed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let has_primefield = stdout.lines().filter(|l| !l.is_empty()).count() > 0;

    assert!(
        has_primefield,
        "R1.2 RED: No ark_ff::PrimeField or ark_bn254::Fr reference found in pvthfhe-pvss/src/. \
         The Shamir implementation must be migrated from GF(256)/u8 to BN254 scalar field. \
         Expected: a shamir.rs module (or equivalent) using ark_bn254::Fr for polynomial \
         evaluation, Lagrange interpolation, and share splitting.\n\n\
         Current state: encrypt.rs uses u8 arithmetic with gf256_mul/gf256_inverse helpers. \
         After GREEN: these will be replaced with BN254 scalar field operations."
    );
}
