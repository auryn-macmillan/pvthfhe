# Learnings - G.12 Schnorr Signatures (Task 3)

## What was done
- Wired Schnorr signing keypairs + per-share signing into `pvthfhe-cli/src/full_pipeline.rs`
- Added 3 new fields to `PipelineReport`: `party_signing_pks`, `share_sig_rs`, `share_sig_ss` (all `Vec<Fr>`)
- Signing happens immediately after `share_coeffs` are collected (before CRT reconstruction)

## Patterns / Conventions
- PipelineReport fields use `G.xx` gap-reference tags in docstrings (consistent with G.3, G.4, G.16)
- G1Affine x-coordinates serialized to Fr via `AffineRepr::x()` → `into_bigint().to_bytes_le()` → `Fr::from_le_bytes_mod_order`
- Share data hashed with SHA-256 before signing (Poseidon arity limits prevent direct hashing of 24576 values)

## Dependencies added
- `ark-ec = "0.5"` to `pvthfhe-cli/Cargo.toml` (needed for `AffineRepr::x()`)
- `use pvthfhe_nizk::schnorr;` import
- `use ark_ec::AffineRepr;` import

## Verification
- `cargo check -p pvthfhe-cli` passes with no new warnings

## Task 4 (2026-05-19): build_c7_prover_toml integration

### What was done
- Added 3 new parameters to `build_c7_prover_toml`: `party_signing_pks: &[Fr]`, `share_sig_rs: &[Fr]`, `share_sig_ss: &[Fr]`
- Wrote Prover.toml entries for each: `party_signing_pks` (public inputs), `share_sig_rs` and `share_sig_ss` (private witness inputs)
- Updated all 3 callers: main pipeline (passes local variables), test (passes empty slices), e2e binary (passes report fields)
- All fields serialized as hex via `field_hex_be()` (consistent with existing Prover.toml format)

### Patterns / Conventions
- `field_hex_be(value: Fr) -> String` returns big-endian hex with `0x` prefix
- Arrays written as `"0x{hex}"` elements in TOML
- Empty slices (`&[]`) used for test callers that lack Schnorr data
- Specification traceability via G.12 tags on parameters and code blocks

### Verification
- `cargo check -p pvthfhe-cli` passes with no errors
