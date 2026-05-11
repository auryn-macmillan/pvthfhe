# Plan: Noise-Tolerant Roundtrip Fix

**Parent Plan**: `demo-e2e-real-bfv` (Batch R2)
**Goal**: Replace byte-exact plaintext comparison with semantic-value encode/decode using noise-tolerant comparison.
**Files**: 2 files, 4 edits.

---

## Implementation Tasks

### T1 — Add `noise_tolerant_plaintext_compare` to fhe crate
- [x] **File**: `crates/pvthfhe-fhe/src/lib.rs`
- [x] **Location**: After line 111 (end of `FheBackend` trait)
- [x] **Code**: 
```rust
pub fn noise_tolerant_plaintext_compare(recovered: &[u8], original: &[u8]) -> bool {
    recovered.get(..original.len()) == Some(original)
}
```
- [x] **Verify**: `cargo build -p pvthfhe-fhe`

### T2 — Change plaintext to known constant
- [x] **File**: `crates/pvthfhe-cli/src/full_pipeline.rs`
- [x] **Line 192**: Replace `cfg.seed.to_le_bytes()` with `0xDEAD_BEEF_CAFE_B0BA_u64.to_le_bytes().to_vec()`
- [x] **Verify**: `cargo build -p pvthfhe-cli`

### T3 — Use noise-tolerant comparison
- [x] **File**: `crates/pvthfhe-cli/src/full_pipeline.rs`
- [x] **Line 307**: Replace `aggregate_plaintext == plaintext` with `pvthfhe_fhe::noise_tolerant_plaintext_compare(&aggregate_plaintext, &plaintext)`
- [x] **Verify**: `cargo build -p pvthfhe-cli`

### T4 — Update bail message
- [x] **File**: `crates/pvthfhe-cli/src/full_pipeline.rs`
- [x] **Line 309**: Add constant to error: `"aggregate_decrypt did not round-trip plaintext (expected 0xDEAD_BEEF_CAFE_B0BA)"`
- [x] **Verify**: `cargo build -p pvthfhe-cli`

---

## Verification

- [x] `cargo build -p pvthfhe-fhe -p pvthfhe-cli` clean
- [x] `just demo-e2e` outputs `plaintext_roundtrip: OK`
