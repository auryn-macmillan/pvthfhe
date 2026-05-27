## RED-1 (error_display)
Test file: crates/pvthfhe-pvss/tests/error_display.rs
Status: RED as expected — Display prints "PVSS backend error" without inner string.
## RED-2 (context_too_large)
Test file: crates/pvthfhe-pvss/tests/context_too_large.rs
Status: RED as expected — current message does not contain "255"/"GF(256)"/"Shamir".
LatticePvssBfvAdapter constructor: LatticePvssBfvAdapter::new() -> Result<Self, PvssError> (confirmed in crates/pvthfhe-pvss/src/encrypt.rs).
## 2026-05-07 — D1 PVSS backend display

- `PvssError::BackendError` now formats as `PVSS backend error: {inner}` so downstream errors keep their context.
- The focused `error_display` test passes after this change.
## 2026-05-07
- `validate_context` in `pvthfhe-pvss` now returns a cap-specific error when `n > 255`, naming both the 255 limit and the Shamir over GF(256) rationale.
- The targeted `context_too_large` test passes once the error string includes both the offending `n` and the supported-party cap.
## 2026-05-07 — RED-3 demo n-cap test scaffold

- Added `crates/pvthfhe-cli/tests/demo_n_cap.rs` to exercise `cargo run -p pvthfhe-cli -- demo --n 256 --threshold 129 --seed 1` without `nova-compressor`.
- The test checks for non-success exit, mentions the `255` cap, and rejects `step 4/9` in stderr.

## 2026-05-07 — D2 part 2 demo n-cap guard

- `run_demo` now rejects `n == 0` and `n > 255` before threshold validation, surfacing the Shamir over GF(256) cap directly.
- The CLI `Demo` doc comment now says `Number of parties (maximum 255).`
- `demo_n_cap` and `demo_threshold` both pass after the change.

## 2026-05-07 — D5 docs update

- `Justfile` `demo-e2e` now advertises the supported range inline: `1 ≤ t ≤ n ≤ 255 (Shamir over GF(256))`.
- `README.md` `just demo-e2e` guidance now notes the `n ≤ 255` cap.
## 2026-05-07 — D4 bench fixture witness bytes

- Both bench fixtures (`bench_scaling.rs` and `gen_goldens.rs`) now use the same stub witness bytes as the working pipeline: `vec![1u8; 32]`.
- `cargo build -p pvthfhe-bench --release --bins` and `cargo test -p pvthfhe-bench` both pass after the substitution.
