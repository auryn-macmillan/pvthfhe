# Learnings — demo-e2e-real-crypto (S4.1, S4.2)

## S4.1: Demo E2E Verification
- `just demo-e2e` ran successfully with n=10, t=4, seed=1
- All 9 steps completed: keygen → nizk_prove (10) → nizk_verify (90) → pvss_share_encrypt → cyclo_fold → compressor_prove → compressor_verify → partial_decrypt (4) → aggregate_decrypt
- Final output: `demo complete: ACCEPT`, `verify: ACCEPT`, `plaintext_roundtrip: OK`
- All warnings are pre-existing (mock backend, missing docs, deprecated structs) — no new warnings introduced

## S4.2: Backend ID Replacement
- `main.rs` L300 (was L296): Replaced hardcoded `"cyclo-rlwe-t10-lemma9-heuristic"` with `CYCLO_P2_BACKEND_ID` constant imported from `pvthfhe_cyclo` (aliased to avoid conflict with P1 `CYCLO_BACKEND_ID` from `pvthfhe_fhe::real_nizk`)
- `main.rs` L301 (was L297): Replaced hardcoded `"ultra-honk-micronova"` with `compressor_backend_id()` from `pvthfhe_cli::compressor_glue`
- Both `info!` and `println!` calls updated consistently

## Active Backend IDs (verified in demo output)
| Phase | Backend | ID String |
|-------|---------|-----------|
| P1 (NIZK) | Cyclo Ajtai | `cyclo-ajtai-d2-conditional` |
| P2 (Fold) | Cyclo RLWE T10 | `cyclo-rlwe-t10-lemma9-heuristic` |
| P3 (Compress) | Sonobe Nova | `sonobe-nova-bn254-grumpkin` |
| PVSS | Lattice PVSS BFV | `lattice-pvss-bfv-d2` |

## Caveats Encountered
- `pvthfhe_cyclo::CYCLO_BACKEND_ID` and `pvthfhe_fhe::real_nizk::CYCLO_BACKEND_ID` have the same name but different values (`"cyclo-rlwe-t10-lemma9-heuristic"` vs `"cyclo-ajtai-d2-conditional"`). Had to alias the cyclo import as `CYCLO_P2_BACKEND_ID`.
- `compressor_backend_id()` requires feature gate `#[cfg(all(feature = "with-fhe", feature = "sonobe-compressor"))]` to match the `run_demo` function's gate — otherwise it's undefined.
- `compressor_glue` module is in the CLI crate itself (accessible via `pvthfhe_cli::compressor_glue`), not an external crate.
