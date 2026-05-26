
## G.15: crt_reconstruct_coeffs overflow → error propagation (2026-05-18)

**Change**: Changed `crt_reconstruct_coeffs` return type from `Vec<i128>` to `Result<Vec<i128>, FheError>`.

**Rationale**: Security review finding C.5 — CRT-reconstructed coefficients can legitimately exceed i128 range (Q ≈ 2^174 > i128::MAX ≈ 2^127-1). The previous `i128::MAX` sentinel made overflow values indistinguishable from real MAX values.

**Details**:
- At line 1418: `None => coeffs.push(i128::MAX)` replaced with `None => return Err(FheError::Backend { reason: "CRT coefficient exceeds i128 range at index {i}" })`
- Only caller was `c7_coefficient_check.rs` test (no production callers of this function found)
- `poly_coeffs_fr_reconstruct` and `aggregate_decrypt_raw_result_poly` have their own independent CRT implementations (not affected)
