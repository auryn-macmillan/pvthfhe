# NTT Protocol Migration — Execution Log

## 2026-05-23 Attempt #1 (T1-T8 executed)

### What worked
- `ntt_split` + `ntt_recover` + `ntt_recover_with_points` added to fhe.rs shamir.rs ✅
- `generate_secret_shares_from_poly` switched to `ntt_split` ✅
- `decrypt_from_shares` switched to NTT recovery ✅
- [patch] section in Cargo.toml resolved fhe version conflicts ✅
- Full build clean ✅
- All unit tests pass ✅

### What failed
- `demo-e2e 5 2 1` → `aggregate_decrypt did not round-trip plaintext`
- Root cause: NTT split generates shares at domain points (ω^k), but downstream
  `aggregate_collected_shares` → `sk_poly_sum` → `partial_decrypt` chain
  accumulates these shares and uses them for decryption. The aggregated
  `sk_poly_sum` from NTT shares differs from Horner shares, producing wrong
  partial decryption values.

### Why recovery changes didn't help
- Even with correct domain-point-aware recovery, the `sk_poly_sum` changes
  because the underlying share values changed. The decryption uses `sk_poly_sum`
  directly (not via Lagrange recovery), so wrong `sk_poly_sum` → wrong decryption.

### What's needed to complete
- Either: ALL share-generation paths must use NTT simultaneously (not just
  `generate_secret_shares_from_poly` but also the DKG deal path)
- Or: NTT must preserve the original evaluation point semantics (not possible
  with standard NTT — requires chirp Z-transform at [1..n], which is O(n²))
- Recommendation: use NTT for the `compute_party_sk_sums` parallel precomputation
  only, storing shares in coefficient form (not evaluation form), so downstream
  aggregation is unaffected.

### Reverted changes
- All fhe.rs changes reverted to maintain clean state
- ntt_shamir.rs module preserved (tested, correct)
- [patch] section removed from Cargo.toml (no longer needed)
