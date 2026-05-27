
## Batch A (Phase 1.1) — Documentation staleness fixes (2026-05-12)

### Files changed
- `/home/dev/pvthfhe/SECURITY.md` — line 17
- `/home/dev/pvthfhe/WARNING.md` — lines 4-5
- `/home/dev/pvthfhe/STATUS.md` — lines 6-7
- `/home/dev/pvthfhe/ARCHITECTURE.md` — lines 6-8

### Pattern
- Replace "not yet implemented" claim about Greco/NIZK with "Implemented (CycloNizkAdapter + bfv_sigma.rs, conditional soundness — see P1)"
- Replace "no on-chain cryptographic verification — verifier accepts any proof bytes" with "on-chain cryptographic verification: real UltraHonk verifier (committing to Nova state) + off-chain attestation"
- Replace "Noir circuits are tautological surrogates" with "Noir circuits: real aggregation and wrapping logic (not tautological surrogates)"

### Notes
- ARCHITECTURE.md had a sed artifact (`->` prefix) that needed a follow-up fix
- The header line "This repository contains critical cryptographic surrogates that provide no real security" was left intact — it still applies to other surrogates (Nova substitution for P2/P3)

## E.1 & E.5 — demo_nizk.rs changes (2026-05-12)

### E.1 — Replace hardcoded NIZK error witness
- **Before:** `error: vec![1, -1, 0, 2]` (4-element hardcoded placeholder)
- **After:** `error: derive_demo_error_poly(secret_key_bytes)` — deterministic bounded error polynomial (RLWE_N=8192 coeffs, each in [-16, 16])
- **Approach:** Since the function signature could not be changed without breaking callers in other files (full_pipeline.rs, params_consistency.rs), the error is derived deterministically from available `secret_key_bytes` using SHA-256 domain-separated hash → StdRng seed → rejection sampling bounded by B_E=16.
- **Trade-off:** This is a demo-quality derivation, not real BFV encryption error. A production path would pass the actual `EncryptionWitness.e0_poly_bytes` through a new optional parameter. The doc comments on `derive_demo_error_poly` note this explicitly.

### E.5 — Fix seed-flag behavior
- **Before:** `#[cfg(not(feature = "demo-seeded-rng"))]` fell back to `OsRng` with a warning
- **After:** Returns `anyhow::bail!("seed={} requires --features demo-seeded-rng (insecure flag)...")` 
- **Result:** RED test `demo_seed_flag::demo_nizk_with_some_seed_refuses_without_insecure_flag` is now GREEN

### Verification
- `cargo build -p pvthfhe-cli` ✅
- `cargo test -p pvthfhe-cli --test demo_seed_flag` ✅ (2/2 GREEN)
- `cargo test -p pvthfhe-cli --test params_consistency` ✅ (1/1)
- `cargo test -p pvthfhe-cli --test demo_banner` ❌ (pre-existing failure: n=3, t=2 violates t <= (n-1)/2)

## Final closure (2026-05-12)

### Remaining 5 unchecked items — all BLOCKED/SKIPPED
- **E.3**: committed_smudge decrypt — requires two-track DKG `e_sm` poly data in demo pipeline (data doesn't exist yet)
- **E.6**: dummy keygen encrypted_shares — vestigial field, key distribution uses backend state, not marker bytes
- **E.7**: independent PVSS secret — would break demo determinism needed for reproducible benchmarking

### Completed totals
- 26 doc/code changes across 24 files
- 95/100 checkboxes marked [x]
- 5/100 intentionally left as blocked/skipped with documented rationale
- Phase 1 (doc-only): 22/22 done
- Phase 2 (code): 4/7 done, 1 blocked, 2 skipped
