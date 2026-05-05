# Stage 1 Finding Disposition Matrix
Generated: 2026-05-05

## Critical Findings (C-class)

| ID  | Description | Disposition | Evidence | Residual Risk |
|-----|-------------|-------------|----------|---------------|
| C2  | Tautological Noir circuits (assert(x == x) — no real constraints) | Fixed | T2: circuits/pvthfhe/src/main.nr — real Ajtai/norm constraints | Low |
| C3  | fold.rs SHA-256 hash chain masquerading as Ajtai folding; norm is byte-max | Fixed | T1: crates/pvthfhe-cyclo/src/fold.rs — real lattice Ajtai folding | Low |
| C4  | NIZK Fiat-Shamir does not absorb pvss_commitment before challenge | Fixed | T3: crates/pvthfhe-nizk/src/fiat_shamir.rs — pvss_commitment absorbed | Low |
| C5  | Threshold downgrade: any 1≤t≤n accepted without enforcement | Fixed | T4: on-chain (n,t) registry with t > n/2 enforcement | Low |
| C6  | Forged-share threshold collapse via composition | Fixed | T5/T6: forged-share rejection + decrypt_share circuit constraints | Low |

## High-Severity Findings (H-class)

| ID  | Description | Disposition | Evidence | Residual Risk |
|-----|-------------|-------------|----------|---------------|
| H1  | Folding layer was a simulation (SHA-256 hash chain, no cryptographic binding) | Fixed | T1: crates/pvthfhe-cyclo/src/fold.rs replaced with real Ajtai accumulator using fhe-math ring ops | Low |
| H2  | Noir circuits contained unconstrained hash operations (tautological assertions) | Fixed | T2: circuits/pvthfhe reauthored with real norm-bound constraints and Ajtai witness checks | Low |
| H3  | Fiat-Shamir transcript missing pvss_commitment binding (malleability vector) | Fixed | T3: crates/pvthfhe-nizk/src/fiat_shamir.rs absorbs pvss_commitment before challenge derivation | Low |
| H4  | On-chain verifier accepted arbitrary (n,t) without registry or replay protection | Fixed | T4: contracts registry enforces t > n/2, replay nonce stored per session | Low |
| H5  | Forged shares bypassed threshold check via scalar verdict collapse | Fixed | T5: crates/pvthfhe-fhe forged-share rejection tests pass; adversarial test suite green | Low |
| H6  | decrypt_share circuit lacked range/norm constraints allowing malformed witness | Fixed | T6: circuits/pvthfhe decrypt_share constraints added; RED→GREEN test pair in place | Low |
| H7  | Hermine simulation layer was active in production code path | Fixed | T7: Hermine simulation removed; real PVSS backend wired; PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK opt-in preserved for test path only | Low |
| H8  | Norm-bound checks used byte-max heuristic instead of lattice security parameter | Fixed | T8: crates/pvthfhe-nizk/src/ajtai.rs norm bound derived from security parameter; test vectors confirm rejection above bound | Low |

## Summary

All H1–H8 findings are **Fixed**. No Deferred deployment-relevant Highs remain.
Stage 0 T2 tripwire (`cargo:warning=SURROGATE ACTIVE` in build.rs) preserved.
Stage 0 T3 mock opt-in (`PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK`) preserved.
