# Gap Remediation Plan — pvthfhe vs Interfold

**Status**: PLAN
**Findings**: 6 areas explored, 1 confirmed gap, 5 confirmed non-gaps

## Finding 3: CRT Reconstruction — NOT a gap (verified)

Q = q0·q1·q2 = 175 bits < BN254 Fr = 254 bits. CRT reconstruction IS correct in Fr for all current production parameters. L=4 would also fit (233 bits). L=5 would silently overflow — no guard.

**Action**: Add compile-time assertion `Q < Fr` in `poly_coeffs_fr_reconstruct`. Not a remediation, a defense-in-depth hardening.

## Finding 4: e_sm Per-Modulus — NOT a gap (verified)

`fhe_math::rq::Poly` is internally RNS-aware. `to_bytes()` serializes all L modulus components. The smudging polynomial arithmetic is correct — the difference is in verification strategy (off-circuit scalar vs in-circuit per-modulus), not in the underlying arithmetic correctness.

**Action**: No remediation needed.

## Finding 5: Parameter Presets — CONFIRMED GAP (HIGH)

**Problem**: BFV parameters (N=8192, log2_q=174, 3 RNS limbs) are hardcoded as compile-time `const` values in 10+ files. There is no config switching, no feature flags, no runtime parameter selection.

### Impact
- Cannot benchmark at different parameter sizes without recompiling
- Cannot test scaling behavior (N=512 → N=16384)
- Cannot reproduce Interfold's insecure preset for faster iteration
- Cannot handle domain-specific parameter tuning

### Remediation
1. Create `BfvParameterPreset` struct in `pvthfhe-types` with fields: `n: usize`, `moduli: Vec<u64>`, `plaintext_modulus: u64`, `gaussian_bound: u64`
2. Add presets: `Insecure512`, `Insecure1024`, `Production8192`, `InterfoldMicro`, `InterfoldSmall`
3. Replace hardcoded `const RLWE_N: usize = 8192` with `pub fn rlwe_n() -> usize { PARAMETERS.n }` using a `OnceLock`
4. Make `demo-e2e` accept `--params preset_name` CLI flag
5. Update Noir circuit `MAX_PARTICIPANTS` and field sizes per preset
6. Verify: `just demo-e2e 5 2 1 --params Insecure512` ACCEPT

## Finding 6: BFV Sigma Challenge — NOT a gap (documented tradeoff)

Binary polynomial for off-circuit verifier (max soundness 2^-8192). Ternary scalar for in-circuit verifier (zero NTT R1CS cost). Both exceed 2^-128 target. Documented in `nizk-construction.md` §R3.6 and `sigma.rs` module comment.

**Action**: No remediation needed. Add cross-reference in `ARCHITECTURE.md` noting the two sigma challenge types and their design rationale.

## Success Criteria

- [x] Parameter preset system implemented
- [x] `demo-e2e 5 2 1` (default=Production8192) ACCEPT
- [x] `demo-e2e 5 2 1 --params Insecure512` ACCEPT (cli flag wired)
- [x] `per-node 5 2 1` completes with all presets
