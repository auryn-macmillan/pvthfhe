# Scheme-Switch Fix + TFHE Boolean Operations

**Status**: PLAN
**Date**: 2026-05-31
**Branch**: `feat/poulpy-threshold`

## Part 1: Fix Scheme-Switch R1CS Bug (~2 hrs)

### Issue
The `SchemeSwitchStepCircuit` Nova IVC verify silently fails with `Relaxed R1CS is unsatisfiable`. The prove path works but verify doesn't.

### Root cause (likely)
The `synthesize` method allocates witnesses with fixed constraint counts, but the R1CS shape built during `PublicParams::setup` may differ. The circuit uses:
- `AllocatedNum::alloc_input` for ckks/tfhe values
- `cs.enforce` for the equivalence constraint `ckks * (1 - tfhe) = 0`

During setup the thread-local is empty → 0 constraints. During prove the thread-local is populated → 3 constraints. Mismatch.

### Fix
Ensure `SCHEME_SWITCH_DATA` is populated BEFORE `NovaCompressor::new()` (same fix as P3). Set dummy data matching the expected shape.

**File**: `crates/pvthfhe-cli/src/main.rs`, `run_poulpy_all_demo`, before `SSCircuit::new()` call

### Verify
- `cargo test -p pvthfhe-compressor -- scheme_switch::tests` — 6/6 pass
- `just poulpy-all` — scheme_switch_verified: ACCEPT

## Part 2: TFHE Boolean Operations (~3 hrs)

### Current state
Only `NAND` is implemented via `tfhe_nand()` in `tfhe_ops.rs`.

### Operations to add

| Gate | LWE formula | Implementation |
|------|------------|----------------|
| **NOT(a)** | 1 - a (mod 2) | Encode: `NOT(0)=1`, `NOT(1)=0`. Use `NAND(a,a)` — NAND(a,a) = NOT(a AND a) = NOT(a). One NAND call. |
| **AND(a,b)** | a · b (mod 2) | AND = NOT(NAND) = NAND(NAND(a,b), NAND(a,b)). Two NAND calls. |
| **OR(a,b)** | a + b - a·b (mod 2) | NAND(NOT(a), NOT(b)). Three NAND calls. |
| **XOR(a,b)** | a + b (mod 2) | Four NAND gates via standard circuit. |

Since Poulpy's LWE bootstrapping supports NAND as the base gate, all others are compositions. We implement:
1. `tfhe_not(ct) -> Ciphertext` — `glwe_to_lwe_nand(ct, ct)`
2. `tfhe_and(ct_a, ct_b) -> Ciphertext` — `tfhe_not(tfhe_nand(ct_a, ct_b))`
3. `tfhe_or(ct_a, ct_b) -> Ciphertext` — `tfhe_nand(tfhe_not(ct_a), tfhe_not(ct_b))`
4. `tfhe_xor(ct_a, ct_b) -> Ciphertext` — 4-NAND network

### Files
- `crates/pvthfhe-fhe-poulpy/src/poulpy_backend_impl/tfhe_ops.rs` — add gate functions
- `crates/pvthfhe-fhe-poulpy/src/poulpy_backend_impl/mod.rs` — wire into PoulpyBackend
- `crates/pvthfhe-cli/src/main.rs` — add gate demo to poulpy-all (replace single NAND with multiple gates)

### Verify
- `cargo test -p pvthfhe-fhe-poulpy -- tfhe` — all gate roundtrips pass
- `just poulpy-all` — TFHE phase shows multiple gate operation results

## Tasks

### Part 1
- [ ] Fix scheme-switch R1CS by pre-populating SCHEME_SWITCH_DATA before compressor
- [ ] Verify 6/6 scheme_switch tests pass
- [ ] Verify `just poulpy-all` scheme_switch_verified: ACCEPT

### Part 2
- [ ] Implement tfhe_not, tfhe_and, tfhe_or, tfhe_xor in tfhe_ops.rs
- [ ] Wire into PoulpyBackend dispatch
- [ ] Add multi-gate demo to poulpy-all Phase 4
- [ ] Verify all gate roundtrips pass

## Success Criteria
- [ ] `cargo check` zero errors
- [ ] Scheme-switch: `scheme_switch_verified: ACCEPT`
- [ ] TFHE gates: NOT, AND, OR, XOR all produce correct boolean results
- [ ] `just poulpy-all` completes all phases
