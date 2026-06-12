# G-N8 + C2 Resolution Plan

**Date**: 2026-06-08
**Status**: DRAFT — awaiting Momus review
**Source**: MPC audit v3 — two remaining circuit-level gaps after P4 fix

---

## Problem Statement

Two circuit-level gaps remain after the P4 fix (verifyWithIvc now verifies UltraHonk proof):

1. **G-N8 decrypt_share**: Circuit times out at N=8192 due to per-coefficient range checks
   (O(N) loops × 3 constraint types). aggregator_final already compiles at N=8192.
2. **C2 integration**: `verify_c2_bfv_encryption()` function exists but is not wired
   into `main()` — needs 22 parameter additions.

---

## Fix A: G-N8 — Restructure decrypt_share for N=8192

### Root cause

`decrypt_share/src/main.nr` has per-coefficient loops that overwhelm the Noir compiler
at N=8192:

```
Lines 83-94:  range check sk_i ∈ {-1,0,1}    →  N iterations, ~2N constraints
              range check e_i ∈ [-B_E, B_E]   →  N iterations, ~3N constraints (with casting)
Lines 95-104: vector_hash (Poseidon over N+1 elements) → depends on N
Lines 113-114: eval_poly × 4 calls              →  4N constraints (Horner)
```

At N=8192, the aggregate is ~9N ≈ 73K constraints from these loops alone. The
`vector_hash` function expands to O(N) Poseidon sponge operations. Combined with
the S-Z relation and binding checks, the Noir compiler times out at 10 minutes.

**Contrast**: `aggregator_final` has 128 shares × N eval_poly calls = 1M+ constraints
but NO per-coefficient range checks (those are natively verified). It compiles
successfully.

### Fix

Move coefficient-level checks to native verification. The circuit should only verify:

1. **Algebraic relation** (Schwartz-Zippel): `eval(d_i, r) = eval(c1, r)·eval(sk_i, r) + eval(e_i, r)`
2. **Commitment binding**: each polynomial's Poseidon hash matches its public hash
3. **DKG/ciphertext/statement binding**: hash-chain consistency checks
4. **Ring identity**: `r^N + 1 ≠ 0` (the S-Z challenge point is not a ring root)

Per-coefficient range checks (`sk_i` must be ternary, `e_i` norm ≤ B_E) are
computational-ZK properties verified by the native sigma protocol verifier
(`sigma.rs:verify_multi` / `bfv_sigma.rs:verify`). They do not need in-circuit
replication.

### Concrete changes to `decrypt_share/src/main.nr`

1. Change `global N: u32 = 8;` → `global N: u32 = 8192;` (line 12)
2. Change `global LOG_N: u32 = 3;` → `global LOG_N: u32 = 13;` (line 13)
3. Remove lines 83-94 entirely (per-coefficient sk/e range checks)
4. Replace `bind_8_with_domain` with generic `bind_N_with_domain` using `[Field; N_param+1]` where N_param is 8 (the number of hash inputs, NOT the ring dimension)
5. Replace `[1, 0, 0, 0, 0, 0, 0, 0]` test fixtures with `mut arr = [0; N]; arr[0] = val; arr` pattern
6. Replace the `test_tamper_sk_out_of_range` and `test_tamper_error_out_of_bound` tests
   with a single `test_norm_bounds_checked_natively` note (or remove entirely since
   the check moves to native)

### Files changed

- `circuits/decrypt_share/src/main.nr` — N, LOG_N, remove range checks, update tests

### Tests

All 7 existing tests should pass. The 2 range-check-specific tests become n/a
(their invariant is verified natively). New test: `test_sz_evaluation_accepts_N8192`
that exercises the S-Z relation with zero-sk, zero-e, zero-c1 polynomials at N=8192.

### Verification

```bash
cd circuits && nargo compile --package decrypt_share
cd circuits && nargo test --package decrypt_share
```

---

## Fix B: C2 — Wire `verify_c2_bfv_encryption` into `main()`

### Current state

`verify_c2_bfv_encryption()` (lines 222-297 of `main.nr`) is a fully-specified function
that proves BFV encryption well-formedness in-circuit. It is NOT called from `main()`
because it requires 22 new parameters (10 pub, 12 private) and updating all 23 test
fixtures + Prover.toml files.

### Fix

Add the 22 C2 parameters to `main()`'s signature and call `verify_c2_bfv_encryption()`
at the start of the `main()` body.

The neutral fixture (all zeros) satisfies the C2 constraints vacuously
(0 = 0·0 + 0 + Δ·0). All existing tests use the neutral fixture via a helper.

### Concrete changes to `aggregator_final/src/main.nr`

1. Add C2 parameter block to `main()` signature (after line 360, before the closing `)`):
   ```
   // -- C2: BFV encryption sigma public inputs (10) --
   c2_pk0_eval: pub Field, c2_pk1_eval: pub Field,
   c2_ct0_eval: pub Field, c2_ct1_eval: pub Field,
   c2_u_eval: pub Field, c2_e0_eval: pub Field,
   c2_e1_eval: pub Field, c2_m_eval: pub Field,
   c2_recipient_pk_root: pub Field, c2_delta: pub Field,
   // -- C2: witnesses (12) --
   c2_pk0_coeffs: [Field; N], c2_pk1_coeffs: [Field; N],
   c2_ct0_coeffs: [Field; N], c2_ct1_coeffs: [Field; N],
   c2_u_coeffs: [Field; N], c2_e0_coeffs: [Field; N],
   c2_e1_coeffs: [Field; N], c2_m_coeffs: [Field; N],
   c2_pk0_commitment: Field, c2_pk1_commitment: Field,
   c2_pk_merkle_path: [Field; DEPTH], c2_pk_leaf_index: Field,
   ```

2. Add call after IVC hash guard (after line ~374, before C7 n_shares guard):
   ```
   verify_c2_bfv_encryption(
       ciphertext_hash, dkg_root, epoch, participant_set_hash,
       c2_pk0_eval, c2_pk1_eval, c2_ct0_eval, c2_ct1_eval,
       c2_u_eval, c2_e0_eval, c2_e1_eval, c2_m_eval,
       c2_pk0_coeffs, c2_pk1_coeffs, c2_ct0_coeffs, c2_ct1_coeffs,
       c2_u_coeffs, c2_e0_coeffs, c2_e1_coeffs, c2_m_coeffs,
       c2_pk0_commitment, c2_pk1_commitment,
       c2_pk_merkle_path, c2_pk_leaf_index,
       c2_recipient_pk_root, c2_delta,
   );
   ```

3. Add a `c2_neutral_fixture()` helper that returns all 22 values as a tuple
   (zero polynomials → zero evaluations → trivially satisfied constraints)

4. Update each test: destructure `c2_neutral_fixture()` once, append 22 values
   to `main()` call

### Files changed

- `circuits/aggregator_final/src/main.nr` — main() signature, C2 call, c2_neutral_fixture(), all 23 test call sites
- `circuits/protocol_constants/src/lib.nr` — DOMAIN_C2_ENCRYPTION_CHALLENGE (already added)

### Tests

All 28 existing tests must pass unchanged. The neutral fixture ensures C2 is
vacuously satisfied for non-C2 tests.

### Verification

```bash
cd circuits && nargo test --package aggregator_final  # all 28 pass
cd circuits && nargo compile --package aggregator_final
```

---

## Summary

| Fix | Nature | Circuit | Constraint impact at N=8192 | Testing |
|-----|--------|---------|---------------------------|---------|
| A | Remove range checks → S-Z only | decrypt_share | ~4N eval + hashes | nargo test |
| B | Wire C2 function into main() | aggregator_final | +8N eval + 2 Merkle paths | all 28 existing + neutral fixture |

**Total circuit constraints at N=8192** (estimated):
- aggregator_final: ~1M (existing G2) + ~67K (C2) ≈ 1.07M
- decrypt_share: ~33K (4 eval_poly calls) + hashes ≈ 40K

Both within Noir compiler capacity given that aggregator_final already compiles at 1M+.
