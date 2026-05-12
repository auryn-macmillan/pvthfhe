## T1 Implementation — 2026-05-11

### Architecture Decisions

1. **Struct design**: Kept `matrix_data` for backward compat with `ccs_rlwe.rs` and existing
   tests, added `m1_bytes`, `m2_bytes`, `m3_bytes` as new fields. The `check_satisfiability_rq`
   function auto-detects mode by checking if `m2_bytes`/`m3_bytes` are non-empty.

2. **Wire format**: Interleaved length-data pairs `[m1_len][m1_bytes][m2_len][m2_bytes]...`
   NOT all-lengths-then-all-data. The decode function reads each pair in sequence.

3. **ccs_rlwe.rs modification**: Added `m1_bytes: Vec::new(), m2_bytes: Vec::new(), m3_bytes: Vec::new()`
   to the struct literal — mechanical T1 consequence, not T2 logic change.

4. **ring_sub**: Added local `ring_sub` function using negation + `ring_add_poly`. Uses `Q_COMMIT`
   (imported from ring module).

### Test Coverage

- Unit: `encode_decode_rq_roundtrip` (1-matrix, backward compat), `encode_decode_rq_three_matrix_roundtrip` (3-matrix)
- Integration: `ccs_full_matrix_3x3.rs` with `a*b=c` (valid + tampered-c)
- All 7 existing `ccs_rq_satisfiability` tests pass (backward compat verified)
- 3 RLWE relation tests are pre-existing RED (ccs_rlwe_relation.rs is untracked on this branch)

### Dispatch Logic

```rust
let has_three_matrices = !instance.m2_bytes.is_empty() || !instance.m3_bytes.is_empty();
if has_three_matrices {
    // Validate all three matrices present, delegate to check_three_matrix_rq
} else {
    // Old path: M·z ⊙ z == 0 using matrix_data
}
```

### Wire Format

New: `[num_rows:u32][num_cols:u32][m1_len:u32][m1_bytes][m2_len:u32][m2_bytes][m3_len:u32][m3_bytes][num_vars:u32][witness: ...][ajtai_hash:32][public_io_hash:32]`

Backward compat: `encode_rq_instance` uses `matrix_data` as `m1_bytes` when `m1_bytes` is empty.
`decode_rq_instance` populates `matrix_data` when `m2_len == 0 && m3_len == 0`.

### Imports Added

- `Q_COMMIT` from `crate::ring` (needed for `ring_sub` negation)

## T2 Implementation — 2026-05-11

### ccs_rlwe.rs Rewrite

1. **Witness simplification**: Reduced from 7 elements `[c, s_i, e_i, d_i, cs, residual, one]`
   to 5 elements `[c, s_i, e_i, d_i, one]`. The `cs` (c·s_i) and `residual` are no longer
   needed as separate witness entries — the 3-matrix CCS encodes the relation directly.

2. **Matrix encoding**:
   - M₁ (2×5): Row 0 selects `c`, Row 1 selects `one`
   - M₂ (2×5): Row 0 selects `s_i`, Row 1 selects `one`
   - M₃ (2×5): Row 0 selects `d_i - e_i`, Row 1 selects `one`
   - Row 0 enforces: `c · s_i == d_i - e_i` → `d_i == c·s_i + e_i` ✓
   - Row 1 enforces sanity: `one · one == one` (idempotence)

3. **Backward compatibility**: `matrix_data` field set to `Vec::new()` — the 3-matrix data
   goes into `m1_bytes`, `m2_bytes`, `m3_bytes`. `check_satisfiability_rq` auto-detects
   the 3-matrix mode when those fields are non-empty.

4. **party_id handling**: Unchanged — still used for `ajtai_hash` and `public_io_hash` SHA-256
   derivation. Not part of the constraint system.

5. **Removed functions**: `ring_sub()` — no longer needed since the relation is fully
   encoded in the 3-matrix CCS.

### CCS_WIRE_VERSION

Added `pub const CCS_WIRE_VERSION: u32 = 2;` to `lib.rs`. V1 = 1-matrix (legacy),
V2 = 3-matrix (full CCS). Epochs: V1 starts at the project origin; V2 starts 2026-05-11.

### Test Updates

6. **tampered_residual_rejected**: Changed witness[4] tampering from `one_poly()` to
   `random_poly(&mut rng)`. In V2 layout, index 4 is `one` (not `cs`/`residual`).
   A random polynomial breaks the sanity row (random·random ≠ random) with overwhelming
   probability ≈ 1 - (1/q)^256.

7. **deterministic_encoding**: Added assertions for `m1_bytes`, `m2_bytes`, `m3_bytes`
   determinism alongside existing `matrix_data` check.

### Test Results

- All 9 ccs_rlwe_relation tests: ✅ PASS
- All 3 ccs_encode unit tests: ✅ PASS (backward compat)
- All 2 ccs_full_matrix_3x3 tests: ✅ PASS
- All 7 ccs_rq_satisfiability tests: ✅ PASS (backward compat)
- Full test suite (minus forgery_resistance): 100% pass rate, no regressions
