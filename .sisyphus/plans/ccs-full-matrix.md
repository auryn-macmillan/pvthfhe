# Plan: Full 3-Matrix CCS for RLWE Relation

**Plan**: `ccs-full-matrix`
**Goal**: Extend the CCS satisfiability check from `(M·z) ⊙ z == 0` to the full `(M₁·z) ⊙ (M₂·z) == M₃·z` formulation, enabling correct encoding of the quadratic RLWE decryption-share relation `d_i = c·s_i + e_i`.
**Depends on**: P2B.1 (CCS over R_q infrastructure already built).

---

## Background

The single-matrix CCS `(M·z) ⊙ z == 0` can only express constraints of the form `Linear(z) * z[r] == 0`. The RLWE relation `d_i = c·s_i + e_i` requires encoding `c * s_i - cs == 0` — the product of two independent witness elements. This needs the full CCS:

```
(M₁·z) ⊙ (M₂·z) == M₃·z
```

For `a * b = c`:
- `M₁` selects `a`: row that picks `z[a_idx]`
- `M₂` selects `b`: row that picks `z[b_idx]`  
- `M₃` selects `c`: row that picks `z[c_idx]`

Result: `(M₁·z)[r] * (M₂·z)[r] == (M₃·z)[r]` → `a * b == c`.

---

## Batch T1 — Extend CCS to 3 Matrices

### T1.1 — Add M1, M2, M3 to CcsRqInstance
- [x] **File**: `crates/pvthfhe-cyclo/src/ccs_encode.rs`
- [x] **Change**: Extend `CcsRqInstance` with `m1_bytes: Vec<u8>`, `m2_bytes: Vec<u8>`, `m3_bytes: Vec<u8>` (each encodes a matrix in the existing sparse-row wire format). Keep backward-compatible: if `m2_bytes` and `m3_bytes` are empty, fall back to `(M·z) ⊙ z == 0` using `m1_bytes` as `M`.
- [x] **RED**: `ccs_full_matrix_3x3.rs` — encode `a * b = c` using 3 matrices with `z = [a, b, c, one]`. Valid witness satisfies, tampered `c` rejected. FAILS on current code (only 1-matrix available).
- [x] **GREEN**: Implement the fallback dispatch. If m2/m3 empty → use old `(M·z) ⊙ z == 0`. If all three present → use `(M₁·z) ⊙ (M₂·z) == M₃·z`.
- [x] **GATE**: `cargo test -p pvthfhe-cyclo` — all existing tests pass (old path). New 3-matrix test passes.

### T1.2 — Implement `check_satisfiability_rq_full`
- [x] **File**: `crates/pvthfhe-cyclo/src/ccs_encode.rs`
- [x] **Change**: Add new function or modify `check_satisfiability_rq` to support the 3-matrix path. For each row `r`:
  1. Compute `v1 = (M₁·z)[r]` via `mat_vec_mul_rq_row`
  2. Compute `v2 = (M₂·z)[r]` via `mat_vec_mul_rq_row`
  3. Compute `v3 = (M₃·z)[r]` via `mat_vec_mul_rq_row`
  4. Compute Hadamard: `h = ntt_mul(v1, v2)`
  5. Compute difference: `diff = ring_sub_poly(h, v3)`
  6. Assert `diff` is the zero polynomial
- [x] **GATE**: `cargo test -p pvthfhe-cyclo -- ccs_full_matrix` passes.

### T1.3 — Wire format for 3-matrix CCS instances
- [x] **File**: `crates/pvthfhe-cyclo/src/ccs_encode.rs`
- [x] **Change**: Update `encode_rq_instance` and `decode_rq_instance` to handle the 3-matrix format. Wire format:
  ```
  [u32 BE: num_rows][u32 BE: num_cols]
  [u32 BE: m1_len][m1_bytes...]
  [u32 BE: m2_len][m2_bytes...]   (0 = use old 1-matrix path)
  [u32 BE: m3_len][m3_bytes...]   (0 = use old 1-matrix path)
  [u32 BE: num_vars][witness_len_bytes...]
  [32B: ajtai_hash][32B: public_io_hash]
  ```
- [x] **GATE**: Encode→decode roundtrip for 3-matrix instances.

---

## Batch T2 — Encode RLWE Relation with Full CCS

### T2.1 — Rewrite `encode_rlwe_share_relation` for 3 matrices
- [x] **File**: `crates/pvthfhe-cyclo/src/ccs_rlwe.rs`
- [x] **Change**: Redesign the witness and matrices. Witness: `z = [c, s_i, e_i, d_i, one]` (5 elements, no separate `cs`). The RLWE relation `d_i = c·s_i + e_i` is encoded as:

  ```
  M₁: row 0 = [1, 0, 0, 0, 0]  → selects z[0] = c
  M₂: row 0 = [0, 1, 0, 0, 0]  → selects z[1] = s_i
  M₃: row 0 = [0, 0, -1, 1, 0] → selects -z[2] + z[3] = -e_i + d_i = d_i - e_i

  Check: (M₁·z)[0] * (M₂·z)[0] == (M₃·z)[0]
       → c * s_i == d_i - e_i
       → d_i == c·s_i + e_i   ✓
  ```

  Row 1: `M₁[1] = [0, 0, 0, 0, 1]`, `M₂[1] = [0, 0, 0, 0, 1]`, `M₃[1] = [0, 0, 0, 0, 1]` — enforces `one * one == one` (trivial sanity row, ensures non-zero Hadamard).

- [x] **GREEN**: Witness is 5 elements, matrices are 2×5. Encoding uses the 3-matrix wire format from T1.3.
- [x] **GATE**: All 9 tests in `ccs_rlwe_relation.rs` pass:
  - `valid_rlwe_share_satisfies` — GREEN
  - `zero_ciphertext_still_satisfies` — GREEN
  - `multiple_valid_parties` — GREEN
  - `tampered_ciphertext_rejected` — GREEN (c'*s_i ≠ d_i - e_i)
  - `tampered_secret_key_rejected` — GREEN (c*s_i' ≠ d_i - e_i)
  - `tampered_error_poly_rejected` — GREEN (c*s_i ≠ d_i - e_i')
  - `tampered_decryption_share_rejected` — GREEN (c*s_i ≠ d_i' - e_i)
  - `tampered_one_rejected` — GREEN (tampered `one` breaks row 1)
  - `accepts_encoded_witness` — GREEN (wire format roundtrip)

### T2.2 — Bump wire format version
- [x] **File**: `crates/pvthfhe-cyclo/src/lib.rs`
- [x] **Change**: Bump `CCS_WIRE_VERSION` from 1 to 2 (or add new variant). Existing 1-matrix instances at version 1 remain parseable via the backward-compatible fallback.
- [x] **GATE**: Version 1 instances still parse. Version 2 instances parse with 3 matrices.

---

## Verification

- [x] `cargo build -p pvthfhe-cyclo` clean
- [x] `cargo test -p pvthfhe-cyclo` — ALL tests pass (existing 63+ plus new 3-matrix tests)
- [x] `cargo test -p pvthfhe-cyclo -- ccs_rlwe_relation` — all 9 tests GREEN
- [x] No new `#[allow(...)]`
