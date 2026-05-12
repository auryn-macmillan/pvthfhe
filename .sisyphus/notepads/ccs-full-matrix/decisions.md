## T1: 3-Matrix CCS Extension — 2026-05-11

### Decision 1: Keep `matrix_data` for backward compat
**Context**: `ccs_rlwe.rs` constructs `CcsRqInstance` with `matrix_data` and cannot be modified
(T2 task constraint).  
**Decision**: Keep `matrix_data` field alongside new `m1_bytes`, `m2_bytes`, `m3_bytes`.
In `check_satisfiability_rq`, if m2/m3 empty, use `matrix_data` (old 1-matrix path).
**Alternative considered**: Remove `matrix_data` and alias to `m1_bytes` — rejected because
it would require modifying `ccs_rlwe.rs`.

### Decision 2: Interleaved wire format
**Context**: The wire format spec uses `[m1_len][m1_bytes][m2_len][m2_bytes][m3_len][m3_bytes]`.
**Decision**: Encode each matrix as length-then-data pair. Decode reads pairs in sequence.
**Alternative considered**: All lengths first then all data — would have been simpler to parse
but doesn't match the spec format.

### Decision 3: ring_sub as local helper
**Context**: Need polynomial subtraction for `h - v3` check in 3-matrix path.
`ring.rs` lacks a `ring_sub` function.  
**Decision**: Added local `ring_sub(a, b) = ring_add_poly(a, neg(b))` in `ccs_encode.rs`.
Uses `Q_COMMIT` for negation. Same pattern as `ccs_rlwe.rs`.
**Alternative considered**: Add `ring_sub` to `ring.rs` — deferred to avoid touching
unrelated module.
