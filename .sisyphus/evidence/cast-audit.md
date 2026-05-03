# Cast Risk Audit — `crates/pvthfhe-keygen/src/hermine.rs`

Generated: 2026-05-03  
Grep command: `grep -nE ' as [a-z_][a-z0-9_]*' crates/pvthfhe-keygen/src/hermine.rs`  
Raw output: `.sisyphus/evidence/audit-cast/grep-casts.log`  
`wc -l` result: **18** (16 code casts + 2 comment false-positives)

---

## Cast Table (18 grep matches)

| Row | Line | Snippet | Src Type | Dst Type | Risk Class | Justification / Fix Recommendation |
|-----|------|---------|----------|----------|------------|-------------------------------------|
| 1 | 18 | `used as the Shamir` | — | — | **comment** | In doc comment; not a cast. No action needed. |
| 2 | 43 | `c as u128` | `u64` | `u128` | **safe** | `c` is `&u64` from `coeffs: &[u64]`. Widening to u128 for overflow-safe arithmetic; no bits lost. |
| 3 | 43 | `PRIME as u128` | `u64` | `u128` | **safe** | `PRIME: u64 = (1<<61)-1`. Widening constant; fits in u128. |
| 4 | 44 | `x as u128` | `u64` | `u128` | **safe** | `x: u64` param of `poly_eval`. Widening for modular multiply; no bits lost. |
| 5 | 44 | `PRIME as u128` | `u64` | `u128` | **safe** | Same as row 3. |
| 6 | 46 | `result as u64` | `u128` | `u64` | **safe** | `result` is kept `% PRIME as u128` = `% (2^61-1)` throughout the loop. Value ≤ 2^61−2 < 2^64; narrowing is lossless. |
| 7 | 76 | `threshold as usize` | `u16` | `usize` | **safe** | `usize` ≥ 16 bits on every Rust target. Widening; used only for length comparison. |
| 8 | 186 | `PRIME as u128` | `u64` | `u128` | **safe** | Widening constant; see row 3. |
| 9 | 193 | `xj as u128` | `u64` | `u128` | **safe** | `xj: u64` from slice of shares. Widening for modular arithmetic. |
| 10 | 196 | `(xi - xj) as u128` | `u64` | `u128` | **safe** | Guard `xi > xj` on line 195 ensures subtraction does not wrap. Widening the non-negative difference. |
| 11 | 198 | `(xj - xi) as u128` | `u64` | `u128` | **safe** | Reached only in `else` branch where `xi <= xj`. Subtraction does not wrap; widening is lossless. |
| 12 | 205 | `yi as u128` | `u64` | `u128` | **safe** | `yi: u64` from shares tuple. Widening for modular multiply. |
| 13 | 208 | `secret as u64` | `u128` | `u64` | **safe** | `secret` is kept `% p` throughout where `p = PRIME as u128 < 2^61`. Value ≤ 2^61−2 < 2^64; narrowing is lossless. |
| 14 | 260 | `session.threshold as usize` | `u16` | `usize` | **safe** | Widening; see row 7. |
| 15 | 270 | `i as u64` | `usize` | `u64` | **safe** | `i` is a loop index `1..t` where `t = threshold as usize ≤ u16::MAX`. On all Rust targets usize ≤ 64 bits; value fits in u64. |
| 16 | 278 | `p.id as u64` | `u16` | `u64` | **safe** | `p.id: u16`. Widening; no bits lost. |
| 17 | 354 | `.threshold…? as usize` | `u16` | `usize` | **safe** | `Share::threshold: Option<u16>`. Widening; see row 7. |
| 18 | 367 | `threshold as u16` | `usize` | `u16` | **truncating** | `threshold: usize` (line 354 binding). On 64-bit targets usize can exceed `u16::MAX` (65535). If reconstructing with >65535 participants, this silently wraps. **Fix:** use `u16::try_from(threshold).map_err(|_| KeygenError::new("threshold exceeds u16 range"))?`. |
| 19 | 373 | `.participant_id…? as u64` | `u16` | `u64` | **safe** | `Share::participant_id: Option<u16>`. Widening; no bits lost. |
| 20 | 433 | `byte slice as a lowercase` | — | — | **comment** | In doc comment; not a cast. No action needed. |

> **Note:** The grep pattern matches 18 lines; rows 1 and 20 are doc-comment false-positives (the word "as" appearing in English prose). True code cast count = **18 rows − 2 comments = 16 casts** across 14 unique source lines (lines 43 and 44 each contain 2 casts).

---

## `manual_contains` Instances

| Line | Snippet | Clippy lint | Rewrite Recommendation |
|------|---------|-------------|------------------------|
| 413 | `artifact.commitments.iter().any(\|c\| *c == expected_commit)` | `clippy::manual_contains` | Replace with `artifact.commitments.contains(&expected_commit)`. `Vec<Vec<u8>>` implements `contains` via `PartialEq`; this is identical semantics with clearer intent. |

---

## Summary

| Risk Class | Count |
|------------|-------|
| safe | 15 |
| truncating | 1 (line 367) |
| sign-changing | 0 |
| lossy-float | 0 |
| comment (false-positive) | 2 |
| **Total grep matches** | **18** |

### Only actionable item

- **Line 367 `threshold as u16`** — `usize → u16` narrowing cast. Replace with `u16::try_from(threshold)?` to surface a clear error rather than silent wrap when threshold exceeds 65 535. This is the fix target for T19.
