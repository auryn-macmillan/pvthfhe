# Learnings — deep-audit-remediation

## B.1 / B.2 — Remove plaintext slot logging

### Pattern: `#[cfg(feature = "...")]` for gating debug statements

When removing debug logging that may leak plaintext/slot content, use
`#[cfg(feature = "trace-decrypt")]` on individual `eprintln!` statements rather
than deleting them entirely. This preserves the debugging capability while
ensuring production builds cannot leak plaintext.

### Locations gated (fhers.rs):
- `encode_plaintext_slots`: `[FHE-ENCODE]` eprintln (line 436)
- `decode_plaintext_slots`: `[FHE-DECODE] FAIL` eprintln (lines 455-462)
- `aggregate_decrypt`: `[FHE-DECRYPT] aggregate_decrypt` eprintln (line 1119)

### Verification:
- `cargo build -p pvthfhe-fhe` (default, no feature): passes, eprintln lines removed
- `cargo build -p pvthfhe-fhe --features trace-decrypt`: passes, eprintln lines active
- LSP diagnostics confirm all 4 locations show as `inactive-code` when feature disabled

### Feature flag name:
Single consistent name `trace-decrypt` across all three locations.

## A.2 / A.3 — Double-subtract threshold fix + DKG key mismatch

### Root cause of double-subtract bug

The `saturating_sub(1)` on `backend_threshold` was a misguided conversion from
"PVSS threshold" to "FHE backend threshold." The fhe.rs `setup_threshold(n, t)`
stores `t` directly as the configured threshold, and `aggregate_decrypt` checks
`threshold == configured_threshold`. There is no off-by-one in the FHE backend
— `t` means exactly `t` shares.

When `cfg.t == 1`, `saturating_sub(1)` produced 0, causing `setup_threshold` to
fail with "invalid threshold parameters: t=0".

### Pattern: assert_eq on aggregate key material

The DKG transcript's `aggregate_pk` and the FHE backend's `aggregate_keygen`
output are both `OpaquePublicKey`. Comparing their `.bytes` fields catches
deterministic key derivation mismatches early. The old code used `_aggregate_key`
(underscore-prefixed, unused), silently discarding the result.

### Verification summary
| Test | Seed | t | n | Result |
|------|------|---|---|--------|
| build | — | — | — | ✅ |
| demo | 1 | 4 | 10 | plaintext_roundtrip: OK, verify: ACCEPT |
| demo | 1 | 1 | 10 | plaintext_roundtrip: OK, verify: ACCEPT (t=1 previously broken) |
| demo | 2 | 4 | 10 | OK, ACCEPT, assert_eq not fired |
| demo | 3 | 4 | 10 | OK, ACCEPT, assert_eq not fired |
| unit test | 0 | 2 | 5 | red_3_records_all_full_pipeline_phases: ok |

### Side fix: atomic_decrypt test compilation
Pre-existing type error (`Vec<u8>` assigned to `ProtocolBytes` field) fixed by
using `ProtocolBytes(vec![...])` constructor and adding the `ProtocolBytes` import.

## Batch C — 6 MEDIUM fixes

### C.1 — Wrap DecryptNizkWitness secret fields in Secret<T>

**Pattern**: `pvthfhe_types::Secret<T>` wraps sensitive bytes with zeroize-on-drop.
- `secret_key_bytes: Vec<u8>` → `Secret<Vec<u8>>` (via `Secret::new(...)`)
- `decryption_noise: Vec<u8>` → `Secret<Vec<u8>>`
- All field accesses changed to `.expose_secret()` for borrowing the inner value
- `Secret<T>` implements `Debug` as `"Secret(<redacted>)"` — safe for derives
- 7 construction sites updated across `pvss_support.rs` and test files
- No breaking API changes: the struct keeps `Clone, Debug, PartialEq, Eq`

### C.2 — Input validation in scale_plaintext_to_rns

Added guard at function entry: `m_int.iter().any(|c| c.abs() > B_M)` returns
`Err(NizkError::InvalidInput(...))`. Uses the existing `B_M = 65_536` constant
(matches the BFV plaintext modulus bound). No external constant needed.

### C.3 — bytes_to_i64_poly assertion

Added `assert!(bytes.len() % 8 == 0, "input length must be multiple of 8")`
before `chunks_exact(8)`. The old code silently ignored trailing bytes; the
assert makes the contract explicit for callers.

### C.4 — Rename B_E constants

Two colliding `B_E` constants renamed:
- `sigma::B_E = 16` → `sigma::SIGMA_B_E = 16`
- `bfv_sigma::B_E = 10_000` → `bfv_sigma::BFV_SIGMA_B_E = 10_000`
- `B_Z_E` (which depends on `B_E`) NOT renamed (no collision in that name)
- 3 external references updated: `demo_nizk.rs` (2), `params_consistency.rs` (1)
- Doc comments updated to reference new names
- `B_U`, `B_M`, `B_Y` unchanged (no collisions)

### C.5 — n>0 guard in compute_party_sk_sums

Added early return `if n == 0 { return Err(FheError::Backend { ... }) }`.
Prevents `(1u32..=0)` empty range panic.

### C.6 — derive_demo_error_poly doc

Updated doc comment first line to: "Generates small-norm demo polynomial for
NIZK testing, not actual BFV encryption error." Also updated `B_E` → `SIGMA_B_E`
in doc and inline comments.

### Verification

- `cargo build`: ✅ clean (0.05s, no new warnings)
- `cargo test -p pvthfhe-pvss`: ✅ 68 passed / 0 failed / 5 ignored

## Batch H — Demo + Benchmark integration verification

### H.1 — Demo e2e passes

- `just demo-e2e 10` → `plaintext_roundtrip: OK`, `verify: ACCEPT`
- No `[FHE-ENCODE]` or `[FHE-DECRYPT] aggregate_decrypt:` leaks in output
- 0 lines matched for plaintext leak patterns

### H.2 — force-large-n works

- `cargo run --release ... -- demo --n 11 --threshold 4 --seed 1 --force-large-n`
- `plaintext_roundtrip: OK`, `verify: ACCEPT`

### C.2 bug found and fixed — scale_plaintext_to_rns B_M check too restrictive

**Root cause**: The C.2 fix added `|c| ≤ B_M` (65,536) validation to
`scale_plaintext_to_rns`, but this function is used for BOTH plaintext
polynomials AND masking polynomials (y_m sampled from [-B_Y, B_Y] with
B_Y = 2^30 = 1,073,741,824). The masking values legitimately exceed B_M.

**Symptom**: `bfv_sigma::prove` failed with `InvalidInput("plaintext coefficient exceeds B_M bound")`.

**Fix**: Removed the B_M check from `scale_plaintext_to_rns`. The function is a
generic math utility (scale integer polynomial to RNS by delta); coefficient
domain validation belongs in the caller. The doc comment was updated to note
caller responsibility for domain bounds (B_M for plaintext, B_Y for masking).

**File changed**: `crates/pvthfhe-nizk/src/bfv_sigma.rs` line 163-167

### H.3 — Benchmark executed

- `python3 bench/i1_one_vs_two_track.py --n 10 --t 4 --seed 1` → success
- Output: `bench/results/i1-one-vs-two-track.json`, `bench/results/i1-one-vs-two-track.md`

### H.4 — Benchmark integrity checks

- `python3 -m py_compile bench/i1_one_vs_two_track.py` → PASS
- `python3 -m json.tool bench/results/i1-one-vs-two-track.json` → PASS

### H.5 — Baseline documented

Post-remediation baseline saved to `bench/results/deep-audit-before-after.md`.
No prior "before" snapshot exists; current benchmark results serve as the
post-remediation reference.

### Mock backend status

The mock feature (`pvthfhe-fhe/mock`) is being resolved as active in the
workspace feature resolution (confirmed via `cargo metadata`), but the demo
uses `FhersBackend` (real BFV) directly in `LatticePvssBfvAdapter::new()`.
The mock warning in build output is from build.rs detecting `CARGO_FEATURE_MOCK`
set at workspace level — this does not affect the demo's actual backend choice.
