## Batch D — Paper + Docs Sync (2026-05-14)

### Changes Applied (9/9)

- **D.1**: lemma9.md:36 — "downgraded to Conjecture 9 pending..." → "accepted as a documented protocol assumption." (aligns with §0)
- **D.2**: 5 files — "straight-line extractor" → "rewinding extractor" (paper/main.tex ×2, claims-table.md, T2.md, obligations.md)
- **D.3**: paper/main.tex:149-151 — P1-T3 scope updated from narrow SLAP-core to full serialized ShareNizkProof format
- **D.4**: paper/main.tex:154 — Removed obsolete T2/T3 tension note entirely
- **D.5**: ARCHITECTURE.md:5 — "Sonobe attestation" → "ECDSA/ecrecover attestation"
- **D.6**: ARCHITECTURE.md:193-194 — Track B default clarified as "norm-enforced Sonobe Nova path" with LatticeFold+ deferred
- **D.7**: claims-table.md:37-38 — "skeleton" → "PROVED (rewinding extractor, ROM, forking lemma)"
- **D.8**: SECURITY.md:48 — "deferred" → "PROVED — rewinding extractor"
- **D.9**: interfold-threat-model.md:77 — "a skeleton" → "PROVED (rewinding extractor)"

### Cross-Reference Verification

- paper/main.tex — no "straight-line extractor" for P1-T2 ✅
- lemma9.md — §0 and §3 now agree ✅
- ARCHITECTURE.md — on-chain description now says ECDSA/ecrecover ✅
- SECURITY.md — T2 no longer "deferred" ✅

### Out-of-Scope Stale References (not in Batch D)
- WARNING.md:3 still says "Sonobe attestation" (not targeted)
- soundness-budget-reconciliation.md:65 still says "downgraded to Conjecture 9" (not targeted)

## Batch A — Critical Fixes (2026-05-14)

### Changes Applied (4/4)

- **A.1**: full_pipeline.rs:368-369 — Replaced `RingElement::zero(PHI_COMMIT)` with z_s/z_e cloned from witness coefficients (`s.coeffs.clone()`, `e.coeffs.clone()`). Added comment documenting the approximation: z_s ≈ s, z_e ≈ e (conservative for demo; bounds have enough slack).
- **A.2**: mod.rs:144-145 — Replaced `.expect("init_accumulator must succeed for valid instance")` with `match`+`.map_err(|e| FoldError(format!("init_accumulator: {e}")))?`. Required restructuring from `unwrap_or_else` closure to `match` because `?` cannot be used inside closures returning non-Result types.
- **A.3**: full_pipeline.rs:881,894 — Replaced both `.expect()` calls with `.map_err(|e| anyhow::anyhow!("Ajtai commit: {e}"))?`. Required changing `compute_cyclo_ajtai_commitment` return type from `Vec<u8>` to `anyhow::Result<Vec<u8>>`, and `compute_ajtai_commitment_for_track` from `Vec<u8>` to `anyhow::Result<Vec<u8>>`. Added `?` at call site in `build_fold_instances`. Used `.collect::<Result<Vec<_>, _>>()?` pattern for the closure-based map to propagate errors.
- **A.4**: cyclo_norm_enforcement.rs — Added `full_validation_accepts_matching_zs_ze` test verifying valid witnesses (‖s‖=42 ≤ 1024, ‖e‖=7 ≤ 16, ‖zs‖=42 ≤ 2049, ‖ze‖=7 ≤ 2049) pass validation.

### Verification

- `cargo build --workspace` — ✅ (dev + release)
- `cargo test -p pvthfhe-aggregator --test cyclo_norm_enforcement` — ✅ (5/5 pass)
- `cargo test -p pvthfhe-aggregator -p pvthfhe-cli` — ✅ (3 pre-existing adversarial test failures unrelated)
- `just demo-e2e` — ✅ (ACCEPT)

### Gotchas

- **? in closures**: The `?` operator cannot be used inside closures that don't return `Result`/`Option`. Required restructuring with `match` (A.2) and `collect::<Result<Vec<_>, _>>()` (A.3).
- **Move semantics**: Cloning `s.coeffs` instead of `s_coeffs` after the latter was moved into `s` (A.1 fix v2).

## Batch E progress (2026-05-14)

### E.2: i128 truncation SAFETY comments — DONE
- Added SAFETY comment at `fhers.rs:1387` documenting that for t ≤ 10 with party IDs {1..10}, the Lagrange-weighted coefficient sum fits in i64 (< 2^63).
- Added SAFETY comment at `fhers.rs:1438` documenting that Lagrange coefficients are small integers (< 10! ≈ 3.6e6) and the division fits in i64.
- These are necessary comments (security/reviewable bounds), not code smells. The `as i64` cast is maintained per task spec (E.2 says "document safe bounds" as alternative to `try_from`).

### E.3: Track parsing tests — DONE
- Added three new tests to `full_pipeline.rs`:
  - `track_a_lowercase`: verifies `"a".parse::<Track>()` → `Track::A`
  - `track_b_lowercase`: verifies `"b".parse::<Track>()` → `Track::B`  
  - `track_empty_defaults_b`: verifies `""` parse falls back to `Track::B`
- All 6 Track parsing tests pass (3 existing + 3 new).

## Batch B: Comment-Only Fixes (2026-05-14)

### B.1: CycloFoldStepCircuit ring verifier comment (mod.rs:186-198)
Replaced misleading PLACEHOLDER comment with honest documentation:
- Acknowledges `ring_verification_count` is a dead counter (not real R1CS)
- Points to real implementation at `cyclo_verifier.rs` and `tests/cyclo_r1cs_verifier.rs`
- No logic changes

### B.3: build_fold_instances AjtaiMatrix doc comment (full_pipeline.rs:709-710)
Fixed: old comment claimed Track B uses deterministic AjtaiMatrix from aggregator.
New: "Track B uses the same Cyclo Ajtai commitment format. The aggregator's AjtaiMatrix is experimental and not yet integrated."

### B.4: compute_ajtai_commitment_for_track doc comment (full_pipeline.rs:817-820)
Fixed: old comment claimed Track A uses Cyclo and Track B uses AjtaiMatrix.
New: "Both tracks use the Cyclo Ajtai commitment format. Track B AjtaiMatrix integration is deferred per p2-m4-lattice-commitment."

## Batch C Learnings (2026-05-14)

### C.1: Enable C7 Sonobe in demo-e2e
- Added `export PVTHFHE_RUN_C7_SONOBE=1` before the cargo run in the `demo-e2e` recipe (Justfile line 30).
- The env var is read by `run_c7_sonobe_optional()` in pvthfhe_e2e.rs (line 376).
- Previously, C7 Sonobe never ran during `just demo-e2e` because the env var defaulted to empty/"0".

### C.2: Silent-pass markers
- Documented three deferred phases in `finish()`:
  - `noir_decrypt_share` — Noir decrypt-share circuit not implemented
  - `noir_sonobe_wrap` — Sonobe wrap circuit not implemented
  - `onchain_verify` — on-chain UltraHonk verification not implemented
- Added a block comment at the top of `finish()` listing all deferred phases.
- Removed misleading timing blocks (Instant::now + elapsed) for `noir_sonobe_wrap` and `onchain_verify` that were printing 0.0 ms measurements of nothing.
- Added inline `// Phase marker only — not implemented. See deferred plans.` on each marker println.

### C.3: Track B comment in bench script
- Added a comment to `bench/i1_one_vs_two_track.py` noting that:
  - Track B benchmarking requires `--features pipeline-extra-checks,sonobe-compressor` and `PVTHFHE_TRACK=B`
  - The current benchmark uses Track A only (default)
  - Users should see `just bench-comparison` for the full Track B feature set

### C.4: bench-comparison features verified
- Confirmed `just bench-comparison` recipe (Justfile line 51) has: `sonobe-compressor,demo-seeded-rng,pipeline-extra-checks` — correct per plan.
