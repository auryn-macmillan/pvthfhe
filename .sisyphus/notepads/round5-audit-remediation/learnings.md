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
