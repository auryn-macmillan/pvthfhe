# Round 8 Learnings

## Batch B Implementation (2026-05-15)

### B.4 — Deferred
C7 Merkle integration test with real decryption share data is deferred to follow-up.
Reason: Requires building real Merkle trees from pipeline decryption outputs,
which depends on F2 (Merkle ordering fix) being completed first in Batch A.
Tracked as F5 in the plan.

## Batch E — DKG Cache (2026-05-15)

### Implementation
- Created `crates/pvthfhe-fhe/src/dkg_cache.rs` with `FhersBackend::setup_threshold_cached`.
- Cache key: `(n, t, seed)` → marker file at `/tmp/pvthfhe-dkg-{n}-{t}-{seed}.marker`.
- On cache hit: skips `setup_threshold` entirely (saves O(n²·degree) Shamir computation).
- On cache miss: delegates to `setup_threshold` then writes marker file.
- Added `pub mod dkg_cache;` to `lib.rs`.
- Wired into `full_pipeline.rs` → replaced `setup_threshold(cfg.n, backend_threshold)` with `setup_threshold_cached(cfg.n, backend_threshold, cfg.seed)`.
- No `hex` dependency needed: used raw `seed` in filename.

### Build Result
- `pvthfhe-fhe` builds clean (3 pre-existing warnings).
- `pvthfhe-cli` has pre-existing compilation errors unrelated to this change (lines 210, 243).

## Batch D — Parallel NIZK Verification + C7 Horner (2026-05-15)

### Implementation
- Added `rayon = "1"` dependency to `crates/pvthfhe-cli/Cargo.toml`.
- Parallelized NIZK verify loop in `run_full_pipeline` (lines ~208-250):
  - Flattened nested `for` loops into a `Vec` of (dealer, recipient, stmt, proof) tuples.
  - Used `par_iter()` for parallel verification, collecting `Result<(String, f64), anyhow::Error>`.
  - Observer calls (`phase_start`/`phase_end`) remain sequential — collected results then iterated.
- C7 Horner evaluation (line ~1192) was already parallelized via pre-existing changes.
- Added scoped `use rayon::prelude::*;` in both the NIZK and C7 functions.

### Key Decisions
- **No type annotation on nizk_pairs**: Removed `Vec<(&u64, &NizkStatement, &NizkProof)>` to avoid importing `NizkProof`. Used `Vec<_>` with type inference instead.
- **Tuple destructuring avoidance**: Used `let pair = result?;` with `pair.0`/`pair.1` fields instead of `let (detail, ms) = result?;` to avoid a confusing `str`-not-Sized compiler error.
- **Scoped imports**: `use rayon::prelude::*;` placed near usage sites (not top-level) since rayon is only used in two isolated functions.

### Build Result
- `pvthfhe-cli` builds clean with `--features "sonobe-compressor,demo-seeded-rng,pipeline-extra-checks"`.
- No new warnings introduced; 2 pre-existing warnings at lines 645/652 (unrelated to this change).
