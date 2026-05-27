# PVTHFHE Crate Inventory & Skeleton Disposition

**Status**: Authoritative as of 2026-05-08 (R11.1 DECISION).
**Owner**: Atlas (orchestrator).
**Scope**: Records the disposition for every workspace crate whose `src/lib.rs` is <20 lines, per the `tests/lints/no_skeleton_crates.sh` invariant.

## Lint contract

- File: `tests/lints/no_skeleton_crates.sh` (CI job: `no-skeleton-crates`).
- Rule: Any `crates/*/src/lib.rs` with <20 lines MUST contain the literal sentinel `# ⚠️ INTENTIONALLY MINIMAL` somewhere in the file.
- Sentinel form: a `//!` doc-comment header, e.g.
  ```rust
  //! # ⚠️ INTENTIONALLY MINIMAL
  //!
  //! <one-paragraph rationale>
  ```

## R11.1 dispositions

Six crates were flagged by the R11.1 RED lint on 2026-05-08:

| Crate | Lines | F66 audit | Disposition | Rationale |
|---|---|---|---|---|
| `pvthfhe-api` | 6 | YES (skeleton) | **DELETE** | Zero consumers; placeholder content; no API surface defined. Removing eliminates the workspace dead weight that motivated F66. |
| `pvthfhe-core` | 9 | YES (skeleton) | **POPULATE rationale header** | `lib.rs` is empty but the crate hosts substantive `tests/vectors/*.json` consumed cross-crate (e.g. `pvthfhe-aggregator/tests/decrypt_roundtrip.rs`). Crate exists to host shared test fixtures; lib intentionally trivial. |
| `pvthfhe-circuits` | 6 | NO | **POPULATE rationale header** | Façade crate for Noir circuit Rust bindings. Real circuits live in `circuits/` (Noir workspace). Rust crate exists for `Cargo.toml` integration only. |
| `pvthfhe-cli` | 19 | NO | **POPULATE rationale header** | CLI façade. Real logic lives in feature-gated modules (`pvss_support`, `demo_nizk`, `compressor_glue`, `full_pipeline`) and the binary entry-points in `src/bin/`. The `lib.rs` itself is intentionally a thin module-export shim. |
| `pvthfhe-offchain-verifier` | 3 | NO | **POPULATE rationale header** | Crate hosts a Nova attestation helper module (`attestation.rs`) and a binary (`main.rs`). `lib.rs` only re-exports `attestation`; intentionally minimal. |
| `pvthfhe-rng` | 9 | NO (R0.7 deliverable) | **POPULATE rationale header** | Façade crate created by R0.7. Sole purpose: re-export `rand::rngs::OsRng` and provide the `production_rng()` factory function so all production callsites can be enforced via `cargo deny` / lint to depend only on this crate. Intentionally trivial; expanding it would dilute the lint's utility. |

## Workspace `Cargo.toml` impact

R11.1 GREEN must remove the `pvthfhe-api` member entry from workspace `Cargo.toml` line 25 (current state). All other dispositions are header-only (no Cargo.toml changes).

## Cross-crate consumers to verify before delete

- **`pvthfhe-api`**: confirmed zero consumers via `grep -rn "pvthfhe-api\|pvthfhe_api" --include="*.toml" --include="*.rs"` on 2026-05-08. Safe to delete.

## Future-state guidance

When adding a new façade crate:
1. Either write ≥ 20 lines of real code, or
2. Add the sentinel header `//! # ⚠️ INTENTIONALLY MINIMAL` with a one-paragraph rationale.

The lint will catch any silent regression to skeleton-crate sprawl.
