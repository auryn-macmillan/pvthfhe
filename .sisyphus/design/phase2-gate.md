# Phase 2 Gate Report

**Status**: FAIL
**Date**: 2026-06-03T19:56:17Z

## Checks

| Check | Status | Detail |
|-------|--------|--------|
| artifacts | FAIL | Missing 1 artifact(s): crates/pvthfhe-api/src/lib.rs |
| parameters_toml | PASS | parameters.toml valid with required keys |
| noise_budget_test | PASS | cargo test noise_budget passed |
| theorem_mapping | PASS | Success: All theorems mapped correctly (4 theorems, 13 assumption references) |
| boundary_coverage | PASS | Success: All 12 boundary entries present with valid primary assignments |
| oracle_dispositions | PASS | All findings ADDRESSED |
| lit_refresh_no_blocking | PASS | No BLOCKING+undecided lines in lit-refresh-2.md |
| cyclo_tests | PASS | cargo test -p pvthfhe-cyclo passed |
| aggregate_1024_smoke | FAIL | cargo test -p pvthfhe-aggregator --test aggregate_1024_smoke failed: ck file, run `cargo update` to use the new
      version. This may also occur with an optional dependency that is not enabled.
error: target `aggregate_1024_smoke` in package `pvthfhe-aggregator` requires the features: `legacy-fold`
Consider enabling them by passing, e.g., `--features="legacy-fold"` |
| cargo_check | PASS | cargo check --workspace passed |

## Summary

Phase 2 gate FAILED. See failing checks above.
