# G.21: Gate stdout secret leaks — Learnings

## Implementation Notes
- Used `tracing::enabled!(tracing::Level::DEBUG)` for gating because `tracing` was already a dependency with env-filter subscriber initialized in `main()`.
- The default `RUST_LOG` filter is `pvthfhe_cli=info`, so debug-level output is suppressed by default.
- Users can opt in with `RUST_LOG=pvthfhe_cli=debug` to see secret hex values.
- Non-secret metadata (party_id) is shown in the else branch; only the secret hex is hidden.
- No new dependencies needed.

## Files Changed
- `crates/pvthfhe-cli/src/main.rs`:
  - Line 232: Partial decrypt share_hex gated behind `tracing::enabled!(tracing::Level::DEBUG)`
  - Line 277 (now 281): Aggregate plaintext_hex gated behind same check

## Verification
- `cargo check -p pvthfhe-cli` — passed (only pre-existing unrelated warnings)
- `lsp_diagnostics` — no issues
