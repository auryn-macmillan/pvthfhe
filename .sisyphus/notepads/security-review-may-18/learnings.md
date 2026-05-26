# Learnings — Security Review May 18

## G.23: `compile_error!` vs `panic!` in const context

- `compile_error!` fires unconditionally when the token stream is reached — dead-code analysis doesn't help. Inside `if false { compile_error!(...) }` it STILL fires.
- Use `panic!()` inside a `const` block with `match option_env!(...)` instead. The panic in const eval produces `error[E0080]` — a compile-time error that correctly respects control flow.
- Pattern used:
  ```rust
  #[cfg(feature = "demo-seeded-rng")]
  const _: () = {
      match option_env!("PVTHFHE_I_UNDERSTAND_INSECURE_RNG") {
          Some(_) => {}
          None => panic!("message"),
      }
  };
  ```
- Verified: all three scenarios (feature off, feature on without env, feature on with env) work correctly.

## G.24: PATH injection hardening for nargo/bb subprocess execution

- Two files modified: `crates/pvthfhe-cli/src/full_pipeline.rs` and `crates/pvthfhe-cli/src/bin/pvthfhe_e2e.rs`
- Added `resolve_tool` helper that prefers env vars (`PVTHFHE_NARGO_PATH`, `PVTHFHE_BB_PATH`) over PATH
- Falls back to PATH resolution with a `tracing::warn!` about injection risk — no hard failure on missing env vars
- Both files use the same pattern: `fn resolve_tool(tool_name: &str, env_var: &str) -> std::path::PathBuf`
- `full_pipeline.rs` defines `resolve_tool` as a nested function inside the `else` block (line 926)
- `pvthfhe_e2e.rs` defines `resolve_tool` as a nested function inside `run_noir_aggregator_final_optional` (line 348)
- Verified: `cargo check -p pvthfhe-cli` passes cleanly with no new warnings

## Noir failure propagation + Poseidon participant_set_hash (2026-05-19)

### Problem
1. `nargo execute` returning non-zero was logged at `warn` level and `noir_passed` was set to false, but the `PipelineReport::all_verifications_passed` was hardcoded to `true`, so Noir failures were silently swallowed.
2. `participant_set_hash` was computed via `Sha256::digest(format!("ps-{n_participants}-{session_id}"))` but the Noir circuit computes `vector_hash(committee_party_ids, DOMAIN_VECTOR_MERKLE=1)`. These never matched, causing ALL Noir verification to fail across all scales (n=16,32,64,128).

### Fix 1 (full_pipeline.rs:1059-1148)
- Hoisted `noir_passed` to outer scope so it's accessible at report construction
- Set `noir_passed = false` in Prover.toml write-failure path
- Bumped `tracing::warn!` to `tracing::error!` for nargo execute failures
- Changed `all_verifications_passed: true` → `all_verifications_passed: noir_passed`

### Fix 2 (full_pipeline.rs:2017-2031)
- Replaced SHA-256 `ps_hash_bytes` with Poseidon sponge: `poseidon_hash_native(&[1u64, party_ids...])`
- Matches Noir `vector_hash` which prepends domain_tag=1 then sponges
- Uses existing local `poseidon_hash_native` (no new dependency needed)
