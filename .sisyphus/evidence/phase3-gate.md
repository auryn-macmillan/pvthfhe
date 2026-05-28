# Phase 3 Gate Report

**Status**: FAIL
**Date**: 2026-05-28T16:00:15Z

## Steps

| Step | Status | Detail |
|------|--------|--------|
| workspace-tests | FAIL | cargo test -p pvthfhe-aggregator failed: `pvthfhe-aggregator` (test "cyclo_norm_enforcement") generated 1 warning
    Finished `test` profile [unoptimized + debuginfo] target(s) in 13.25s
     Running unittests src/lib.rs (target/debug/deps/pvthfhe_aggregator-7f08907c14cf5645)
     Running tests/adversarial/mod.rs (target/debug/deps/adversarial-cd3bc86a31ac5f00)
error: test failed, to rerun pass `-p pvthfhe-aggregator --test adversarial` |
| clippy | FAIL | cargo clippy failed: igma.rs:957:21
    |
957 |     for eval_idx in 0..3 {
    |                     ^^^^
    |
    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.95.0/index.html#needless_range_loop
help: consider using an iterator
    |
957 -     for eval_idx in 0..3 {
957 +     for <item> in &gammas {
    |

error: could not compile `pvthfhe-nizk` (lib) due to 30 previous errors |
| fmt | FAIL | cargo fmt --check failed: ype ExternalInputs = ExternalInputs3<F>;
     type ExternalInputsVar = ExternalInputs3Var<F>;
 
[31m-    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> { // folding (legacy-nova)
[m[32m+    fn new(_params: Self::Params) -> Result<Self, folding_schemes::Error> {
[m[32m+        // folding (legacy-nova)
[m         Ok(Self {
             _field: PhantomData,
         }) |
| deny | FAIL | cargo deny check failed: pvthfhe/deny.toml:13:16
   │
13 │     { crate = "fhe-traits", allow = ["MIT"] },
   │                ━━━━━━━━━━ unmatched license exception

warning[license-exception-not-encountered]: license exception was not encountered
   ┌─ /home/dev/pvthfhe/deny.toml:14:16
   │
14 │     { crate = "prime_factorization", allow = ["CC0-1.0"] },
   │                ━━━━━━━━━━━━━━━━━━━ unmatched license exception |
| noir-tests | PASS | nargo test --workspace passed |
| forge-tests | FAIL | forge test failed: , 7776)] test_verifyAndConsume_atomic_and_replay_reverts() (gas: 94933)

Encountered 1 failing test in test/SessionRegistryAbortRestart.t.sol:SessionRegistryAbortRestartTest
[FAIL: ProofLengthWrongWithLogN(16, 4, 7776)] test_verifyAndConsume_afterAbortRestart() (gas: 94716)

Encountered a total of 52 failing tests, 78 tests succeeded

Tip: Run `forge test --rerun` to retry only the 52 failed tests |
| demo-e2e | PASS | just demo-e2e passed |
| adversarial-suite | PASS | just adversarial-suite passed |
| bench-scaling | PASS | just bench-scaling passed; all 4 envelopes present |
| docs-check | PASS | All 6 required docs present |
| evidence-check | PASS | All 3 key evidence files present |
| gas-check | PASS | gas=1278 ≤ 5000000 (PASS) |

## Summary

Phase 3 gate FAILED. See failing steps above.
