## 2026-05-17 — Remaining issue
- The always-run pipeline writes C7Prover.toml and invokes nargo unconditionally, but demo-e2e still logs a non-fatal plaintext_hash mismatch for generated pipeline witness data. The current code intentionally preserves fallback warning behavior, so just demo-e2e ACCEPTS despite the Noir failure; a future unit should make generated plaintext witness data match the N=8 circuit exactly if strict failing-on-Noir behavior is required.
- Requested bb verify command with --oracle_hash keccak failed on evm-no-zk proof size; rerunning verify with --verifier_target evm-no-zk succeeded.
## 2026-05-18 — Scalar sigma issues
- just demo-e2e ACCEPTS; it still logs the pre-existing non-fatal Noir plaintext_hash mismatch noted on 2026-05-17.
- cargo test -p pvthfhe-nizk passes with pre-existing warnings about missing docs in integration tests and unused variables in a sigma test.
## 2026-05-18 — G7 compressor sigma issues
- `cargo test -p pvthfhe-compressor` exceeded the 600s tool timeout in the long c7_nova_fold_n8192_4_steps integration test; targeted modified tests and sonobe_roundtrip passed, and just demo-e2e reached ACCEPT.
- just demo-e2e still logs the pre-existing Noir aggregator_final plaintext hash mismatch warning, but the demo completes with verify: ACCEPT.
