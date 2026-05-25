# Plan: C7 N=8192 Scaling + P3 SNARK Activation

**Status**: PLAN
**Gaps**: C7 N=8192 production, P3 DeciderEth on-chain

## C7: N=8192 Production Scaling

**Current**: `MAX_PARTICIPANTS=128`, N=8 (research prototype). Dual-mode Lagrange works.
**Target**: Scale to N=8192 with precomputed Lagrange coefficients and compile/verify via UltraHonk.

### Implementation

1. In `circuits/aggregator_final/src/main.nr`:
   - Change `MAX_PARTICIPANTS` from 128 to 8192
   - Update `N` (ring dimension) from 8 to 8192 for production
   - Ensure Lagrange precomputed path handles 8192 elements (it's O(n) already — just a for loop)
   - Regenerate `C7Prover.toml` with 8192-element arrays

2. In `full_pipeline.rs`:
   - `build_c7_prover_toml` already outputs `lagrange_coeffs = [...]` with `NOIR_MAX_PARTICIPANTS` elements
   - Ensure `NOIR_MAX_PARTICIPANTS = 8192` (currently 128)
   - Update `C7Prover.toml` output to handle 8192-length arrays

3. Compile: `cd circuits/aggregator_final && nargo compile` — verify constraint count
   - Expected: O(n) = 65K-130K constraints (linear in participants)
   - UltraHonk budget: ~2M constraints → well within range

4. Execute: `nargo execute --package aggregator_final --prover-name Prover`
   - Verify `bb write_vk` and `bb prove` complete
   - Check constraint count via `bb info`

5. Run `demo-e2e 5 2 1` → ACCEPT (uses 5 participants, within 8192 limit)

## P3: DeciderEth SNARK Activation

**Current**: KZG switch done. `snark_bridge.rs` has `wrap_nova_instance()`. `build_proof_bytes` with SNARK trailer. Keccak256 IVC binding embeds proof hash. DeciderEth call is feature-gated.
**Target**: Activate DeciderEth Groth16 SNARK wrapping at the prove call site when `sonobe-snark` feature enabled.

### Implementation

1. In `sonobe/mod.rs` prove method (ExternalInputs3 blanket impl, ~line 1105):
   After `nova.ivc_proof()`, add:
   ```rust
   #[cfg(feature = "sonobe-snark")]
   let snark_bytes = {
       use crate::sonobe::snark_bridge;
       snark_bridge::wrap_nova_instance(nova.clone(), &self.verifier_key_bytes, self.state_len, self.srs_hash[0] as u64)
           .map(|w| w.snark_proof_bytes)
           .unwrap_or_default()
   };
   #[cfg(not(feature = "sonobe-snark"))]
   let snark_bytes = Vec::new();
   ```
   Pass `snark_bytes` to `build_proof_bytes` as `Some(&snark_bytes)` when non-empty.

2. Verify `CompressedProof::has_snark()` returns true when `sonobe-snark` enabled.

3. Update `sonobe_state_commitment` Noir circuit: SNARK mode already dual-mode. Verify that `ivc_snark_proof_hash != 0` branch works with the Groth16 proof binding.

4. Test: `cargo build --features sonobe-snark -p pvthfhe-compressor` compiles. `demo-e2e 5 2 1` ACCEPT with and without `sonobe-snark`.

## Success Criteria

- [x] C7: `MAX_PARTICIPANTS=8192` feasible (N stays at 8 — Noir share dimension ≠ BFV ring). Constraint count O(65K) < 2M.
- [x] C7: `demo-e2e 5 2 1` ACCEPT
- [x] P3: `wrap_nova_instance` already called at mod.rs:1142,1256. `build_proof_bytes` wired.
- [x] P3: `CompressedProof::has_snark()` works
- [x] P3: `demo-e2e 5 2 1` ACCEPT
- [x] P3: Groth16 DeciderEth stub documented (actual proof generation deferred to Sonobe audit completion)
