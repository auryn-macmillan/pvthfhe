# Plan: Close All Remaining Gaps

**Status**: PLAN
**Target**: Complete implementation of C1, C3, C4, C5, C7, P3, and Accountability.
No deferrals. Full wiring into demo-e2e, per-node, and aggregator.

## Gap C1: PK Contribution Proof

**Current**: `pk_contribution_circuit.rs` exists (compiles). Uses `sigma_verify_step` for per-party PK contribution verification. Not wired.
**Target**: Wire into demo-e2e after keygen phase. Each party publishes a proof that `pk_0_i = a · sk_i + e_i`.

### Implementation
1. In `full_pipeline.rs`, after keygen (line ~242), set `PK_CONTRIBUTION_DATA` with per-party data
2. Create `SonobeCompressor::<KeyContributionStepCircuit<Fr>>::new(...)` once
3. For each party, populate thread-local, call `compressor.prove()`, verify
4. Store `pk_contribution_hash` in `PipelineReport`
5. Add `pk_contribution_hash` to `pipeline_integrity_hash` chain (C1 slot already reserved)
6. Test via `demo-e2e 5 2 1` → ACCEPT

## Gap C3: BFV Encryption Share Binding

**Current**: `CycloNizkAdapter::verify` at `adapter.rs:192` checks `pvss_commitment` binding. Natively verified.
**Target**: Add explicit share binding check in the demo-e2e nizk_verify phase. Document in SECURITY.md.

### Implementation
1. In `full_pipeline.rs` nizk_verify phase (line ~639), add explicit assertion:
   `assert_eq!(decoded_pvss_commitment, expected_share_commitment)`
2. Add test: tamper share commitment → verification fails
3. Update SECURITY.md: C3 "Partially implemented" → "Fully implemented (native adapter)"
4. Wire into per-node (already exercises nizk_prove/verify)

## Gap C4: DKG Share Aggregation

**Current**: `dkg_aggregation_circuit.rs` exists (compiles). Native verifier at `dkg_aggregation.rs`. Not wired into Nova.
**Target**: Wire the circuit into demo-e2e after dkg_aggregate phase. Fold via Nova IVC.

### Implementation
1. In `full_pipeline.rs`, after dkg_aggregate (line ~493), set `DKG_AGG_DATA` with per-recipient shares
2. Create `SonobeCompressor::<DkgAggregationStepCircuit<Fr>>::new(...)` once
3. For each recipient, populate thread-local, call `compressor.prove()`
4. Fold into Nova IVC accumulator
5. Store `dkg_agg_hash` in `PipelineReport`
6. Add `dkg_agg_hash` to `pipeline_integrity_hash`
7. Test via `demo-e2e 5 2 1` → ACCEPT

## Gap C5: PK Aggregation Proof

**Current**: Design doc only. No circuit.
**Target**: Prove that `aggregate_pk = Σ pk_i` for all committee members. Wire via Nova IVC.

### Implementation
1. Create `pk_aggregation_circuit.rs` — simple FCircuit that sums all pk_i contributions in R1CS:
   - Thread-local: `PK_AGG_SK_DATA` storing per-party secret key coefficients
   - State: (pk_sum_accumulator, step_count)
   - Each step adds one party's contribution to the accumulator
2. Wire into full_pipeline after aggregate key computation
3. Store `aggregate_pk_hash` in `PipelineReport`
4. Add to `pipeline_integrity_hash`
5. Test via `demo-e2e 5 2 1` → ACCEPT

## Gap C7: Lagrange Recombination at Production Scale

**Current**: N=8 prototype in `circuits/aggregator_final`. Lagrange is O(n²) in-circuit.
**Target**: Scale to N=8192 using precomputed Lagrange coefficients passed as public inputs.

### Implementation
1. In `circuits/aggregator_final/src/main.nr`:
   - Keep `MAX_PARTICIPANTS = 128` (Noir constraint budget)
   - Remove in-circuit `lagrange_coeff_at` computation
   - Use `lagrange_coeffs: pub [Field; MAX_PARTICIPANTS]` public input (already added)
   - O(n) weighted sum: `plaintext += shares[i] * lagrange_coeffs[i]`
2. In `full_pipeline.rs`, compute Lagrange coefficients from committee party IDs at evaluation x=0:
   - `lagrange_coeffs[i] = Π_{j≠i} x_j / (x_j - x_i)` where x_j = committee_party_ids[j]
   - Pass via `build_c7_prover_toml` as `lagrange_coeffs` field
3. Test: `nargo test` (12 tests pass)
4. Deploy: `max_n = 128` hardcoded; `MAX_PARTICIPANTS` in Noir scales independently

**Note**: N=8192 requires the Noir prover to handle ~2M constraints (UltraHonk budget). The circuit itself is O(n) thanks to precomputed coefficients. The constraint count comes from `n * 8` = `8192 * 8 = 65k` linear combinations for Lagrange recombination, well under 2M.

## Gap P3: SNARK On-Chain Verification

**Current**: KZG switch done. `snark_bridge.rs` has `wrap_nova_instance()`. `sonobe_state_commitment` Noir dual-mode. Extended `CompressedProof` format with SNARK trailer. Keccak256 IVC proof binding in prove method.
**Target**: Full DeciderEth Groth16 SNARK wrapping wired at compressor call site.

### Implementation
1. In `sonobe/mod.rs` prove method (line ~1100), after `nova.ivc_proof()`:
   ```rust
   #[cfg(feature = "sonobe-snark")]
   let snark_bytes = snark_bridge::wrap_nova_instance(nova, &self.verifier_key_bytes, state_len, seed)?;
   let snark_ref = Some(snark_bytes.snark_proof_bytes.as_slice());
   #[cfg(not(feature = "sonobe-snark"))]
   let snark_ref: Option<&[u8]> = None;
   ```
2. The Keccak256 binding currently in prove (P3-lite) serves as fallback when `sonobe-snark` not enabled
3. Wire via feature flag: `cargo build --features sonobe-snark` enables full DeciderEth
4. Update `sonobe_state_commitment` Noir circuit: SNARK mode already implemented (dual-mode)
5. Test via `demo-e2e` with `sonobe-snark` feature

## Gap: Per-Party Accountability

**Current**: Design doc only. No signing.
**Target**: Schnorr signing of commitments per party. Signatures stored in PipelineReport.

### Implementation
1. In `full_pipeline.rs`, after keygen, generate Schnorr keypairs:
   ```rust
   use pvthfhe_nizk::schnorr;
   let (sk, pk) = schnorr::generate_signing_keypair(&mut rng);
   ```
2. After each NIZK proof, sign the proof hash: `sig = schnorr_sign(sk, proof_hash)`
3. Store `node_schnorr_pks` and `node_schnorr_sigs` in `PipelineReport`
4. Add verification in per-node and per-aggregator: verify signatures before accepting proofs
5. Test: tamper signature → verification fails
6. Update `per-party-accountability.md` with implementation notes

## Wiring Into Demo Scripts

All gaps wired into `demo-e2e` for correctness. `per-node` and `per-aggregator` wired where the gap affects per-node operations (C1, C3, C4, Accountability apply to all parties). C5 and P3 are aggregator-level.

## Execution Order

1. C3 (simplest: adapter check already exists, add assertion)
2. C1 (circuit exists, just needs Nova wiring)
3. C4 (circuit exists, just needs Nova wiring)
4. C5 (new circuit needed, simple Fr addition)
5. C7 (Noir circuit + pipeline parameterization)
6. P3 (SNARK wiring at call site)
7. Accountability (Schnorr signing in pipeline)

## Success Criteria

- [ ] `demo-e2e 5 2 1` → ACCEPT
- [ ] `demo-e2e 10 4 1` → ACCEPT
- [ ] `per-node 5 2 1` → completes successfully
- [ ] `per-aggregator 5 2 1` → completes successfully
- [ ] All existing tests pass
- [ ] No stubs, surrogates, or shortcuts
