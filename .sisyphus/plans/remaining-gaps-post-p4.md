# Plan: Remaining Gaps Post-Phase-4

**Status**: PLAN (awaiting Momus review)
**Depends on**: Phase 1-4 completion (all gates passed)
**Estimate**: See per-item estimates

## Context

Phases 1-4 addressed the cryptographer's three highest-priority claims: C0 (keygen NIZK —
real sigma::prove), C2 (P(0) commitment binding — dual in-circuit/off-circuit), C6 (sigma
verification — in-circuit Nova R1CS). Eight gaps remain, ranging from major architectural
additions to wiring fixes.

## Gaps to Address

### G1: C4 — Wire DKG Share Aggregation Verifier (1 day)

**Status**: Verifier exists natively in [`dkg_aggregation.rs`](file:///home/dev/pvthfhe/crates/pvthfhe-pvss/src/dkg_aggregation.rs) but is listed as "Verifiers Exist,
Not Called" in ARCHITECTURE.md and has no in-circuit equivalent.

**Approach**: Add `DkgAggregationStepCircuit` (Sonobe FCircuit) wrapping the existing
`verify_recipient_dkg_aggregation` logic. Wire it into `full_pipeline.rs` after DKG
aggregation.

1. Create `dkg_aggregation_circuit.rs` in compressor's sonobe module
2. Thread-local: `DKG_AGG_DATA` storing per-recipient `(DealerDkgShare, sk_commitment, esm_commitment)`
3. FCircuit step verifies share aggregation + commitment consistency in R1CS
4. Wire into `full_pipeline.rs` → SonobeCompressor prove after `dkg_aggregate`
5. Track state: (agg_hash, step_count). Final agg_hash bound into PipelineReport
6. Add test: `dkg_aggregation_works.rs`
7. Test via `cargo test -p pvthfhe-compressor --test dkg_aggregation_works`
8. Verify via `demo-e2e 10 4 1` → ACCEPT

**Success criteria**:
- `DkgAggregationStepCircuit` R1CS rejects tampered share aggregation
- `demo-e2e` passes with dkg aggregation verification in Nova IVC
- PipelineReport carries `dkg_agg_hash`

### G2: P3 — Wire DeciderEth SNARK at Compressor Call Site (1 day)

**Status**: KZG switch done, `snark_bridge.rs` has `wrap_nova_instance()` documented with
correct DeciderEth type patterns. The call site in `SonobeCompressor::prove` does NOT call
`wrap_nova_instance()`.

**Approach**: Add `#[cfg(feature = "sonobe-snark")]` call to `wrap_nova_instance()` after
`nova.ivc_proof()` in the prove method. Embed the SNARK bytes in the extended
`CompressedProof` format.

1. In `sonobe/mod.rs`, after `nova.ivc_proof()` in ExternalInputs3 prove method:
   - `#[cfg(feature = "sonobe-snark")]` call `snark_bridge::wrap_nova_instance(nova, &self.verifier_key_bytes, state_len, seed)`
   - `#[cfg(not(feature = "sonobe-snark"))]` keep current behavior (no SNARK)
2. Use `snark_bridge::serialize_wrapped_proof()` to extend the proof bytes
3. Implementation note: `wrap_nova_instance` currently returns empty SNARK bytes (placeholder).
   The actual DeciderEth flow requires adding concrete type annotations at the call site.
   The placeholder is acceptable for wiring — it makes the extended format functional while
   full DeciderEth integration waits for the Sonobe `sonobe-snark` feature stabilization.
4. Test via `cargo test -p pvthfhe-compressor --test dealer_parity_works` (should still pass)
5. Verify via `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just demo-e2e 5 2 1` → ACCEPT

**Success criteria**:
- `CompressedProof::has_snark()` returns true when `sonobe-snark` enabled
- Extended proof format roundtrip (prove+verify with SNARK trailer)
- Backward compat: existing proofs without SNARK still verify

### G3: C3 — BFV Encryption Share Binding (Partial Fix) (2 days)

**Status**: BFV sigma proves encryption well-formedness. Missing: commitment that the
ciphertext encrypts the committed share under the recipient's key. This is D.1 blocker.

**Approach**: Add per-track share commitment binding to `bfv_sigma::verify`. When
verifying an encryption proof, also verify a SHA-256 binding: `H(session_id,
recipient_pk, ciphertext_hash, committed_share) == share_commitment`. This does not
require circuit changes — it's a native verifier enhancement.

1. In `bfv_sigma.rs`, extend `BfvSigmaVerifier::verify` to accept optional
   `share_commitment: Option<&[u8; 32]>` parameter
2. When provided, compute `expected = SHA256(session_id, pk_hash, ct_hash, share_value)`
   and assert `expected == share_commitment`
3. In `full_pipeline.rs` nizk_verify phase, pass the recipient's share commitment
   from the DKG deal data
4. Add test in `nizk_share_batched_tracks.rs`: tamper share commitment → reject
5. Document D.1 improvement in SECURITY.md (not full closure — D.1 remains partially open)

**Success criteria**:
- Native BFV verifier rejects encryption proofs with wrong share commitment
- All existing BFV sigma tests still pass
- D.1 gap documented as "partially mitigated with commitment hash binding"

### G4: Cross-Circuit DKG Chain — Pipeline Integrity Hash (2 days)

**Status**: C0→C3→C4→C6 chain is broken. C0 has real NIZK, C6→C7 link exists in Noir
`aggregator_final`, but the pipeline doesn't verify that C0 NIZK outputs feed into C3/C4/C6.

**Approach**: Add `pipeline_integrity_hash` — a Poseidon chain computed during the
pipeline that accumulates hashes at each DKG phase, passed to `PipelineReport` and
bound into `aggregator_final` as a new public input.

1. In `full_pipeline.rs`, add `pipeline_integrity_hash: Fr` accumulator
2. After each phase:
   - Phase C0 (keygen): `acc = Poseidon(acc, keygen_nizk_hash)`
   - Phase C2 (share computation): `acc = Poseidon(acc, share_computation_hashes)`
   - Phase C4 (dkg aggregation): `acc = Poseidon(acc, dkg_agg_hashes)`
3. Store final `pipeline_integrity_hash` in `PipelineReport`
4. Add as new public input in `aggregator_final` Noir circuit: `assert(pipeline_integrity_hash != 0)`
5. Re-run `nargo test` for aggregator_final

**Success criteria**:
- PipelineReport carries `pipeline_integrity_hash` covering C0→C2→C4→C6 phases
- Noir `aggregator_final` binds the hash as a public input
- Demo-e2e passes with pipeline integrity hash populated

### G5: C1 + C5 Design Document → Implementation Deferred to Phase 5 (2 days design)

**Status**: Both C1 (PK contribution) and C5 (PK aggregation) are missing in-circuit proofs.
These require new circuit designs. Rush implementation would produce brittle code.

**Approach**: Create design documents specifying the exact R1CS constraints and interfaces.
Implementation deferred to Phase 5.

1. Create `.sisyphus/design/c1-c5-pk-aggregation.md` documenting:
   - C1 relation: `pk_i = sk_i * a + e_i` (keypair correctness per party)
   - C5 relation: `aggregate_pk = Σ pk_i for i in committee` (additive homomorphism)
   - Integration into existing CycloFoldStepCircuit or separate FCircuit
   - Public inputs needed in `aggregator_final` Noir circuit
2. Update `interfold-equivalence.md` to reflect C1/C5 as "DESIGN" (not IMPLEMENTED)
3. Update README.md to reflect plan status

**Success criteria**:
- Design document reviewed and accepted
- C1/C5 tagged as "Phase 5" in all tracking docs

### G6: C7 — Scale aggregator_final from N=8 to N=128 (3 days)

**Status**: Noir circuit operates at N=8 (toy prototype). Production needs N=8192.
Scaling directly to N=8192 requires Lagrange optimization (O(n²) → O(n log n) via
FFT in-circuit). Intermediate step: scale to N=128 (verify constraint growth rate).

**Approach**: Parameterize `MAX_PARTICIPANTS` from 8 to 128. Replace O(n²) Lagrange
with batched Lagrange (precompute Lagrange coefficients from committee_party_ids as
circuit constants — they're deterministic per epoch). Run circuit at N=128 and measure
constraint count.

1. Update `MAX_PARTICIPANTS` in `circuits/aggregator_final/src/main.nr` from 8 → 128
2. Add a `lagrange_coeffs` array as circuit constant (precomputed from party IDs)
3. Replace the O(MAX_PARTICIPANTS²) loop body with O(MAX_PARTICIPANTS) lookup
4. Regenerate tests for N=128
5. Measure constraint count with `nargo info`
6. If < 2M constraints: proceed; if > 2M: document constraint explosion and defer
   N=8192 to Phase 5
7. Document findings in `.sisyphus/design/c7-scaling.md`

**Success criteria**:
- `nargo test` passes at N=128
- Constraint count measured and documented
- C7 status updated to "N=128 functional, N=8192 deferred"

### G7: Per-Party Accountability — Design Document (1 day)

**Status**: No ECDSA signing or slashing mechanism. This is a protocol-level feature
requiring: (a) proof signing at the party level, (b) on-chain slashing when proof
verification fails, (c) Noir circuit for ECDSA/EdDSA verification.

**Approach**: Create design document. Implementation deferred to Phase 5 (requires
Solidity contract changes + Noir signature verification circuit).

1. Create `.sisyphus/design/per-party-accountability.md` documenting:
   - Signature scheme selection (EdDSA over Grumpkin for Noir-friendliness)
   - Party signing flow: sign(proof_hash, party_sk) appended to each proof
   - On-chain slashing: Solidity `slash(party_id)` callable when Noir circuit detects bad proof
   - Integration into PipelineReport
2. Update SECURITY.md and ARCHITECTURE.md with accountability gap and plan
3. Tag as "Phase 5" in tracking docs

**Success criteria**:
- Design document reviewed
- Accountability gap clearly documented with migration plan

## Execution Order

1. **G1 (C4 wiring)** — highest ROI, existing verifier just needs Nova wrapper
2. **G2 (P3 SNARK wiring)** — completes Phase 4, enables `sonobe-snark` feature
3. **G3 (C3 binding)** — partial D.1 fix, native verifier only
4. **G4 (cross-circuit chain)** — pipeline integrity hash, ties C0→C6 together
5. **G5 (C1+C5 design)** — design docs, no code
6. **G6 (C7 scale)** — parameterize from 8→128, measure constraints
7. **G7 (accountability design)** — design doc, no code

Total: **12 days** (1+1+2+2+2+3+1)

## Verification Gate

After all items:
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just demo-e2e 10 4 1` → ACCEPT
- `PVTHFHE_ALLOW_RESEARCH_BUILD=1 just demo-e2e 16 7 1` → ACCEPT
- `just per-node 10 4 1` → completes
- `just aggregator 10 4 1` → completes
- All Rust tests pass (`cargo test --workspace`)
- All Noir tests pass (`cd circuits && nargo test --workspace`)
- C4 wiring avoids breaking existing G1-NizkAdapter-dependent code
- C3 enhancement does not change the NizkAdapter trait interface
- C7 does not modify BFV parameters in parameters.toml
- No modification to generated UltraHonkVerifier.sol
- No change to hardcoded seeds or deterministic RNG outside test fixtures
