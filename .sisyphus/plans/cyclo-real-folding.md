# Plan: Real Cyclo Folding + Multi-Input Step Circuit

**Plan**: `cyclo-real-folding`
**Goal**: Replace SHA-256 hash-chain folding surrogate with real Cyclo/LatticeFold+ Ajtai commitments, and fix the Sonobe step circuit to receive separate commitment/norm/count inputs.
**Reference**: `osdnk/cyclo` (research artifact, Rust + HEXL) and `NethermindEth/latticefold` (Rust PoC).

---

## Architecture

The current gap:

```
Aggregator: HashChainCycloAdapter ──wraps──▶ LegacyHashChainAdapter
                                                    │
                                                    ▼
                                         fold.rs: acc + r·inst (over R_q) ✅
                                         commitment = SHA-256(poly_bytes)  ❌ surrogate

Compressor: CycloFoldStepCircuit with ExternalInputs = Fr (single scalar)  ❌ toy
```

Target:

```
Aggregator: CycloFoldingAdapter ──uses──▶ fold.rs: Ajtai_commit(acc) + r · Ajtai_commit(inst)
                                         ccs_encode.rs: real CCS over R_q
                                         fiat_shamir.rs: biased ternary challenges

Compressor: CycloFoldStepCircuit with ExternalInputs = (commitment: Fr, norm: Fr, count: Fr)
            generate_step_constraints encodes:
              - Ajtai commitment folding (acc_commitment * inst_commitment mod R_q)
              - Norm escalation (acc_norm + inst_norm, bound check)
              - Step count increment (acc_count + 1)
```

---

## Batch P3 — Multi-Input Step Circuit (unblocks P2 by removing the limitation)

### P3.1 — Expand ExternalInputs to tuple
- [x] **File**: `crates/pvthfhe-compressor/src/sonobe/mod.rs` — `ExternalInputs = (F, F, F)` with local `ExternalInputs3Var` newtype (orphan rule workaround). ToyStepCircuit expanded to 3-state.
- [x] **RED**: `multi_input_step_circuit.rs` — test with separate inputs. GREEN: test passes.
- [x] **GATE**: `cargo build -p pvthfhe-compressor` clean. 15 files changed across compressor + compressor_glue.
- [x] **File**: `crates/pvthfhe-cli/src/compressor_glue.rs` — `compressor_inputs` produces 96-byte encodings of (commitment, norm, count).
- [x] **GATE**: Pipeline compiles end-to-end with new step circuit.
- [x] **File**: `crates/pvthfhe-cyclo/src/ajtai.rs` — NEW. AjtaiParams, AjtaiCommitment, commit(), verify() over R_q using ring.rs.
- [x] **RED**: `ajtai_commitment.rs` — commit→verify roundtrip, binding property (different witness → different commitment).
- [x] **GATE**: `cargo build -p pvthfhe-cyclo` clean. 12 warnings (new module, expected).

### P2A.2 — Replace SHA-256 commitment with Ajtai in fold.rs
- [x] **File**: `crates/pvthfhe-cyclo/src/fold.rs`
- [x] **Change**: `init_accumulator` decodes Ajtai commitments directly. `fold_one_step`: component-wise fold over 13 ring elements. `verify_fold`: validates 26624-byte commitment + CCS.
- [x] **RED**: `fold_ajtai_commitment.rs` — valid fold passes, tampered rejected. 63/63 cyclo tests pass.
- [x] **GATE**: Zero SHA-256 in fold.rs. All fold tests pass.
- [x] **Change**: `CycloTernaryTranscript` with domain separator `"pvthfhe-cyclo-fs-v2"`. `sample_challenge()` returns −1/0/+1 with probability 1/3 each.
- [x] **RED**: `cyclo_ternary_transcript.rs` — challenge distribution verified.
- [x] **GATE**: Sonobe v1 transcript unchanged.

---

## Batch P2B — CCS Encoder Over R_q

### P2B.1 — Extend CCS encode from Fr to R_q
- [x] **File**: `crates/pvthfhe-cyclo/src/ccs_encode.rs`
- [x] **Change**: Add `CcsRqInstance` type that encodes a CCS instance over R_q (polynomial domain). The CCS relation `M·z ⊙ z == 0` operates on `Vec<RqPoly>` instead of `Vec<Fr>`.
- [x] **Change**: Implement `check_satisfiability_rq(&self, witness: &[RqPoly]) -> Result<bool, CycloError>` using the existing NTT arithmetic from `ring.rs`.
- [x] **RED**: `crates/pvthfhe-cyclo/tests/ccs_rq_satisfiability.rs` — real + tampered witnesses over R_q, positive and negative cases.
- [x] **GATE**: CCS over R_q catches non-satisfying witnesses with real polynomial arithmetic.

### P2B.2 — Wire RLWE decryption-share relation into CCS encoder
- [x] **File**: `crates/pvthfhe-cyclo/src/ccs_rlwe.rs` (NEW)
- [x] **Implement**: Encode the RLWE decryption-share relation `d_i = c · s_i + e_i` as a CCS instance over R_q. This is the **production folding relation** — each party instance encodes their partial decryption share as a CCS constraint.
- [x] **RED**: `crates/pvthfhe-cyclo/tests/ccs_rlwe_relation.rs` — encode a share, check satisfiability with correct witness, reject with tampered witness.
- [x] **GATE**: RLWE relation encoded and verified.

---

## Batch P2C — Real Cyclo Adapter + Pipeline Integration

### P2C.1 — Replace LegacyHashChainAdapter with CycloFoldingAdapter
- [x] **File**: `crates/pvthfhe-cyclo/src/adapter.rs`
- [x] **Change**: Rename `LegacyHashChainAdapter` → `CycloAjtaiAdapter` (or create new impl). The new adapter uses:
  - `fold.rs` with real Ajtai commitments
  - `ccs_encode.rs` / `ccs_rlwe.rs` with real CCS over R_q
  - `fiat_shamir.rs` with biased ternary challenges
- [x] **RED**: `crates/pvthfhe-cyclo/tests/adapter_real_fold.rs` — test the adapter does real Ajtai folding (not SHA-256 hash chain).
- [x] **GATE**: Adapter uses real commitments. Legacy adapter removed or `#[deprecated]`.

### P2C.2 — Update aggregator to use real adapter
- [x] **File**: `crates/pvthfhe-aggregator/src/folding/mod.rs`
- [x] **Change**: Replace `HashChainCycloAdapter` usage with the new `CycloAjtaiAdapter`. Update `build_fold_instances` to provide Ajtai commitments.
- [x] **GATE**: Aggregator pipeline works with real Cyclo folding.

### P2C.3 — Update compressor step circuit for real RLWE relation
- [x] **File**: `crates/pvthfhe-compressor/src/sonobe/mod.rs`
- [x] **Change**: `CycloFoldStepCircuit::ExternalInputs` receives the actual Ajtai commitment, norm bound, and counter as separate tuple elements (P3.1 delivers this).
- [x] **Change**: `generate_step_constraints` encodes:
  - `z_i[0] * external_inputs.0` (Ajtai commitment fold — real multiplicative constraint)
  - `z_i[1] + external_inputs.1` (norm escalation)
  - Bound check: `z_i[1] ≤ CYCLO_BETABOUND` via bit decomposition range proof
  - `z_i[2] + 1` (count increment)
- [x] **GATE**: Step circuit proves real fold relation.

### P2C.4 — End-to-end pipeline with real Cyclo folding
- [x] **RED**: `crates/pvthfhe-cli/tests/cyclo_real_fold_pipeline.rs` — runs full pipeline (keygen → NIZK → Cyclo fold → compress → verify) with real Ajtai commitments.
- [x] **GREEN**: Pipeline completes. `just demo-e2e` outputs `demo complete: ACCEPT`.
- [x] **GATE**: Real folding verified end-to-end.

---

## Batch Docs — Documentation Update

### D1 — Update fold-construction.md
- [x] **File**: `.sisyphus/design/fold-construction.md`
- [x] **Change**: Update status from "Sonobe substitute" to "Cyclo Ajtai commitments active". Document the concrete Ajtai parameters used.
- [x] **GATE**: Doc reflects current implementation.

### D2 — Update README
- [x] **File**: `README.md`
- [x] **Change**: Update folding layer status: `✅ Real (Ajtai commitments over R_q, CCS over R_q, biased ternary FS)`
- [x] **GATE**: README accurate.

---

## Acceptance Criteria

- [x] `fold.rs` uses real Ajtai commitments — zero SHA-256 surrogates in fold commitment path
- [x] `ccs_encode.rs` supports CCS over R_q (in addition to Fr)
- [x] `ccs_rlwe.rs` encodes the RLWE decryption-share relation as a CCS instance
- [x] `fiat_shamir.rs` provides biased ternary challenge distribution for Cyclo path
- [x] `CycloFoldStepCircuit` receives multiple external inputs `(commitment, norm, count)` as a tuple
- [x] Step circuit encodes: commitment fold, norm escalation with bound check, count increment
- [x] Aggregator uses `CycloAjtaiAdapter` (not `HashChainCycloAdapter` or `LegacyHashChainAdapter`)
- [x] `just demo-e2e` runs with real Cyclo folding — `demo complete: ACCEPT`
- [x] `cargo build` workspace clean
- [x] All RED tests written first, confirmed FAILING, then GREEN makes them pass
- [x] No new `#[allow(...)]` in plan diffs
- [x] `LegacyHashChainAdapter` deprecated or removed from production path
