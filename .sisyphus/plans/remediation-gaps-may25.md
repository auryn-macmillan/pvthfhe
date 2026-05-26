# Remediation: Remaining Gaps from May 25 Implementation

**Status**: PLAN
**Parent**: remove-groth16-and-fix-gaps.md

## Gap Audit

Five gaps remain from the original prompt:

### G1 — sz_r2_eval (cyclotomic quotient) missing
**File**: `crates/pvthfhe-compressor/src/sonobe/mod.rs`
**Line**: SigmaWitness struct (~404-409)
**Missing**: `pub sz_r2_eval: Vec<u64>` field for cyclotomic quotient per RNS limb.
**Impact**: MEDIUM — Incomplete S-Z witness. The cyclotomic quotient r2 = (c(g)·z_s(g) + z_e(g) - t(g) - ch·d_i(g)) / (X^N+1)(g) verifies the polynomial equation mod the cyclotomic polynomial, needed for full RLWE soundness.
**Fix**: Add field to struct; populate in compute_sigma_sz_data; add constraint in sigma_verify_step.

### G2 — LagrangeFoldStepCircuit not in heterogeneous pipeline
**File**: `crates/pvthfhe-compressor/src/sonobe/latticefold_circuit_family.rs`
**Missing**: Registration in `LatticeFoldTreeCircuitFamily` (NOT HeterogeneousStepCircuit — that's a struct, not an enum). Add third variant (index=2, "lagrange_fold") to `circuit_index()` and `num_circuits()`.
**Impact**: MEDIUM — Circuit compiles but can't participate in heterogeneous folding.
**Fix**: Add `circuit_index(i) = 2` case returning `CircuitType::LagrangeFold`; expand `num_circuits()` from 2 to 3.

### G3 — ivc_snark_proof_hash not wired through pipeline
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs` line 2046 + `crates/pvthfhe-compressor/src/sonobe/mod.rs`
**Current**: `ivc_snark_proof_hash: None`
**Required**: `wrap_nova_instance` is called inside `SonobeCompressor::prove()` in mod.rs (NOT in full_pipeline.rs). Need to expose `pp_hash` through `CompressedProof`. Add `ivc_proof_hash: Option<[u8; 32]>` field to `CompressedProof`, populate it from `wrapped.pp_hash` during prove(), then read it in full_pipeline.rs.
**Impact**: HIGH — binding path unreachable.
**Fix**: Add `ivc_proof_hash` field to `CompressedProof` in compressor lib.rs; set from `wrapped.pp_hash` in mod.rs prove(); read in full_pipeline.rs.

### G4 — Keccak256 hash of IVC proof not computed
**File**: `crates/pvthfhe-compressor/src/sonobe/snark_bridge.rs`, line 50-54
**Current**: Uses raw `nova_instance.pp_hash` (public parameter hash, not proof hash).
**Required**: Compute `Keccak256(ivc_bytes)` as the proof hash for binding.
**Impact**: LOW — The current pp_hash is still a valid binding, but not specific to this proof instance. Using Keccak256(ivc_bytes) binds to the exact proof contents.
**Fix**: Add `use sha3::{Digest, Keccak256}; let ivc_hash = Keccak256::digest(&ivc_bytes);` and store in pp_hash.

### G5 — Share provenance not checked in LagrangeFoldStepCircuit
**File**: `crates/pvthfhe-compressor/src/sonobe/lagrange_fold_circuit.rs`
**Missing**: `assert(share_hash_var == registered_share_hashes[i])` constraint.
**Impact**: MEDIUM — Lagrange sum is computed but shares aren't bound to DKG-registered commitments.
**Fix**: Add `registered_share_hashes` to LAGRANGE_DATA type (change to `Vec<(Fr, Fr, Fr)>` with third field being the registered hash). Add equality constraint in generate_step_constraints.

## Remediation Tasks
- [x] G3: Expose ivc_proof_hash via CompressedProof → PipelineReport
- [x] G4: Compute Keccak256(ivc_bytes) as proof hash in snark_bridge.rs
- [x] G1: Add sz_r2_eval field + populate + constrain
- [x] G5: Add share provenance check (3rd field in LAGRANGE_DATA)
- [x] G2: Register in LatticeFoldTreeCircuitFamily (3rd variant)
- [x] Build: cargo build ✅ cargo test: 36 passed ✅

**Status**: COMPLETE
