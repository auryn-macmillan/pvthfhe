# Performance + Security Audit — Remediation Plan

**Status**: PLAN
**Date**: 2026-05-28

## HIGH Severity (4 findings)

### H1 — Sigma data absence = free pass
**File**: `crates/pvthfhe-compressor/src/nova/mod.rs:2723`, `2737`
**Issue**: `sigma_count != Fr::zero()` guard means zero sigma count passes verification. A malicious prover clears thread-locals before prove → valid IVC proof with zero verification.
**Fix**: Remove both guards. Change to: `if fold_count != sigma_count { return Ok(false); }`
**Effort**: 2 lines

### H2 — Thread-local data not bound to DKG transcript
**File**: `crates/pvthfhe-compressor/src/nova/mod.rs:719-741`
**Issue**: `set_sigma_data`, `set_cyclo_ring_data` accept arbitrary data. Malicious prover can inject fake witnesses.
**Fix**: Add `sigma_data_hash` field to IVC proof state. Hash all sigma data via Poseidon before prove. Verifier checks hash matches at verify time.
**Effort**: ~30 min

### H3 — DealerParityStepCircuit P(0) binding off-circuit
**File**: `crates/pvthfhe-compressor/src/nova/dealer_parity_circuit.rs:187-189`
**Issue**: `nova_snark::StepCircuit` trait lacks external inputs — can't enforce P(0) == claimed_secret in-circuit. Legacy ark-r1cs backend does enforce it (line 133).
**Fix**: Add a `p0_commitment` state field to the circuit. Compute Poseidon(P(0)) = p0_commitment during synthesize. Verifier checks p0_commitment == claimed_commitment.
**Effort**: ~1 hr

### H4 — FoldVerifierStepCircuit is placeholder
**File**: `crates/pvthfhe-compressor/src/nova/fold_verifier_circuit.rs:1-18`
**Issue**: Circuit increments counters but provides ZERO actual verification. Recursive compression path non-functional.
**Fix**: Implement real FoldVerifierStepCircuit constraints. Deferred to G.17 task.
**Effort**: ~4-6 hrs (deferred)

## MEDIUM Severity (2 findings)

### M1 — share_verification_hash hardcoded to zero
**File**: `crates/pvthfhe-compressor/src/nova/snark_bridge.rs:126`
**Issue**: `wrap_nova_instance` sets `share_verification_hash: [0u8; 32]`. On-chain verifier rejects zero.
**Fix**: Accept `share_verification_hash` as parameter. Compute from actual share verification results in `full_pipeline.rs`.
**Effort**: ~15 min

### M2 — C4/C5 verify failures non-fatal
**File**: `crates/pvthfhe-cli/src/full_pipeline.rs:593-598`, `1014-1017`
**Issue**: Pipeline continues after IVC verification failure.
**Fix**: Change `tracing::warn!` to `anyhow::bail!` for C4/C5 verify failures.
**Effort**: 4 lines

## Performance (2 findings)

### P1 — dkg_deal pre-computation
**Finding**: Each dealer performs BFV keygen + PVSS share gen + sigma NIZK proving. Sigma proof depends only on dealer's own key (not on other dealers' messages) — can be pre-computed.
**Fix**: Pre-compute sigma NIZK proof in keygen phase. Defer share generation to deal phase. Saves ~30% of per-dealer time.
**Effort**: ~2 hrs

### P2 — Nova IVC is sequential O(n) per prove_steps call
**Finding**: `prove_steps` does n sequential `RecursiveSNARK::prove_step` calls. Symphony T1 (high-arity folding) reduces proof-header calls but NOT Nova accumulator steps.
**Fix**: Modify step circuit to accept batch-folded witness data in single step. Deferred to T1 completion (p2-lattice-folding.md).
**Effort**: ~4-6 hrs (deferred)

## Remediation Tasks

### Wave 1 — Immediate (HIGH, ~2 hrs)
- [ ] H1: Remove sigma_count/bfv_count zero guards in verify_ivc_core
- [ ] H2: Add sigma_data_hash to IVC proof state
- [ ] M1: Compute share_verification_hash from actual results
- [ ] M2: Make C4/C5 verify failures fatal

### Wave 2 — Short-term (MEDIUM, ~1 hr)
- [ ] H3: Enforce P(0) binding in nova-snark DealerParityStepCircuit

### Wave 3 — Deferred (LONG-TERM)
- [ ] H4: Implement real FoldVerifierStepCircuit constraints (G.17)
- [ ] P1: Pre-compute sigma NIZK in keygen phase
- [ ] P2: Batch-folded witness data in Nova step circuit

## Success Criteria
- [ ] `cargo check --workspace` = 0 errors
- [ ] `just demo-e2e` runs with ACCEPT
- [ ] Sigma data absence detected by verifier
- [ ] Thread-local data cryptographically bound to proof
- [ ] C4/C5 verify failures are fatal
