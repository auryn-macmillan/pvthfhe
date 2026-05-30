# Greco+E3 Audit Remediation Plan

**Status**: PLAN
**Date**: 2026-05-30
**Branch**: feat/greco-e3-compute-provider

## Audit Findings

### H1 — BfvEncryptionSnapshot: Public-input/witness disconnect (HIGH)
**File**: `crates/pvthfhe-compressor/src/nova/bfv_snapshot.rs:175-207`
**Issue**: `prove_bfv_snapshot` creates a `BfvEncryptionSnapshot::default()` (empty pk_rns/ct_rns) for circuit synthesis. The in-circuit S-Z check reads pk/ct from **thread-local** `BFV_ENCRYPTION_DATA`. The proof header binds to the caller's real pk/ct values. A malicious prover can prove ANY witness data and stamp the verifier's pk/ct into the header.
**Fix**: Allocate pk_rns/ct_rns as circuit witnesses using `AllocatedNum::alloc_input`, enforce equality with the values from `BFV_ENCRYPTION_DATA`, and bind the public_inputs_hash to these allocated inputs.

### H2 — FheComputeStepCircuit: Native-only enforcement (HIGH)
**File**: `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs`
**Issue**: Merkle proof verification and FHE operation enforcement are native Rust, not in-circuit. The circuit only enforces merkle_root == z[1] and step_count++. A malicious prover can skip all actual verification.
**Fix**: Implement Merkle proof verification gadget in bellpepper. Add in-circuit constraints for Add (ct_out[l] = ct0[l] + ct1[l] mod q[l]), Mul (RNS multiplication + relinearization), and NoiseEval. Bind operation output to the accumulator.

### M1 — Missing compute verify (MEDIUM)
**File**: `crates/pvthfhe-cli/src/main.rs:180-191`, `full_pipeline.rs:1319`
**Issue**: `ComputeCommand` enum has no `Verify` variant. Demo-e2e never calls `verify_steps` on the compute proof.
**Fix**: Add `ComputeCommand::Verify`, call `verify_steps` in the CLI and in demo-e2e.

## Remediation Tasks

### Wave 1 — Immediate (H1, M1)
- [ ] H1: Wire snapshot pk/ct into circuit inputs via AllocatedNum::alloc_input
- [ ] M1: Add ComputeCommand::Verify CLI subcommand
- [ ] M1: Call verify_steps on compute proof in demo-e2e

### Wave 2 — FheComputeStepCircuit in-circuit (H2)
- [ ] H2: Implement Merkle proof verification gadget in bellpepper
- [ ] H2: Add in-circuit FHE operation constraints (Add/Mul/Relin)
- [ ] H2: Bind output_hash to actual operation result

## Success Criteria
- [ ] `cargo check` = 0 errors
- [ ] `just greco` verifies pk/ct binding
- [ ] `just compute` verifies FHE operations
- [ ] `just demo-e2e` includes compute proof verification
