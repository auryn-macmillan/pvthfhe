# Plan: Nova-Folded DKG Verification (Phase 4 Completion)

**Status**: DONE  
**Estimate**: ~1 day remaining  
**Depends on**: AjtaiCommitmentStepCircuit (done), prove_steps_ajtai (done), DKG parity-check proofs (Plan 1)

## Goal

Fold all per-recipient DKG share verifications into one compressed proof per recipient via Nova. Combined with parity-check proofs, this reduces verification from O(n²) to O(1) per recipient.

## Architecture

```
Per recipient:
  All dealer commitments → AjtaiCommitmentWitnessSet
    → SonobeCompressor::prove_steps_ajtai (Nova fold)
    → compressed proof (O(1) on-chain verification)
```

Already built: AjtaiCommitmentStepCircuit, AjtaiCommitmentWitness, prove_steps_ajtai, SonobeCompressor integration.

## Remaining Tasks

### Task 1: Complete DKG wiring (in progress)
- [x] Per-recipient AjtaiCommitmentWitnessSet from dealer commitments  
- [x] prove_steps_ajtai called per recipient
- [x] recipient_fold_hashes in PipelineReport
- [x] Verify that `recipient_fold_hashes[i]` equals `pipelinereport.recipient_fold_hashes[i]` by checking the log output after demo-e2e. The hash is a Fr value printed in the pipeline report summary. Assert that all n hashes are non-zero.
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --release -p pvthfhe-cli --features sonobe-compressor,demo-seeded-rng,pipeline-extra-checks -- demo --n 10 --threshold 4 --seed 1 2>&1 | grep "recipient_fold_hashes"` — outputs n non-zero hashes

### Task 2: Integrate with parity-check proofs
- [x] After parity proofs generated (Plan 1), fold parity proof hashes instead of per-share commitments
- [x] Parity proof hash ≡ proxy for all n share verifications
- [x] Update `AjtaiCommitmentWitness` to carry `parity_proof_hash: Fr` alongside `expected_commitment_hash`
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just demo-e2e 10 4 1` — ACCEPTS with parity-check proofs in pipeline report

### Task 3: Wire into aggregator and per-node
- [x] `per_aggregator.rs`: fold all recipient verifications into one proof via `prove_steps_ajtai`. Add after the existing compressor timing block around line 220.
- [x] `per_node.rs`: include parity-proof generation + Nova folding in timing. Add dkg_fold_ms to per-node report.
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --bin per-aggregator --features sonobe-compressor -- --n 10 --threshold 4 --seed 1 2>&1 | tail -10` — completes without error
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 cargo run --bin per-node --features sonobe-compressor -- --n 10 --threshold 4 --seed 1 2>&1 | tail -15` — dkg_fold line appears in output

### Task 4: Test
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just demo-e2e 10 4 1` — ACCEPTS
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just demo-e2e 16 7 1` — ACCEPTS
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just per-node 10 4 1` — completes
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just per-node 16 7 1` — completes
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just aggregator 10 4 1` — completes
- [x] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just aggregator 16 7 1` — completes
