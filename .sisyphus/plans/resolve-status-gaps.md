# Resolve Remaining Status Gaps — Meta-Plan

**Status**: COMPLETE — 5 sub-plans created, P3 applied to README
**Date**: 2026-05-28

## Current State

5 items in README have ⚠️ status. Each needs a different approach:

| Item | ⚠️ Reason | Fixable? | Approach |
|------|----------|----------|----------|
| **P3** | Docs stale — IVC actually works | ✅ Trivial | Update README |
| **P2** | Nova substitute works, lattice-native folding is aspirational | ⚕️ Partial | Symphony adoption (already started) |
| **P1** | Sigma ternary challenge (2/3 soundness) | ❌ Protocol change needed | Research plan |
| **P4** | On-chain verifier uses hash shortcut | ❌ Major engineering | Research plan |
| **C3** | Verifier lacks BFV encryption relation circuit | ❌ Missing circuit | Implementation plan |

## Meta-Plan Structure

```
.sisyphus/plans/
├── resolve-status-gaps.md          ← THIS FILE (meta-plan)
├── p3-compression-done.md          ← Mark P3 as ✅ (docs update)
├── p2-lattice-folding.md           ← Symphony adoption completion
├── p1-sigma-repetition.md          ← Sigma repetition for soundness
├── p4-onchain-ivc.md               ← Full IVC verification on-chain
└── c3-bfv-encryption-circuit.md    ← BFV relation Nova step circuit
```

## Sub-Plan Summaries

### P3 — Compression (5 min)
**Sub-plan**: `p3-compression-done.md`
**What**: Readme status ⚠️ → ✅. The nova-snark transparent IVC works end-to-end. Demo ACCEPTs at n=128. No Groth16 ceremony. CycloFoldStepCircuit arity=8 fixed with real sigma/ring/BFV verification.
**Task**: Update README status row.

### P2 — Lattice Folding (~2 weeks)
**Sub-plan**: `p2-lattice-folding.md`
**What**: Complete Symphony adoption (T1-T4 already implemented). The gap: Nova IVC works as a folding substitute, but the Symphony paper's lattice-native folding isn't yet integrated as a drop-in replacement. The T1 (high-arity folding) + T2 (FS outside circuit) techniques move us toward lattice-native folding but aren't yet the complete Symphony construction.
**Key steps**:
1. Complete T2 FS-outside-circuit integration (currently feature-gated, not in default path)
2. Integrate T1 high-arity folding into the default prove path
3. Benchmark against pure Nova IVC to quantify gains
4. Document Symphony-lattice-native path vs Nova substitute

### P1 — Sigma Repetition (~1-2 weeks)
**Sub-plan**: `p1-sigma-repetition.md`
**What**: The ternary scalar challenge provides ~1.58 bits of soundness per execution. With 1 round, soundness error is 2/3. Need ~90 parallel repetitions for 2^-128 soundness.
**Key steps**:
1. Add `SIGMA_REPETITIONS` constant (default: 1, secure: ~90)
2. Modify `sigma::prove` to run k rounds and produce a joint proof
3. Update `sigma_verify_step_bp` to verify k rounds
4. Compute soundness budget: Pr[false accept] ≤ (2/3)^k
5. Update sigma witness data to carry k-round data

### P4 — On-Chain IVC (~2-4 weeks)
**Sub-plan**: `p4-onchain-ivc.md`
**What**: The UltraHonk on-chain verifier (`sonobe_state_commitment/src/main.nr`) uses a Poseidon hash shortcut to bind the Nova state instead of verifying the full RecursiveSNARK proof.
**Key steps**:
1. Implement RecursiveSNARK verification in Noir (requires porting Nova's folded R1CS check)
2. Or: generate a Groth16/PLONK proof of RecursiveSNARK verification from nova-snark and verify that in Noir
3. Update `sonobe_state_commitment/src/main.nr` to call the IVC proof verification
4. Update `PvtFheVerifier.sol` to pass IVC proof as calldata
5. Update `CompressedProof` format to include the on-chain verifiable proof

### C3 — BFV Encryption Circuit (~1 week)
**Sub-plan**: `c3-bfv-encryption-circuit.md`
**What**: The verifier doesn't verify the BFV encryption relation (that ct = Encrypt(pk, m; r) for some randomness r). The sigma NIZK proves key correctness, and the Ajtai commitment binds the ciphertext, but there's no in-circuit check that the ciphertext is actually a valid BFV encryption.
**Key steps**:
1. Create `BfvEncryptionStepCircuit` implementing `nova_snark::StepCircuit`
2. Implement BFV encryption constraint in bellpepper (RNS-modular polynomial arithmetic)
3. Wire into the CycloFoldStepCircuit (add bfv_encryption verify as state element)
4. Thread batch BFV ciphertext commitment through the pipeline
5. Update `aggregator_final/src/main.nr` to check the BFV encryption hash

## Execution Order

```
P3 (docs) → P2 (Symphony completion) → P1 (sigma repetition) → C3 (BFV circuit) → P4 (on-chain IVC)
```

P2 and P1 are independent. C3 depends on the CycloFoldStepCircuit being stable. P4 is the most complex and furthest out.

## Success Criteria
- [ ] P3: README shows ✅ for Compression
- [ ] P2: Symphony techniques enabled by default, benchmarked
- [ ] P1: Sigma repetitions configurable, soundness budget documented
- [ ] C3: BFV encryption relation verified in-circuit
- [ ] P4: UltraHonk verifies full IVC proof, not just hash
