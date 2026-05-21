# Plan: Claude-Inspired DKG Improvements

**Status**: DESIGN — Most improvements already implemented. Two remaining gaps to close.

## What's Already Done

| Claude's Requirement | Our Implementation | Status |
|---------------------|-------------------|--------|
| 1. Small norm (`‖s_i‖ ≤ B`) | G7b L2 norm accumulation in CycloFoldStepCircuit (state_len=7) | ✓ |
| 2. Correct sharing (polynomial structure) | `parity.rs` — RS parity-check proof per dealer | ✓ |
| 3. Valid encryption (RLWE under recipient PK) | `deal()` with NIZK verification per share | ✓ |
| 4. Small error (`‖e_i‖ ≤ B_err`) | G7b z_e_sq_acc accumulation | ✓ |
| O(n²) → O(n) proofs | Parity-check: n proofs/dealer → 1 proof/dealer | ✓ |
| O(n²) → O(1) verification | Nova-folded DKG via AjtaiCommitmentStepCircuit | ✓ |

## Remaining Gaps

### Gap 1: Parity proof witness binding
The parity proof currently validates polynomial structure (condition 2) but doesn't cryptographically bind the NORM witness (condition 1) or the encryption witness (condition 3). A malicious dealer could produce shares that pass the parity check but violate norm bounds.

**Fix**: Embed the norm witness hash and encryption validity hash into the parity proof commitment. The parity proof becomes a combined commitment: `ParityProof = {polynomial_coeffs, norm_witness_hash, encryption_validity_hash}`. The verifier checks all three in O(1).

### Gap 2: Document Labrador approach
Labrador (Fenzi et al. 2023) provides efficient lattice ZKPs for norm bounds. Our current approach (L2 accumulation in R1CS) works but is expensive. Documenting the Labrador approach as the recommended upgrade path for production.

## Tasks

### Task 1: Extend parity proof with norm + encryption witness binding
- [ ] Add `norm_witness_hash: [u8; 32]` and `encryption_validity_hash: [u8; 32]` to `ParityProof`
- [ ] `prove_parity()` computes these hashes from the witness data
- [ ] `verify_parity()` checks all three hashes
- [ ] QA: `cargo test -p pvthfhe-pvss parity_extended`
- [ ] Wire: demo-e2e, per-node already call parity verification

### Task 2: Document Labrador approach
- [ ] Add `.sisyphus/notepads/labrador-norm-proofs.md` with reference
- [ ] Note in SECURITY.md that Labrador is the recommended upgrade path for in-circuit norm proofs
- [ ] No code changes

### Task 3: QA and doc sync
- [ ] `just demo-e2e 10 4 1` ACCEPTS
- [ ] `just demo-e2e 16 7 1` ACCEPTS
- [ ] SECURITY.md updated with parity proof witness binding note
- [ ] paper/main.tex updated if tracking specific DKG improvements
