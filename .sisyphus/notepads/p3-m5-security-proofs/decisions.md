# Decisions — P3-M5 Security Proofs

## 2026-05-14

### Decision: Create new files alongside existing T*.md

The existing `T1.md`, `T2.md`, `T4.md` files in `docs/security-proofs/p3/` represent an earlier ECDSA-based on-chain verifier phase. Rather than overwriting them, new files with descriptive suffixes were created:
- `T1-ultrahonk-soundness.md`
- `T2-micronova-preservation.md`
- `T4-gas-bound.md`

**Rationale**: Preserving the ECDSA-era documents provides a historical record of the verifier's evolution and avoids confusion about which theorem variant is current. The new filenames make clear they are the UltraHonk/MicroNova refinements.

### Decision: All three documents marked DEFERRED

All three proof documents carry a `DEFERRED` status with explicit deferral rationale sections. This is consistent with the P3-M5 plan, which notes that these proofs depend on P3-M2 (real proof generation) and P3-M3 (EVM deployment), neither of which has completed.

**Rationale**: Marking them DEFERRED is honest about the current state of analysis. The documents capture the theorem statements, proof sketches, and reduction targets so that work can resume immediately when prerequisites are met.

### Decision: Proof skeleton format partially adopted

The P3-M5 documents use a simplified document structure inspired by but not identical to the proof-skeletons.md format. Each document includes: Statement, Proof Sketch, Dependencies, Open Gaps, and Deferral Rationale sections. The full five-section theorem-proof format from `docs/security-proofs/README.md` is not strictly followed because these are deferred outlines rather than completed proofs.

### Decision: Gas baseline of 39,687 used as floor, not ceiling

The 39,687 gas figure from Aztec's reference implementation is treated as a lower bound (floor), not an upper bound (ceiling). The actual gas consumption for the LatticeFold+ UltraHonk verifier is projected to be higher due to additional constraints and pairing checks. The 5,000,000 gas ceiling from P3-T4 remains the binding safety constraint.
