# Plan: P3 M5 — Security Proofs for MicroNova + UltraHonk

**Plan**: `p3-m5-security-proofs`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P3-M1 through P3-M4
**Goal**: Complete the proof skeletons from `docs/security-proofs/p3/proof-skeletons.md`, providing formal soundness arguments for the P3 pipeline.

---

## Implementation

### P3-M5.1 — T1: UltraHonk knowledge soundness

**File**: `docs/security-proofs/p3/T1-ultrahonk-soundness.md` (update)

Document: UltraHonk knowledge soundness over BN254, referencing Aztec's security analysis. Note that the LatticeFold+ proof uses a subset of UltraHonk features (no lookup arguments), which may tighten the bound.

### P3-M5.2 — T2: MicroNova → UltraHonk soundness preservation

**File**: `docs/security-proofs/p3/T2-micronova-preservation.md` (update)

Prove that the MicroNova compression step preserves the knowledge soundness of the underlying Nova IVC. The reduction: if an adversary breaks MicroNova soundness, they break Nova IVC soundness (or the wrapper).

### P3-M5.3 — T4: Measured gas bound

**File**: `docs/security-proofs/p3/T4-gas-bound.md` (update)

Replace the projection (39,687) with the measured value from P3-M3/M4. Document the gas measurement methodology.

### P3-M5.4 — Documentation

- Update `p3-micronova-target.md` — mark M5 complete
- Update paper: §7.B (Track B) status

## Acceptance Criteria

- [ ] T1, T2, T4 proof documents updated
- [ ] Gas bound reflects actual measurement
- [ ] Demo ACCEPT

## Estimated Effort

~1-2 weeks. Documentation and proof-writing, not novel research.
