# Batch B Decisions — 2026-05-13

## P4 Provenance: BOTH
**Decision**: All P4 claims (PVSS) marked BOTH.
**Rationale**: P4 is the PVSS infrastructure layer — SHA-256 commitments, BN254 Shamir secret sharing. It is shared between both the concrete Nova track and the theoretical LatticeFold+ track. No track divergence at P4.

## P2-T2 Provenance: TARGET (not SURROGATE)
**Decision**: P2-T2 marked TARGET rather than SURROGATE.
**Rationale**: The proof file explicitly states "LatticeFold+ refinement" and "contingent on Lemma 9 (CONJECTURE)". While the current code uses Nova, the formal theorem statement and proof skeleton are written for the target LatticeFold+ system. B.2 only instructs reclassifying T1/T3/T5 as SURROGATE — T2 was already CONTINGENT and is target-specific.

## P2-T4 Provenance: TARGET (not SURROGATE)
**Decision**: P2-T4 marked TARGET rather than SURROGATE.
**Rationale**: The claim is about RingSIS/M-SIS binding which is the target lattice commitment. Current SHA-256 surrogate is noted parenthetically. The CONDITIONAL status depends on "linear lattice commitment replacement" — a target-path change. B.2 only instructs reclassifying T1/T3/T5.

## P3-T3 Provenance: BOTH
**Decision**: P3-T3 marked BOTH.
**Rationale**: Plan B.3 says "keep as-is with note about KZG for target path." The trusted-setup explicitness claim applies to both the ecrecover surrogate path (no trusted setup needed) and the UltraHonk target path (KZG SRS). The proof covers both scenarios.

## P3-T4 Provenance: BOTH
**Decision**: P3-T4 marked BOTH.
**Rationale**: Plan B.3 explicitly says "P3-T4 (Gas Bound) is empirically validated for both — mark BOTH." The ≤5,000,000 gas bound holds regardless of which verification path is used (ecrecover at 5,273 gas or UltraHonk at 39,687 gas). Forge test confirms both paths stay within budget.

## Batch D Decisions (2026-05-13)

### D.1: Dual-track architecture placement
**Decision**: Placed dual-track transition paragraph at the start of §6 (P2) rather than §4 or §1. Rationale: P4 and P1 are shared between tracks; the divergence point is at P2. The §6 intro paragraph clearly describes both tracks and references the relevant subsections.

### D.2/D.3: Theorem naming convention
**Decision**: Track A theorems use P2-A-T1..T5, P3-A-T1..T5. Track B uses P2-B-T1..T5, P3-B-T1..T5. LaTeX labels use lowercase: `thm:p2a-t1` etc. This avoids namespace collisions with old labels (`thm:p2-t1` etc.) which were removed.

### D.4: P3 Track A content
**Decision**: Merged the updated P3 text from Batch A (mentioning Nova Nova IVC compression) with the dual-track structure. The Track A subsection acknowledges both the ecrecover on-chain surrogate and the Nova off-chain verifier.

### D.5: Claims table dual-column approach
**Decision**: Used two separate status columns (Track A Status, Track B Status) rather than splitting into separate rows. This keeps one row per claim while clearly showing track-specific status. P4/P1 rows use "(shared)" designation since both tracks use the same implementations.

### D.6: Plan file structure
**Decision**: Each plan follows a consistent template: goal, blocked dependencies (table), research milestones (M1-M5), estimated effort, cross-references. This enables future teams to quickly understand what's needed and what's blocking.
