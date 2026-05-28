# README Update Plan — Align with Post-Migration State

**Status**: PLAN
**Date**: 2026-05-28

## Outdated Items

| Line | Current Text | Issue | Fix |
|------|-------------|-------|-----|
| 10 | "`.sisyphus/audit/AUDIT-2026-05-08.md`" | Missing 3rd audit + MPC audits | Add MPC audit references |
| 21 | "Nova Nova" (Sonobe dual-Nova) | 6 occurrences — Sonobe removed, Microsoft nova-snark used | Replace with "Microsoft Nova" or "Nova IVC" |
| 25 | "Nova Nova with Cyclo CCS witness representation" | Cyclo CCS folding removed | "nova-snark (Microsoft) Nova IVC" |
| 26 | "DeciderEth SNARK bridge feature-gated" | Groth16 removed | "Transparent IVC (no ceremony)" |
| 28 | "DeciderEth Groth16 bridge + nova-snark feature" | Groth16+feature removed | Replace with "Transparent IVC proof serialization, Keccak256 binding" |
| 31 | "nizk_keygen.rs" | File removed during repo cleanup | "sigma.rs (keygen NIZK integrated)" |
| 39-51 | Audit status table | Missing MPC audits and Symphony | Add rows |
| 62 | "Folding soundness ε_fold = 2⁻¹⁶⁰ (P1, P2, P3 aspirational)" | P2/P3 status changed | Update status |
| 69-73 | Open Problems table | P3 partially resolved (Nova works, CycloFold arity=8 fixed) | Update P3 status |
| 88 | "Folding uses Nova Nova as substitute for lattice-native folding (P2)" | "Nova Nova" removed | "nova-snark (Microsoft) Nova IVC" |

## What to Add

### New Features Since Original README

1. **Microsoft nova-snark migration** (from Sonobe `folding-schemes`)
2. **Transparent IVC** (no Groth16 ceremony — Aztec SRS only)
3. **3 MPC audit passes** (22+ findings fixed)
4. **Symphony paper techniques** (T1-T4, feature-gated)
5. **Per-node distributed timing** in demo-e2e output
6. **Zero Sonobe references** in codebase
7. **CycloFoldStepCircuit arity=8** (sigma/ring/BFV in-circuit verification)
8. **Production readiness improvements** (clean test suite, simplified docs)

### Updated Status Table

| Layer | Before | After |
|-------|--------|-------|
| Folding | "Nova Nova with Cyclo CCS" | "nova-snark (Microsoft) Nova IVC" |
| Compression | "DeciderEth Groth16 feature-gated" | "Transparent IVC (Keccak256 proof binding)" |
| IVC SNARK | "DeciderEth Groth16 bridge" | "Removed — transparent IVC, no ceremony" |

## Tasks

- [x] Update folding/compression/IVC status rows
- [x] Replace "Nova Nova" → "Nova IVC" across all sections
- [x] Add Microsoft nova-snark migration note
- [x] Update Groth16 → transparent IVC
- [x] Add MPC audit passes to audit status
- [x] Add Symphony techniques section
- [x] Update Open Problems P3 status
- [x] Fix file references (nizk_keygen.rs removed)
- [x] Add per-node timing output example
- [x] Verify all commands still work (quickstart section)
**Status**: COMPLETE
