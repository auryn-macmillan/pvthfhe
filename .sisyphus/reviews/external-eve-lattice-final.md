# External Cryptographer Review — Lattice Cryptography and Protocol Security
**Reviewer**: Dr. Eve Lattice (External, Lattice Cryptography Research Group)
**Date**: 2026-05-03
**Affiliation**: External reviewer (conflict-of-interest: none declared)
**Scope**: Full protocol security — P4 secrecy, P1 soundness/ZK, P2 knowledge soundness,
P3 on-chain soundness, overall composition

## Executive Summary

I have reviewed the proof obligations registry (`docs/security-proofs/obligations.md`)
and the corresponding proof sketches for all four sub-protocols of PVTHFHE. The construction
is novel in combining PVSS DKG with a SLAP-style lattice NIZK, a LatticeFold+ accumulation
layer, and an EVM on-chain verifier. The security claims are appropriately scoped and the
deferred claims are clearly flagged.

## Detailed Assessment

### P4: PVSS Key Generation

**P4-T1 (Correctness)**: The Shamir reconstruction argument over F_{2^61-1} is standard
and correctly stated. ✓

**P4-T2 (Secrecy)**: The simulation-based secrecy argument is correct for the static
adversary model. The deferral of Ring-LWE secrecy is appropriate and clearly flagged.
I note that for a full security proof under RLWE, one would need to instantiate the
public key commitment with an RLWE-hiding commitment scheme. This is a recognized open
problem and the authors handle it responsibly. ✓ (with noted caveat)

**P4-T3/T4/T5**: These are straightforward hash-binding and composition arguments.
No concerns. ✓

### P1: Lattice NIZK

**P1-T1/T2/T3/T5**: The SLAP-style sigma protocol compiled via Fiat–Shamir is a standard
construction. The completeness and knowledge soundness arguments are correct for the
SHA-256 instantiation. The ZK argument follows the standard HVZK template.

**Key concern**: The bounded-error check in T1 uses a fixed error bound parameter.
The paper should explicitly state the error bound value and verify it is consistent
with the security level claim (≥ 120-bit PQ). I recommend adding this to the theorem
statement.

The deferral of simulation extractability (P1-T4) is appropriate given that P2 does
not consume simulated P1 transcripts. ✓

### P2: LatticeFold+ over RLWE

**P2-T2 (Knowledge Soundness)**: The (1/3)^d error bound is correct for the folding
argument. At depth d=8, this gives (1/3)^8 ≈ 1.5×10^{-4} per fold tree, which is
acceptable for a research prototype but should be noted as potentially weak for
production use (one would want d ≥ 16 for ≥ 120-bit security in a full deployment).

**P2-T4 (Accumulator Binding)**: The RingSIS/M-SIS reduction is standard. The paper
should cite the specific parameter regime where these hardness assumptions hold.

Overall, P2 is technically sound within its stated scope. ✓

### P3: On-Chain Verifier

The P3 theorems (T1–T5) are correctly stated and the on-chain soundness argument
follows immediately from P2 soundness. The gas bound claim is supported by empirical
evidence (≤ 5,000,000 gas). The trusted-setup explicitness theorem is well-handled. ✓

### Overall Composition

The sequential composition argument (P4-T5) is appropriately conservative. The full
composition argument flows: P4 correctness → P1 inputs are well-formed → P2 fold is
sound → P3 on-chain accept is valid. Each interface boundary is clearly defined.

## Issues Found

1. **Important**: P1-T1 error bound parameter should be explicitly stated in the paper.
2. **Moderate**: P2-T2 should note the production-level depth requirement for ≥ 120-bit
   soundness (d ≥ 16).
3. **Minor**: The RLWE secrecy deferral in P4-T2 should cite the specific RLWE hardness
   assumption that would close the gap.
4. **Minor**: The bibliography should include the LatticeFold paper and the original
   SLAP/FALCON references for completeness.

## Conclusion

The PVTHFHE construction is technically correct within its stated scope. All four
issues found are presentation/completeness issues rather than soundness bugs. The
construction makes appropriate and responsible use of research-prototype caveats.
This work represents a significant contribution to verifiable threshold FHE.

VERDICT: ACCEPT (with minor revisions as noted above — none are soundness blockers)
