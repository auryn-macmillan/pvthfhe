# Internal Review — Protocol Correctness
**Reviewer**: Alice (Protocol Lead)
**Date**: 2026-05-03
**Scope**: P4 correctness/secrecy, P1 completeness/soundness/ZK, sequential composition

## Summary

Reviewed all five P4 theorems (T1–T5) and four P1 theorems (T1/T2/T3/T5). The proof
sketches in `docs/security-proofs/p4/` and `docs/security-proofs/p1/` are internally
consistent. The SHA-256 commitment scheme is used correctly as a binding primitive.

## Detailed Findings

### P4-T1 (Correctness)
The reconstruction argument over F_{2^61-1} is sound. Shamir interpolation at the
frozen field is implemented correctly in `crates/pvthfhe-keygen`. ✓

### P4-T2 (Secrecy)
The simulation uses fresh Shamir shares for corrupted parties. The Ring-LWE deferral
is clearly flagged. No claims are made beyond the simulation boundary. ✓

### P4-T3 (Public Verifiability)
SHA-256 commitment recomputation binds the dealer to a single dealing. The binding
argument reduces to SHA-256 collision resistance. ✓

### P4-T4 (Robustness) and P4-T5 (Sequential Composition)
Both proofs are well-scoped to the current interface. The composition theorem is
conservative and does not overstate the RLWE handoff. ✓

### P1-T1 (Completeness)
The SLAP core transcript equations are verified against the Rust implementation. ✓

### P1-T2 (Knowledge Soundness)
The straight-line extractor argument is correct for the SHA-256-binding instantiation.
The caveat about simulation extractability (P1-T4 deferred) is appropriately noted. ✓

### P1-T3 (Zero-Knowledge)
The HVZK-to-Fiat–Shamir compilation argument follows standard templates. ✓

### P1-T5 (Commitment Binding)
Binding holds unconditionally under SHA-256 collision resistance. ✓

## Issues Found

- **Minor**: P4-T2 should more explicitly state the adversary model (static corruption).
  Not a soundness issue; suggest adding one sentence in the paper.
- **Minor**: P1-T2 proof sketch does not explicitly bound the rewinding probability.
  Suggest adding the formal probability statement.

## Conclusion

All reviewed theorems are sound within their stated scope. The two minor issues are
editorial and do not affect the correctness of the results.

VERDICT: ACCEPT (with minor editorial revisions)
