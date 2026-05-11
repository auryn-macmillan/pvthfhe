# R7.3 Decision: share_wf Circuit

**Date**: 2026-05-09
**Decision**: DELETE
**Rationale**: The `share_wf` (Share Well-Formedness) circuit was a surrogate placeholder for a LatticeFold+ NIZK that would prove encrypted shares are well-formed (binding to party secret key, correct encryption, etc.). Under the current architecture, the R3 NIZK output (partial-decryption shares from `decrypt_share`) is what gets aggregated by `aggregator_final`. The well-formedness of encrypted shares is proven by the NIZK protocol itself (T3: Fiat-Shamir transcript absorbs `pvss_commitment`), not by a standalone circuit. Since no other task depends on `share_wf` for Stage 1 remediation, and the circuit logic is out of scope for the current proof system design, the default disposition is deletion.

**Impact**:
- `circuits/share_wf/` removed from workspace `circuits/Nargo.toml`
- No CI dependencies on `share_wf`
- If well-formedness proofs are needed later, they should be part of a new circuit designed against the real NIZK transcript structure

**Alternatives considered**:
- Keep as a stub: rejected — creates dead code and confusion about scope
- Formalize into a real circuit: rejected — out of scope for this remediation wave; R3 NIZK already handles well-formedness
