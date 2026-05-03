# P1 Interface Review Memo

Date: 2026-05-03
Task: B.D.1 — P1 frozen interface spec

VERDICT: APPROVE

## Summary

- The frozen interface separates the semantic P1 decrypt-share relation from any concrete proving backend.
- The statement encoding binds the inherited P4 commitment hash, caller-visible decrypt-share objects, and the required FHE parameter tuple `(q, N, B_e)`.
- The surrogate path is isolated behind a feature-gated adapter rather than allowed to define the public API.

## Interface Soundness

- `NizkStatement` binds exactly the public identifiers required by the threat model and theorem inventory: `session_id`, `participant_id`, ciphertext `c`, claimed share `d_i`, the 32-byte P4 commitment hash, and the FHE parameter tuple.
- `NizkWitness` binds the current provenance share `s_i`, lattice error vector `e_i`, and backend-private randomness `r_i` without exposing circuit internals to callers.
- `NizkProof` is specified as deterministic bytes with explicit size and constraint metadata, which is the right shape for downstream folding and review.

## Surrogate Isolation

- The frozen trait and spec do not expose surrogate circuit fields or backend verifier object names.
- The legacy path is explicitly placed behind the `surrogate-decrypt-share` feature and marked as temporary compatibility only.
- Adapter-local derivation is required for any surrogate-only helper fields, preventing surrogate contamination of the long-lived API.

## P2 Compatibility

- The public-input layout is stable, ordered, and versioned, which gives P2 a fixed object to fold.
- Publishing `constraint_estimate` and `proof_size_bytes` at the proof boundary supports recursion budgeting without forcing P2 to understand backend internals.
- The batch verification contract is aligned with theorem T5 by requiring statement/proof alignment before backend checks run.

## Risks

- The current witness still binds a Shamir-derived `u64` share because that is what P4 exports today; future RLWE-native upstream changes will need an adapter update, though not necessarily a public API change.
- Concrete canonical encoding for large `q` values must remain single-valued across backends or the deterministic serialization promise weakens.
- The surrogate adapter can preserve API stability, but it cannot erase the semantic gap between today's surrogate circuit and the intended lattice relation; that remains implementation debt until the real backend lands.
