# A1 Decisions

## 2026-06-04: Plan Creation

### Decision: Wire Format Versioning
- **Choice**: Use `accumulator_version: u16 BE = 0x0001`
- **Rationale**: Followed the existing `PROOF_VERSION: u16 = 0x0002` pattern in adapter.rs:48. Allows future format evolution without breaking backward compatibility. Unknown versions must be rejected at decode time.
- **Alternatives considered**: (a) no version field (risks silent format breakage), (b) varint version (unnecessary complexity for infrequent changes).

### Decision: params_digest in Transcript
- **Choice**: Include `fiat_shamir::params_digest_v1(b"pvthfhe-cyclo-params-v1")` in the transcript header
- **Rationale**: Prevents cross-parameter-set replay attacks. If someone changes `PVTHFHE_CYCLO_PARAMS`, the digest changes and old transcripts become invalid. The digest is already computed by `init_accumulator_inner` (fold.rs:115) and stored in `CycloAccumulator::params_digest`.
- **Verification**: The verifier recomputes `params_digest` from its own parameter set and compares.

### Decision: Hash-Reference Approach for Per-Instance Commitments
- **Choice**: Encode 32-byte SHA-256 hashes of Ajtai commitments and public I/O, not full 26,624-byte commitments
- **Rationale**: The full commitments are already verified by the NIZK sigma proof (which includes `sha256_binding`). The accumulator transcript layer verifies the fold relation, not the commitment correctness. The hash binds the transcript to the commitments without re-transmitting 26KB per instance.
- **Forbidden shortcut analysis**: This is NOT "hash-only binding" because the hash is not used as a standalone proof of anything. It is a binding reference to commitments that have already been cryptographically verified by the sigma proof. The fold verifier recomputes the accumulator from the instance list, so it would detect any commitment mismatch.
