# Decisions: C5 Aggregate Public-Key Formation Proof

## 2026-06-04: Initial plan decisions

1. **Proof approach**: Plan recommends PoP (proof-of-possession) over key-registration model. PoP preserves the malicious-security model. Protocol design (Task 1) will finalize.

2. **Complement to G4**: C5 and G4 are complementary, not overlapping. G4 proves key is in transcript; C5 proves the key IS the sum. Both must be resolved.

3. **c5_proof_root field**: Keep the existing `bytes32` field in `VerificationStatementV1`. Do not add new fields or change the schema version. The field already exists and is Poseidon-hash-ready.

4. **Out of scope**: Noir circuit implementation is excluded from the mandatory task list but may be chosen if Task 1 determines it's the best approach. C5 must work alongside C7 in the `aggregator_final` circuit eventually.
