# A1 Issues

## 2026-06-04: Plan Creation

### Issue A1-1: Codec Location
- **Decision needed**: Should the accumulator transcript codec live in `crates/pvthfhe-nizk/src/` (adapter layer) or `crates/pvthfhe-cyclo/src/` (Cyclo layer)?
- **Tradeoff**: nizk crate creates a dependency on pvthfhe-cyclo for the codec. cyclo crate avoids dep issues but mixes transport protocol with cryptography.
- **Current lean**: nizk crate, since the codec bridges the adapter and the Cyclo verifier. The nizk crate already depends on pvthfhe-cyclo for sigma proof expansion.

### Issue A1-2: NizkAdapter trait signature change
- **Problem**: Adding `accumulator_ctx: Option<&AccumulatorContext>` to `NizkAdapter::prove` is a breaking trait change.
- **Impact**: All implementors of `NizkAdapter` must update. Currently only `CycloNizkAdapter` implements it. Any downstream mock/test adapters will also break.
- **Mitigation**: Could use a default value (Option::None), but Rust traits don't support default arguments. Alternatives: (a) add a config builder, (b) use a separate `prove_with_accumulator` method, (c) thread through `NizkStatement`.

### Issue A1-3: Full Ajtai commitment vs Hash in Transcript
- **Problem**: Including the full 26,624-byte Ajtai commitment per instance in the transcript balloons proof size dramatically (N×26KB).
- **Mitigation**: Use SHA-256 hashes in the transcript, since the full Ajtai commitment has already been cryptographically verified by the NIZK sigma proof (which includes `sha256_binding`).
- **Risk**: Must avoid the "hash-only binding" forbidden shortcut. The cross-check binds the hash to the already-verified Ajtai commitment, so the hash is a binding reference, not a standalone proof. This is acceptable per the forbidden shortcuts analysis.
