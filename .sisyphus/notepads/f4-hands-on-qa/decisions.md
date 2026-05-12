## F4 QA Gate Decision — 2026-05-09

**VERDICT: REJECT**

### Reasoning

The F4 approval gate requires that ALL 10 checks pass. The following genuine (non-stub, non-RED) failures were observed:

1. **pvthfhe-fhe encoding_golden** — plaintext recovery round-trip is broken. This is a functional correctness issue in the FHE crate.

2. **forge UltraHonkVerifier** — a valid proof fails to verify. The verifier contract rejects what should be an honest proof.

While some failures are attributable to known stub/mock limitations (pvss nizk_soundness RED tests, keygen dkg mock backend size limitation, compressor RED memory test), the two failures above are not in that category and indicate real defects.

### Forge Count
- 104 passed, 1 failed out of 105 total — meets the "104+" threshold but not full pass.

## F4 QA: D.1 Lattice-Native BFV Encryption Proof — 2026-05-12

**VERDICT: PASS**

### Reasoning

Both acceptance criteria met:
1. **Demo**: Runs to completion. `plaintext_roundtrip: OK`. `verify: ACCEPT`. All 9 pipeline steps use real lattice-pvss-bfv-d2 backend with FhersBackend crypto.
2. **Tests**: All 15 focused nizk_share tests pass (soundness=6, fs_binding=2, real_verify=2, batched_tracks=5).

No blocking issues. The D.1 lattice-native BFV encryption proof (NIZK well-formedness with witness-free D2-preimage binding) works correctly under the current construction. The BFV relation stubs have been replaced with real fhe.rs crypto, and the end-to-end path validates this.

### Notes
- Previously reported genuine failures (encoding_golden, UltraHonkVerifier) were not in scope for this D.1-specific QA run.
- `verifier_accepts_internally_consistent_but_invalid_proof` passes as expected: D2-preimage binding is a weaker property than full BFV relation soundness (open problem P1).
