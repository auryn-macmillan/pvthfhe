## F4 QA Gate Decision — 2026-05-09

**VERDICT: REJECT**

### Reasoning

The F4 approval gate requires that ALL 10 checks pass. The following genuine (non-stub, non-RED) failures were observed:

1. **pvthfhe-fhe encoding_golden** — plaintext recovery round-trip is broken. This is a functional correctness issue in the FHE crate.

2. **forge UltraHonkVerifier** — a valid proof fails to verify. The verifier contract rejects what should be an honest proof.

While some failures are attributable to known stub/mock limitations (pvss nizk_soundness RED tests, keygen dkg mock backend size limitation, compressor RED memory test), the two failures above are not in that category and indicate real defects.

### Forge Count
- 104 passed, 1 failed out of 105 total — meets the "104+" threshold but not full pass.
