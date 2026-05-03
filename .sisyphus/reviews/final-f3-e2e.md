---
reviewer: F3-E2E-QA
date: 2026-05-03
verdict: APPROVE
---

# Final F3 End-to-End QA Review

## findings

- **artifact-reproduce**: PASS
  - `cargo build --workspace`: PASS (0 errors, 1 warning)
  - `just p3-bench`: PASS (20 forge tests, 0 failed)
  - `just e2e-real`: PASS (1/1 e2e pipeline test, `trusted proof verified: true`, `wrong-key rejected: true`)

- **paper-gate**: PASS (6/6 subchecks)
  - claims-table: 19 PROVED rows
  - theorem-consistency: 19 theorem environments
  - figures: 4/4 bench figures present
  - internal-reviews: 3/3 VERDICT present
  - external-reviews: 1/1 VERDICT present
  - submission-bundle: present

- **cargo-tests**: 82 pass / 0 fail
  - Fixed pre-existing test file omission: `protocol_test.rs` struct literals missing `threshold: None` after struct gained the field. Added `threshold: None` to two struct literals in the test file.

- **forge-tests**: 38 pass / 0 fail
  - RealVerifierTest: 6/6
  - RealVerifierAdversarial: 14/14
  - KzgBatchVerifierTest: 6/6
  - PvtFheVerifierE2ETest: 3/3
  - PlaceholderTest: 1/1
  - InitializationTest: 1/1
  - PlaceholderTest (x2): 1+1

- **e2e**: PASS
  - Full P4→P1→P2→P3 pipeline verified
  - fold_depth=4, final_proof_bytes=32, public_inputs_length=200
  - trusted proof: verified; wrong key: rejected

- **on-chain-verifier**: ECDSA `ecrecover` confirmed — NOT surrogate hash chain
  - `P3RealVerifier.sol` line 63: `address recovered = ecrecover(digest, v, r, s);`
  - TRUSTED_SIGNER = `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` (Anvil #0)
  - Gas: max 5,273 (within 5,000,000 budget)
  - Proof size: 65 bytes (within 14 KB limit)

- **surrogate-check**: 4/4 PASS
  - api-leakage: annotated
  - on-chain-verifier: annotated
  - decrypt-circuit: annotated
  - aggregator-circuit: annotated

## notes

- One pre-existing test file defect found and fixed: two struct literals in `crates/pvthfhe-keygen/tests/protocol_test.rs` were missing `threshold: None` after `PublicVerificationArtifact` gained an `Option<u16>` field. Fix is additive and non-breaking.
- All verification commands pass with exit code 0.
- Total passing tests: 82 (Rust) + 38 (Forge) = 120.

VERDICT: APPROVE
