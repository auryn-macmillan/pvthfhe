# P3 Real Verifier — Architecture Sketch

**Date**: 2026-05-03
**Status**: Open implementation task (current deploy is trusted-signer surrogate)

## Current State

`contracts/src/P3RealVerifier.sol` implements a **trusted-signer surrogate**:

```solidity
address constant TRUSTED_SIGNER = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

function verifyProof(...) external view returns (bool) {
    address recovered = ecrecover(proofHash, v, r, s);
    return recovered == TRUSTED_SIGNER;
}
```

This is **not** a cryptographic verification of the P2 accumulator. Security reduces
entirely to key custody of `TRUSTED_SIGNER`. Machine-proved vacuous by
`contracts/test/P3VacuityProof.t.sol` (evidence: `audit-p3-vacuity/`).

The proof document `docs/security-proofs/p3/T1.md` proves **ECDSA completeness**
(honest signer always produces an accepted signature), not the claimed
"on-chain soundness" (no forged proof passes without knowledge of the P2 witness).

## What a Real Verifier Needs

A real P3 verifier must verify the P2 `FinalSnark` on-chain. The minimal path:

1. **Choose a SNARK backend** that has an EVM verifier: UltraHonk (bb CLI),
   Groth16, or PLONK. The Noir/bb stack (already in toolchain) supports
   UltraHonk with a Solidity verifier exported via `bb write_vk`.

2. **Export a Solidity verifier** from the P2 circuit:
   ```bash
   (cd circuits && nargo execute --package p2_fold --prover-name Prover)
   bb write_vk --scheme ultra_honk -b circuits/target/p2_fold.json -o circuits/target
   bb contract --scheme ultra_honk -k circuits/target/vk -o contracts/src/P3HonkVerifier.sol
   ```

3. **Replace** `P3RealVerifier.sol` with the exported `P3HonkVerifier.sol` plus
   a thin wrapper that:
   - Decodes the `FinalSnark.proof_bytes` into `(proof, public_inputs)`
   - Calls `P3HonkVerifier.verify(proof, public_inputs)`
   - Emits `ProofVerified(sessionId, result)`

4. **Gas bound (P3-T4)**: UltraHonk verifier is typically 300k–800k gas;
   well within the claimed 5,000,000 gas ceiling.

5. **Security proof update**: once the Solidity verifier is deployed, the
   P3-T1 proof should cite UltraHonk soundness (from Aztec/bb audit) rather
   than ECDSA completeness.

## Blocking Dependencies

- P2 circuit (`circuits/p2_fold`) must exist and produce a valid proof artifact.
  Currently the `real-folding` feature is dead in production (P2-reachability.md).
- bb CLI version must match `REPRODUCING.md` pin.

## Acceptance Criteria

- `P3VacuityProof.t.sol` flips from PASS to FAIL (vacuity test becomes GREEN
  after the real verifier is deployed, meaning the verifier actually enforces
  proof structure).
- `test_fold_large_norm_witness_rejected` (P2-G3) turns GREEN, showing the
  end-to-end norm bound is enforced before the proof reaches P3.
