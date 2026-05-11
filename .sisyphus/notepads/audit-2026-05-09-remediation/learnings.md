# Learnings — Batch A.3: Fix Fiat-Shamir challenge binding (C13)

## Problem
The Fiat-Shamir challenge at `nizk_share.rs:492-507` was derived from statement fields only, 
never absorbing the prover's commitment ciphertext (`commitment_ct`). This meant two proofs 
with different witnesses (same statement) produced identical challenges — the transcript did 
not bind the witness.

## Root Cause
The original control flow in `prove()` was:
1. Derive challenge from statement alone
2. Compute commitment_seed = hash(stmt + challenge)
3. Create commitment_ct using commitment_seed

The circular dependency (commitment_ct needed challenge-derived seed) prevented absorbing 
commitment_ct into the transcript before challenge derivation.

## Fix Approach
Broke the circular dependency by removing the challenge from `commitment_seed` computation:
1. `compute_commitment_seed(stmt)` — seed from statement only (version bumped to v2)
2. `commitment_ct = encrypt(witness, rng(commitment_seed))` — created BEFORE challenge
3. `derive_challenge(stmt, commitment_ct)` — absorbs commitment_ct into transcript
4. `lattice_binding` — unchanged, still binds everything including challenge

## Changes Made

### `nizk_share.rs` (source)
- `derive_challenge()`: added `commitment_ct: &[u8]` parameter, absorbs it as `b"commitment_ct"` after share_commitment
- `compute_commitment_seed()`: removed `challenge` parameter; bumped domain tag to `greco-bfv-commitment-seed-v2`
- `prove()`: reordered — commitment_seed computed first, then commitment_ct created, then challenge derived
- `verify()`: passes `opened.commitment_bytes.as_slice()` to `derive_challenge()`

### Test file
- `nizk_share_fs_binding.rs`: RED→GREEN test verifying challenges differ when witnesses differ

## Verification
- RED test confirmed: identical challenges for different witnesses
- GREEN test passes: challenges differ when witness changes
- All 10 nizk_share tests pass (fs_binding, no_witness_leak, real_verify, soundness, zk)
- All 23 pvss tests pass (excluding pre-existing nizk_decrypt_soundness failures for audit batch E)

# Learnings — Batch B: On-Chain Verifier Fixes

## B.1: HonkVerifierRegenerated.t.sol (RED test)

Created RED test `contracts/test/HonkVerifierRegenerated.t.sol` with 5 tests
documenting the BB VK shape mismatch blocker:
- BB 5.0.0-nightly.20260324 expects 1888-byte VKs
- All circuits produce 3680-byte VKs
- `bb write_solidity_verifier` fails with VK size mismatch
- Tests are gated with `[blocked_on=BB-VK-shape]` convention

Resolution options documented in test: upgrade BB, adjust circuit, or patch generator.

## B.2: ecrecover Attestation Signature Verification

### Changes
- `PvtFheVerifier.sol:verifyWithAttestation()`: added ECDSA signature verification
  via `ecrecover` over `keccak256(abi.encode(sonobeStateCommitment,
  cycloAggregateCommitment, sessionId, signer))`
- New `_verifyAttestationSignature()` helper: extracts (v, r, s) from 65-byte
  calldata signature, normalizes v to {27,28}, calls ecrecover
- Updated existing `PvtFheVerifier.t.sol` tests to use real 65-byte signatures
  instead of 2-byte placeholders

### Key gotcha: calldata vs memory keccak256
- `keccak256(bytes calldata)` hashes raw data without length prefix
- `keccak256(bytes memory)` hashes memory layout WITH length prefix
- Must use `keccak256(abi.encodePacked(bytes))` for memory-to-calldata hash matching
- `bytes calldata .offset` points directly to data, NOT to length word

### Key gotcha: calldata assembly parsing
- For `bytes calldata signature`, `.offset` points to the first data byte
- Not `add(signature.offset, 32)` like for memory (where `.offset` + 32 is needed)
- Correct: `r := calldataload(signature.offset)`, `s := calldataload(add(signature.offset, 32))`

### Pre-existing test updates
- Changed `TEST_ATTESTOR` from `0xA7713570` to `0xCf03Dd0a894Ef79CB5b601A43C4b25E3Ae4c67eD` (known SK=0x1234)
- All 4 old attestation tests updated to use 65-byte ECDSA signatures

## B.3: Epoch DOS Fix (verifyAndConsume reordering)

### Changes
- `PvtFheVerifier.sol:verifyAndConsume()`: reordered from
  `check → consume → verify` to `check → verify → consume`
- Proof is verified BEFORE calling `registry.markEpochConsumed()`
- If proof verification fails, returns `false` without consuming epoch
- Replay protection still enforced via `_requireSessionValid()` before verify

### Test design note
- The HonkVerifier tautology checks `keccak256(proof) == publicInputs[0]` where
  `publicInputs[0] = ciphertextHash`
- For "valid" proofs in tests: pass `proofHash(validProof)` as `ciphertextHash`
- For "invalid" proofs in tests: pass a MISMATCHED hash (e.g. `0xDEAD`)
- The `buildPublicInputs` helper was removed — the contract rebuilds its own
  publicInputs from the function arguments; the test's pre-built array was unused

## Verification
- 117 tests pass, 1 pre-existing failure (UltraHonkVerifier.t.sol - unrelated)
- New tests: B.1 (5), B.2 (4), B.3 (4) = 13 new tests
