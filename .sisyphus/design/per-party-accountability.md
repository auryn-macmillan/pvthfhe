# Design: Per-Party Accountability

**Status**: DESIGN (Phase 5)
**Depends on**: Phase 1-4 completion

## Problem

PVTHFHE has no proof signing, no accusation pipeline, and no on-chain
accountability mechanism. A malicious party that submits bad shares has no
on-chain consequence.

## Design

### Signature Scheme

- Use EdDSA over Grumpkin (the Sonobe cycle curve for G2), which has Noir
  standard library support (`std::eddsa`).
- Each party generates an EdDSA keypair `(sk_eddsa, pk_eddsa)` during keygen.
- `pk_eddsa` is published in the DKG transcript `Round1Message`.
- Each proof (keygen NIZK, sigma decryption proof, parity proof) is signed:
  `sig = EdDSA.sign(sk_eddsa, proof_hash)`.
- The signature is appended to the proof bytes and verified by the aggregator.

### On-Chain Slashing

- The `PvtFheVerifier.sol` contract maintains a mapping `partyId => stake`.
- When `aggregator_final` detects a party submitted an invalid proof, it emits
  `event ProofRejected(uint16 partyId, bytes32 proofHash)`.
- The slashing logic: `stake[partyId] = 0;` (full slash), with a `challenge`
  period for the party to submit a counter-proof.
- Implementation: add a `slash()` function callable by the aggregator contract
  when the Noir circuit's `is_valid` output is false.

### Integration Into Pipeline

1. `PipelineReport` carries `party_signatures: Vec<[u8; 64]>` (EdDSA sigs).
2. `aggregator_final` Noir circuit adds: `assert(is_valid_party_sig(sig, pk, proof_hash))`.
3. Solidity `PvtFheVerifier` adds `slash(uint16 partyId)` function.

## Implementation Plan (Phase 5)

1. Add EdDSA keygen to `FheBackend` trait
2. Sign proofs in `full_pipeline.rs` at each NIZK/circuit boundary
3. Add EdDSA verification gadgets in `aggregator_final` Noir circuit
4. Add `slash()` to `PvtFheVerifier.sol`
5. Add adversarial test: submit bad proof, verify slashing event emitted
6. Demo-e2e with signatures and accountability

## Dependencies
- Noir `std::eddsa` (available in standard library)
- Grumpkin curve (already in Arkworks dependency tree)
- Solidity `PvtFheVerifier.sol` (exists, needs `slash` extension)
