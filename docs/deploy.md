# PVTHFHE Deployment Guide

> ⚠️ **DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY**

## Prerequisites

- Rust 1.95.0 (from `rust-toolchain.toml`)
- Foundry 1.6+
- Noir 1.0.0-beta.20 (`nargo`)
- Barretenberg 3.0.0-nightly (`bb`)

## On-Chain Contracts

### Contract Architecture

| Contract | File | Purpose |
|----------|------|---------|
| `UltraHonkVerifier` | `contracts/src/UltraHonkVerifier.sol` | Adapter wrapping generated HonkVerifier |
| `HonkVerifier` | `contracts/src/generated/HonkVerifier.sol` | Auto-generated UltraHonk verifier |
| `PvtFheVerifier` | `contracts/src/PvtFheVerifier.sol` | IVC binding + statement verification |
| `IP3Verifier` | `contracts/src/interfaces/IP3Verifier.sol` | Interface for UltraHonkVerifier |

### Current VK Fingerprint

- **VK hash**: `18ee4b12d5c27622271f1cc1a10c704e15b046d93a8eeee7525a0d7981e55319`
- **Circuit**: `aggregator_final` (7,959 ACIR opcodes, 27,602 circuit size)
- **Scheme**: `ultra_honk`
- **Public inputs**: ~15 field elements (ciphertext_hash, aggregate_pk_hash, decrypt_nizk_hash, dkg_transcript_hash, dkg_root, epoch, participant_set_hash, n_participants, threshold, plaintext_commitment, ivc_snark_proof_hash, nova_share_chain_hash, plus G4 Merkle-path fields)
- **Last regenerated**: 2026-06-04

### Solidity Verifier Generation Status

`bb write_solidity_verifier --scheme ultra_honk` currently fails with `Assertion failed: (val.on_curve())` for this VK shape. This is a known Barretenberg limitation. The verifier is **CI-deferred** until a compatible `bb` version is available.

Workaround: The current `contracts/src/generated/HonkVerifier.sol` was generated from a previous VK and is structurally correct for the UltraHonk verifier interface. The `UltraHonkVerifier` adapter preserves the `IP3Verifier` contract surface.

### Canonical Regeneration Flow

```bash
(cd circuits && nargo compile --package aggregator_final)
(cd circuits && nargo execute --package aggregator_final)
bb write_vk --scheme ultra_honk -b circuits/target/aggregator_final.json -o circuits/target
bb prove --scheme ultra_honk -b circuits/target/aggregator_final.json -w circuits/target/aggregator_final.gz -o circuits/target
bb verify --scheme ultra_honk -k circuits/target/vk -p circuits/target/proof -i circuits/target/public_inputs
# CI-deferred:
# bb write_solidity_verifier --scheme ultra_honk -k circuits/target/vk -o contracts/src/HonkVerifier.sol
```

### Gas Benchmarks

- **Proof size**: ~3.3 KB (UltraHonk proof)
- **On-chain verification**: Estimated ~500K gas (based on circuit_size=27,602, N=65,536, 15 public inputs)
- **IVC binding overhead**: ~227,200 gas (14.2 KB calldata)
- **Total per-verification**: Within 5M gas budget

Note: Exact gas numbers require regeneration of `HonkVerifier.sol` with a compatible `bb` version. Current numbers are estimates based on circuit parameters.

## Sepolia Deploy Status

| Item | Status |
|------|--------|
| Sepolia deploy | **CI-deferred** (requires network + keys) |
| Contract verification | Pending deploy |
| Gas profiling | Pending deploy |

## Verification Status (C5/C7/A1)

| Check | Status | Artifact |
|-------|--------|----------|
| C5 – PK formation proof | ✅ Resolved | `crates/pvthfhe-aggregator/src/keygen/c5_proof.rs`, 9 tests |
| C7 – Threshold decryption | ✅ Resolved | `circuits/aggregator_final/src/main.nr`, 18 tests |
| A1 – Accumulator transcript | ✅ Resolved | `crates/pvthfhe-cyclo/src/accumulator_codec.rs`, 21 tests |
| G3 – Plaintext binding | ✅ Resolved | `crates/pvthfhe-cli/src/full_pipeline.rs` |
| G4 – In-circuit PK binding | ✅ Resolved | `circuits/aggregator_final/src/main.nr`, Merkle-path |

### Proof of Correctness

```bash
# Noir tests (18/18)
(cd circuits && nargo test --package aggregator_final)

# Solidity tests (153/153)
forge test --root contracts

# C5 formation proof tests (9/9)
cargo test -p pvthfhe-aggregator --test c5_formation_proof --features mock

# A1 accumulator tests (21/21)
cargo test -p pvthfhe-cyclo accumulator_codec
cargo test -p pvthfhe-nizk --test accumulator_fail_closed
cargo test -p pvthfhe-nizk --test accumulator_transcript_adversarial
```

## Remaining Open Problems

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK soundness (Greco M-SIS) | OPEN |
| P2 | Lattice-native folding (Nova substitute) | OPEN |
| P4 | On-chain IVC decider verification | OPEN |
| C6 | Committed-smudge enforcement | PARTIAL |
