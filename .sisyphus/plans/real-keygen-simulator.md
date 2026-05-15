# Plan: Real Keygen NIZK + Encryption in Simulator

**Plan**: `real-keygen-simulator`
**Status**: DRAFT
**Created**: 2026-05-15
**Goal**: Replace the hardcoded keygen stubs in `KeygenSimulator` with real BFV encryption under recipient public keys and real Cyclo NIZK proofs.

---

## Current State

```rust
// simulator.rs:337
encrypted_shares.insert(j, vec![0x11, 0x22]);  // all parties get the same 2 bytes

// simulator.rs:348-357
// nizk is hardcoded [0x00, 0x01] — unconditionally passes validation
```

The simulator already computes real Shamir shares for each party via `compute_party_sk_sums`. But the shares are never encrypted or proven — the hardcoded bytes replace them.

## Target State

Each `encrypted_shares[j]` is a real BFV ciphertext encrypting party j's Shamir share under party j's public key. Each NIZK proof is a real Cyclo sigma proof of correct encryption.

## Design

### Dependencies

The `KeygenSimulator` is in `pvthfhe-aggregator` which does NOT currently depend on `pvthfhe-fhe` (FheBackend) or `pvthfhe-nizk` (RealNizkAdapter). Adding these dependencies creates a circular reference risk.

**Better approach**: Move the keygen-enryption logic to the pipeline (`full_pipeline.rs`) where both the backend and NIZK are available. The simulator produces raw Shamir shares; the pipeline encrypts them.

OR: Add a feature gate to the aggregator crate for `real-keygen` that optionally depends on the fhe and nizk crates.

### Implementation

1. Add `fn encrypt_shares_under_recipient_keys(shares: &[Vec<u8>], backend: &dyn FheBackend, ...)` to `full_pipeline.rs` or a new module
2. For each (dealer, recipient) pair:
   a. Get the recipient's public key
   b. BFV-encrypt the share under that public key using `backend.encrypt()`
   c. Generate a Cyclo NIZK proof via `RealNizkAdapter::prove()`
   d. Store the real ciphertext and proof
3. Replace the simulator's hardcoded bytes with the real encrypted shares

### Tasks

| ID | Task | Files | Effort |
|----|------|-------|--------|
| R1 | Add `pvthfhe-fhe` and `pvthfhe-nizk` as optional dependencies of `pvthfhe-aggregator` (behind `real-keygen` feature) | `Cargo.toml` | 0.5 day |
| R2 | Create `encrypt_keygen_shares()` that encrypts Shamir shares under recipient BFV keys with Cyclo NIZK proofs | `simulator.rs` or new module | 2 days |
| R3 | Replace stub encrypted_shares and nizk with real values | `simulator.rs:337,348-357` | 1 day |
| R4 | RED tests: real encrypted shares roundtrip decrypt + NIZK verify | Tests | 1 day |

### Acceptance Criteria

- [ ] Keygen encrypted shares are real BFV ciphertexts
- [ ] NIZK proofs verify correctly for real shares
- [ ] Demo ACCEPT
- [ ] No regression in existing tests

### Estimated Effort

~4-5 days. Most of the time is in integrating the NIZK prover with the simulator's loop structure.
