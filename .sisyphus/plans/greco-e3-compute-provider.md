# Greco Encryption Proofs + Compute Provider — Implementation Plan

**Status**: PLAN
**Date**: 2026-05-29
**Branch**: feat/greco-e3-compute-provider (to be created)

## Background

The CRISP example in `~/enclave/examples/CRISP` demonstrates:
- **Input validation (Greco)**: Noir circuit proves correct BFV encryption. Users publish ciphertexts + Greeco proofs proving they're valid.
- **E3 Program execution**: zkVM (Risc Zero) executes FHE operations over committed input ciphertexts and proves the output matches.
- **Integration**: UltraHonk proofs from both sides verified on-chain.

We want to adapt pvthfhe to provide BOTH capabilities more efficiently.

## Initiative 1 — Standalone Greco-Style Encryption Proofs

### Goal
Produce a Noir circuit (or Nova step circuit) that proves: "Ciphertext ct is a valid BFV encryption of plaintext m under public key pk with randomness r." This is used for input validation when users publish ciphertexts for Interfold programs.

### Current CRISP Approach
- Noir circuit in `~/enclave/circuits/bin/bfv_encryption/`
- Verifies BFV encryption equation: ct[l] = pk[l] * u + e[l] + Δ[l] * m mod q[l] for L=2 RNS limbs
- Uses Schwartz-Zippel evaluation at single point
- Constraint count: ~90K (dominated by polynomial multiplication verification)

### PVTHFHE Approach
We already have:
- `nova_gadgets.rs::bfv_verify_step_bp` — in-circuit BFV encryption verification via S-Z 3-point check
- `monomial_range.rs` — proper monomial embedding range checks (Greco-style)
- Working Nova IVC pipeline with transparent proofs

**Proposal**: Package the existing BFV encryption verification as a standalone Nova step circuit (`BfvEncryptionSnapshot`) that proves a single ciphertext is valid WITHOUT running through the full DKG pipeline. This is lighter than the CRISP Noir approach because:
1. Uses 3-point S-Z for soundness (not 1-point) → 2⁻¹³⁵ vs 2⁻⁴⁵
2. Monomial embedding range checks (proper Greco) → all variables directly checked
3. Transparent IVC (no ceremony) vs Risc Zero (zkVM overhead)

### Tasks
- [ ] Create `crates/pvthfhe-compressor/src/nova/bfv_snapshot.rs` — standalone BfvEncryptionSnapshot circuit
- [ ] Accept public inputs: `pk_rns`, `ct_rns`, `plaintext_commitment`, `session_id`  
- [ ] Prove: ct = Encrypt(pk, m; r) with bounded witness (u, e, m) via in-circuit Greco S-Z + monomial bounds
- [ ] Produce `CompressedProof` compatible with our existing Nova infrastructure
- [ ] Add `just bfv-snapshot-prove` and `just bfv-snapshot-verify` commands
- [ ] Benchmark constraint counts at N=4096, 8192
- [ ] Compare against CRISP Noir approach (constraint count, prove/verify time)

## Initiative 2 — Compute Provider for E3 Programs

### Goal
Prove that a specific sequence of FHE operations (add, mul, relinearize) over a committed set of input ciphertexts (Merkle tree leaf hashes) produces a given output ciphertext. The Compute Provider runs the FHE logic and generates a proof.

### Current CRISP Approach
- Risc Zero zkVM guest program executes BFV operations
- Host provides ciphertext inputs, guest computes output
- zkVM proves the entire execution trace
- Prove time: ~30-90 seconds per operation (Risc Zero zkVM overhead)
- Verify time: ~2ms (STARK proof)

### PVTHFHE Approach
We already have Nova IVC infrastructure that can fold sequential operations. Each FHE operation (add, mul, relinearize) becomes one Nova step.

**Proposal**: Create a `FheComputeStepCircuit` that, for each step i:
1. Reads input ciphertext hashes from a Merkle commitment tree
2. Proves that the current operation (add/mul/relinearize) is correct
3. Updates the accumulator with the output ciphertext commitment
4. After n steps, the final state contains the output ciphertext hash

This is faster than Risc Zero because:
1. Nova folding is O(1) per step (not O(n) like zkVM execution trace)
2. No zkVM overhead (prover runs native Rust, not a guest program)
3. Recursive SNARK gives constant-size proof regardless of operation count

### Tasks
- [ ] Create `crates/pvthfhe-compressor/src/nova/fhe_compute_circuit.rs` — FheComputeStepCircuit
- [ ] State: `[output_commitment, merkle_root, input_hash_chain, step_count]`
- [ ] Each step: verify Merkle inclusion proof for input ciphertexts, apply FHE operation, update output
- [ ] Support: Add (ct0 + ct1), Mul (ct0 * ct1 + relinearize), NoiseEval (estimate noise growth)
- [ ] Create Merkle tree over input ciphertexts (Poseidon leaves)
- [ ] Add `just fhe-compute-prove --operations add,mul,relin --inputs merkle_root` command
- [ ] Benchmark: operation throughput (ops/sec), prove time vs Risc Zero
- [ ] Compare against CRISP zkVM approach

## Integration

Both initiatives share infrastructure:
- Nova IVC folding (same `NovaCompressor` wrapper)
- Monomial embedding range checks (shared `monomial_range.rs`)
- Transparent IVC proofs (no ceremony)
- UltraHonk on-chain verification (same `nova_state_commitment` circuit)

## Trust Model
Per user's specification: **trust only the verifier and chain state**. Native code is always untrusted. All proofs are verifiable on-chain via UltraHonk.

## Success Criteria
- [ ] `cargo check --workspace` = 0 errors
- [ ] Both initiatives have working CLI commands
- [ ] Benchmarks compared against CRISP example
- [ ] Demo-e2e still works (no regressions)
- [ ] No new surrogates or dummy proofs

## Effort Estimate
- Initiative 1 (BfvEncryptionSnapshot): ~4 hours
- Initiative 2 (FheComputeStepCircuit): ~8 hours
- Integration + benchmarking: ~4 hours
- **Total**: ~16 hours
