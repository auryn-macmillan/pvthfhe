# Plan: DKG Parity-Check Proof (RS Polynomial Verification)

**Status**: DONE (~2026-05-23)  
**Estimate**: ~2 days  
**Depends on**: DKG ceremony (done)

## Goal

Replace per-recipient NIZK proofs with a single Reed-Solomon parity-check proof per dealer. Currently each dealer generates n proofs (one per recipient). With the parity-check, each dealer generates ONE proof: "all n shares are evaluations of a polynomial f of degree ≤ t, with f(0) = committed secret."

## Architecture

```
Dealer:
  f(x) = sk_secret + a_1·x + ... + a_t·x^t    (degree-t polynomial)
  shares = [f(1), f(2), ..., f(n)]              (n evaluations)
  
  Parity proof: H · shares == 0
  where H is (n-t-1) × n, row k checks:
    Σ f(i) · α_i^k == 0  for degree > t
    
  Encrypt each share + publish parity proof
```

Each recipient verifies THEIR share by checking the parity proof includes their evaluation point.

## Implementation (Complete)

All tasks implemented, tested, and verified end-to-end:

- **Native parity**: `crates/pvthfhe-pvss/src/parity.rs` — `prove_parity()`, `verify_parity()`, matrix generation, serialization. Tests: `cargo test -p pvthfhe-pvss --lib -- parity` (8 passing).
- **In-circuit parity**: `crates/pvthfhe-compressor/src/sonobe/dealer_parity_circuit.rs` — `DealerParityStepCircuit` verifies H·shares == 0 in R1CS via Schwartz-Zippel + P(0) commitment binding. Test: `cargo test -p pvthfhe-compressor --test dealer_parity_works`.
- **Pipeline wiring**: `full_pipeline.rs` calls `prove_parity` per dealer; parity checks pass for all dealers in `demo-e2e 10 4 1` → ACCEPT.
- **Native commitment binding**: `crates/pvthfhe-pvss/src/share_computation.rs` — `verify_batched_share_computation` binds interpolated P(0) to public secret commitment. Tests: `share_computation_commitment_binding.rs` (3 passing).
- **coefficient_bound**: `u64::MAX` sentinel allows full-field DKG polynomial coefficients.

## Tasks

### Task 1: Parity check matrix generation
- [ ] Create `crates/pvthfhe-pvss/src/parity.rs` (adjacent to `shamir.rs`)
- [ ] Compute H matrix for given (n, t) parameters: dimensions (n-t-1) × n
- [ ] Use alpha = Fr::from(1..n) as evaluation points
- [ ] Verify H has correct dimensions (n-t-1) × n
- [ ] Handle edge case: if n <= t+1, H is 0×n (vacuously true — all vectors pass)
- [ ] Test: `cargo test -p pvthfhe-pvss parity_generation`

### Task 2: Parity proof per dealer
- [ ] In `crates/pvthfhe-pvss/src/parity.rs`: `fn prove_parity(shares: &[Fr], h: &[Vec<Fr>]) -> ParityProof`
- [ ] Compute parity witness = H · shares
- [ ] Generate lattice-native NIZK proof (Cyclo/Ajtai) that H·shares == 0
- [ ] Attach parity proof to dealer's share bundle via `EncryptedShares` extension
- [ ] Test: `cargo test -p pvthfhe-pvss parity_prove_verify`

### Task 3: Recipient verification
- [ ] `fn verify_parity(share_i: Fr, index_i: usize, proof: &ParityProof, h: &[Vec<Fr>]) -> bool`
- [ ] O(1) per recipient
- [ ] Test: `cargo test -p pvthfhe-pvss parity_verify_roundtrip`

### Task 4: Wire into pipeline
- [ ] `full_pipeline.rs`: after Shamir split, call `prove_parity` per dealer; store parity_proof in encrypted share data
- [ ] `full_pipeline.rs`: per recipient, call `verify_parity` with their share
- [ ] `per_node.rs`: add parity proof generation timing after DKG deal
- [ ] `PipelineReport`: add `parity_proof_count: usize`
- [ ] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just demo-e2e 10 4 1` — ACCEPTS
- [ ] QA: `PVTHFHE_I_UNDERSTAND_INSECURE_RNG=1 just demo-e2e 16 7 1` — ACCEPTS

### Task 5: Nova-fold parity proofs (Plan 2 integration)
- [ ] Fold all parity proofs via AjtaiCommitmentStepCircuit
- [ ] O(1) on-chain verification
