# TFHE Bootstrapping Proofs — Implementation Plan

**Status**: PLAN
**Date**: 2026-05-31
**Branch**: `feat/poulpy-threshold`

## Background

Poulpy's TFHE (`poulpy-bin-fhe`) supports circuit bootstrapping: blind rotation → trace → key-switch → bootstrapped GGSW output. We need to prove this operation is correct in-circuit so an on-chain verifier can trust bootstrapped computation results.

The bootstrapping relation: given noisy LWE ciphertext `ct_in = (a, b = a·s + e + m)`, produce a cleaner LWE ciphertext `ct_out = (a', b' = a'·s + e' + m)` with the same message `m` but smaller error `e'`. This enables unlimited-depth FHE computation.

## Phases

### Phase 1 — Bootstrapping Sigma Protocol (~4 hrs)

Create `crates/pvthfhe-nizk/src/bootstrap_sigma.rs` proving the bootstrapping relation:

**Statement**: `BootstrapStatement { ct_in: LweCiphertext, ct_out: LweCiphertext, bootstrapping_key_hash: [u8; 32] }`

**Witness**: `BootstrapWitness { secret_key: Vec<i64>, blind_rotation_trace: Vec<Vec<i64>>, key_switch_noise: Vec<i64> }`

**Prove**: The prover shows knowledge of `sk` such that:
1. `decrypt(sk, ct_in) == decrypt(sk, ct_out)` (message preserved)
2. `noise(ct_out) < noise(ct_in)` (error reduced)
3. The bootstrapping key was used correctly

**Verification**: The verifier checks the sigma equation: `ct_out[0] + ct_out[1]·s ≡ ct_in_body mod q` where `ct_in_body = bootstrap_body(ct_in, bsk, r)` and `bsk` is the bootstrapping key committed via `bootstrapping_key_hash`.

### Phase 2 — In-Circuit Bootstrapping Step Circuit (~4 hrs)

Create `crates/pvthfhe-compressor/src/nova/bootstrap_step.rs` with `BootstrapStepCircuit`:

- **State (arity=1)**: `[bootstrapping_result_hash]`
- **Each step**: Verify the bootstrapping sigma equation at one evaluation point via S-Z
- **Final state**: Output hash binds to all verified intermediate states

The circuit reuses `monomial_range.rs` for bound enforcement on the bootstrapping noise.

### Phase 3 — Poulpy Integration (~2 hrs)

Wire the bootstrap sigma protocol and step circuit into the `PoulpyBackend`:

- `PoulpyBackend::bootstrap(ct_in) -> Result<Ciphertext>` — calls Poulpy's `FheUint::prepare` pipeline
- `PoulpyBackend::bootstrap_prove(stmt, witness) -> SigmaProof` — generates bootstrap NIZK
- `PoulpyBackend::bootstrap_verify(stmt, proof) -> bool` — verifies on-chain
- CLI: `--backend poulpy-tfhe --bootstrap` flag to enable bootstrapping in demo

### Phase 4 — On-Chain Verification (~2 hrs)

- Add `bootstrap_result_hash` to `nova_state_commitment` Noir circuit
- Update `PvtFheVerifier.sol` with bootstrap verification path
- Add forge test: tampered bootstrap → rejected

## Tasks

### Wave 1 — Sigma Protocol
- [ ] Create `bootstrap_sigma.rs` with `prove`/`verify` for bootstrapping relation
- [ ] Reuse existing `SigmaStatement`/`SigmaWitness` types
- [ ] Adapt S-Z evaluation for LWE (N=1, single coefficient)
- [ ] Add `prove_multi`/`verify_multi` for 90-round soundness

### Wave 2 — Step Circuit
- [ ] Create `bootstrap_step.rs` with `BootstrapStepCircuit::StepCircuit`
- [ ] Implement blind-rotation verification in-circuit (RLWE polynomial multiplication)
- [ ] Add trace-extraction verification (constant term = message)
- [ ] Add key-switch noise bound enforcement via `monomial_range_check_bp`

### Wave 3 — Backend Integration
- [ ] Wire `PoulpyBackend::bootstrap` into TFHE path
- [ ] Add Sigma prove/verify into bootstrap flow
- [ ] Add `--bootstrap` CLI flag to tfhe demo
- [ ] Test: n=3, t=1 TFHE bootstrap pipeline

### Wave 4 — On-Chain
- [ ] Add `bootstrap_result_hash` to Noir circuit
- [ ] Update Solidity verifier
- [ ] Forge test: adversarial bootstrap rejection

## Success Criteria
- [ ] `cargo check` zero errors
- [ ] `--backend poulpy-tfhe --bootstrap` pipeline completes
- [ ] Bootstrap sigma NIZK rejects tampered witness
- [ ] On-chain verifier checks bootstrap result hash
