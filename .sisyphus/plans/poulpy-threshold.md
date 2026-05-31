# Poulpy Integration Plan — DKG for CKKS + TFHE

**Status**: PLAN
**Date**: 2026-05-31
**Branch**: `feat/poulpy-threshold` (to be created)

## Background

Poulpy implements CKKS (leveled) and TFHE (binary/gate) over a unified Torus plaintext space using bivariate polynomial representation. The CHIMERA vision unifies BFV, CKKS, TFHE under a single RLWE scheme with different encodings. This means our BFV DKG techniques should extend to Poulpy's schemes with minimal changes to the sigma protocol.

## What Poulpy Has

| Feature | Status |
|---------|--------|
| CKKS (leveled) | ✅ `poulpy-ckks` — evaluator functional |
| TFHE (binary/gate) | ✅ `poulpy-bin-fhe` |
| Bivariate poly rep | ✅ Unified Torus, decoupled arithmetic |
| Keygen/Encrypt/Decrypt | ✅ Per-scheme |
| Add/Mul | ✅ Per-scheme |
| Bootstrap | ✅ TFHE gate bootstrapping |
| DKG | ❌ None |
| Threshold decrypt | ❌ None |
| Sigma NIZK | ❌ None |

## Strategy

### Phase 1 — poulpy-fhe adapter crate

Create `crates/pvthfhe-fhe-poulpy/` as a new FHE backend implementing the same `FheBackend` trait as `pvthfhe-fhe`. This gives us:

- CKKS keygen, encrypt, decrypt, add, mul via `poulpy-ckks`
- TFHE keygen, encrypt, decrypt, NAND via `poulpy-bin-fhe`
- A `Scheme` enum to select CKKS or TFHE at runtime

### Phase 2 — Sigma protocol for Poulpy schemes

The existing sigma protocol (`sigma.rs`) proves `d_i = c · s_i + e_i` for RLWE. This is the same relation for CKKS (which uses the same RLWE structure) and TFHE (which uses LWE, a special case of RLWE with N=1).

For CKKS: same as BFV — no change needed beyond adapting to Poulpy's `VecZnx` polynomial type.

For TFHE: LWE is RLWE with N=1. The sigma protocol simplifies to proving `d = c·s + e` (scalar equation). The NTT optimization (8192 coeffs) doesn't apply — TFHE uses small polynomials.

### Phase 3 — DKG ceremony for CKKS/TFHE

Adapt the existing DKG pipeline (`full_pipeline.rs`) to work with Poulpy backends:

1. **Keygen**: Generate Poulpy CKKS or TFHE keypair via `poulpy-ckks`/`poulpy-bin-fhe`
2. **Shamir resharing**: Reuse `setup_threshold` from `fhers.rs` — shares are over BN254 scalars, independent of the FHE scheme
3. **Sigma NIZK**: Use the Phase 2 sigma protocol per scheme
4. **Nova IVC folding**: Reuse existing `NovaCompressor` — step circuits are scheme-agnostic (operate on Fr values)
5. **On-chain verification**: Reuse UltraHonk — no changes needed (verifies IVC binding, not scheme-specific)

### Phase 4 — Encoding-switch proofs

Poulpy's bivariate representation enables scheme switching. A proof that "X under CKKS encoding = Y under TFHE encoding" would be a novel capability:

- Prove: `Decode_CKKS(ct_ckks) == Decode_TFHE(ct_tfhe)` without decrypting
- Use Poulpy's native encoding conversion (bivariate → Torus → new scheme)
- Verify in-circuit via Nova step circuit

This is aspirational and depends on Poulpy's scheme-switching API.

## Technical Details

### Sigma protocol adaptation

BFV equation: `ct[l] = pk[l] * sk + e[l] + Δ[l] * m  mod q[l]`

CKKS equation: `ct = pk * sk + e + m  (mod Q)` — same structure, different encoding. The plaintext m is a complex vector encoded as a polynomial via canonical embedding. The sigma proof only cares about the RLWE equation, not the encoding.

TFHE equation: `ct = a·s + e + μ·Δ  (mod q)` — LWE with N=1, single coefficient. The sigma protocol simplifies to verifying a scalar equation with a single S-Z check.

### Key parameter mapping

| Parameter | BFV (current) | CKKS (Poulpy) | TFHE (Poulpy) |
|-----------|---------------|---------------|---------------|
| N | 8192 | 8192 | 1 (LWE) |
| L (RNS limbs) | 3 | K (bivariate log₂Q) | K |
| log₂Q | 174 | 300+ (configurable) | 64 |
| t_plain | 65536 | N/A (complex) | 2 (binary) |
| Sigma equation | RLWE 3-limb S-Z | RLWE K-limb S-Z | LWE 1-limb S-Z |

### Slight differences from BFV

- **CKKS**: Plaintext is a vector of complex numbers encoded via canonical embedding. The sigma proof doesn't need to verify encoding correctness — only RLWE equation.
- **TFHE**: N=1 makes sigma proving trivial (1 S-Z check vs 3×3 = 9). The gate-level bootstrapping requires key-switching keys which add additional relations.
- **GKKS rescaling**: CKKS ciphertexts have a "level" that decreases with each multiplication. The sigma proof must track the level or prove at the current level.

## Tasks

### Phase 1 — Backend adapter
- [ ] Create `crates/pvthfhe-fhe-poulpy/` with `PoulpyBackend` implementing `FheBackend`
- [ ] Support `Scheme::CKKS` and `Scheme::TFHE` via feature flags
- [ ] Implement `keygen`, `encrypt`, `decrypt`, `add`, `mul` per scheme
- [ ] Implement `load_params` from TOML string (same API as `FhersBackend`)

### Phase 2 — Sigma protocol
- [ ] Adapt `compute_sigma_ntt_data` for Poulpy polynomial types (VecZnx)
- [ ] Add `poulpy_sigma` module with CKKS-specific and TFHE-specific S-Z checks
- [ ] Update `bfv_sigma.rs` to be scheme-generic or add scheme-specific modules

### Phase 3 — DKG ceremony
- [ ] Wire `PoulpyBackend` into `full_pipeline.rs` DKG flow
- [ ] Test n=3, t=1 CKKS DKG ceremony
- [ ] Test n=3, t=1 TFHE DKG ceremony
- [ ] Benchmark against BFV (same n, t)

### Phase 4 — Integration (deferred)
- [ ] Scheme-switch proof (CKKS↔TFHE) via Nova step circuit
- [ ] End-to-end demo: DKG + compute (CKKS) + decrypt

## Success Criteria
- [ ] `cargo check` zero errors
- [ ] `just demo-e2e` still works (no regression on BFV path)
- [ ] CKKS DKG ceremony completes at n=3, t=1
- [ ] TFHE DKG ceremony completes at n=3, t=1
- [ ] Sigma NIZK rejects tampered witness for both schemes
