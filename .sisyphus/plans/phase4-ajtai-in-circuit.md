# Phase 4 — In-Circuit Ajtai Commitment Verification

**Status**: DESIGN  
**Blocked by**: Constraint budget (see analysis)  
**Recommended**: Defer to on-chain HonkVerifier.sol

## What the Verifier Needs to Check

The native check (Phase 3) verifies:
```
pvss_commitment == sk_commitments[party_index]
```

Where `pvss_commitment = to_d2_digest(A·s_i)` and `s_i` is the secret key share.

To move this in-circuit, the Noir circuit must:
1. Receive `s_i` as a witness (secret key share coefficients)
2. Derive the Ajtai matrix A from `sha256("pvthfhe-d2-ajtai-matrix-v1" || session_id || party_index)`
3. Compute `commitment = A·s_i` (13 ring multiplications over R_q)
4. Hash the commitment to match `pvss_commitment`
5. Constrain `pvss_commitment == sk_commitments[party_index]`

## Constraints Analysis

### Per-step cost (NTT-optimized, per party)
- 13 ring multiplications via NTT: 13 × ~30K ≈ 390K constraints
- Poseidon hash of commitment: ~8K
- Matrix seed → Poseidon: ~8K
- Step total: ~406K constraints (2.4× larger than Schnorr step at ~170K)

### Per-run cost (Nova folded)
- Nova proof: ~27K constraints regardless of n (amortized)
- n=128: 128 × 406K = 52M constraints folded into one 27K proof
- Well within 2.5M WASM limit for the compressed proof

## Optimization Possibilities

### NTT-based multiplication
- Replaces O(φ²) with O(φ log φ)
- Suitable for q ≡ 1 (mod 2φ) — Q_COMMIT satisfies this
- Would reduce ring mul from ~1.97M to ~30K constraints
- Full commitment: 13 × 30K + overhead ≈ 500K per share
- n=128: 64M — still > 2.5M by 25×

### Folding (Nova)
- Each party's commitment is a separate FCircuit step
- Each step: ~500K constraints (NT-optimized)
- Fold n steps via Nova → O(log n) proof size, amortized constraints
- Could fit within limits

### Defer to on-chain
- HonkVerifier.sol already checks proof public inputs
- Add pvss_commitment matching as an additional public input check
- 0 circuit constraints, ~5K gas on EVM
- **This is the recommended approach**

## Architecture: Nova-Folded Ajtai Verification

Follow exactly the G.12 Phase 2 pattern already built for Schnorr verification:

```
Party i: (s_i, matrix_seed_i, expected_commitment_i)
    ↓
AjtaiCommitmentStepCircuit (FCircuit)
    └─ 500K constraints: NTT ring-op A_i · s_i → commitment_i
    └─ State: [accumulated_commitment_hash, step_count]
    ↓
Nova fold n steps → compressed proof (SonobeCompressor)
    ↓
aggregator_final receives: combined_commitment_hash
    ↓
On-chain: HonkVerifier.sol checks accumulator matches d_commitment
```

Reuses existing infrastructure: ExternalInputs6, SonobeCompressor, prove_steps pattern, pipeline wiring — all already built for G.12.

## Implementation (if pursued)

### Phase 4a: NTT ring multiplication in Noir (~1 week)
- [-] Implement `ntt_mul` for R_q = Z_q[X]/(X^256+1) where q = Q_COMMIT ≈ 2^49
- [-] Cooley-Tukey NTT over 256 points, q ≡ 1 (mod 512)
- [-] Constrain forward NTT output via inverse NTT equality check
- [-] Verify correctness against native `ajtai.rs` implementation

**CANCELLED** — architectural decision: lattice operations stay in native (Cyclo) prover. NTT ring multiplication is verified by the native Ajtai commitment scheme, not R1CS.

### Phase 4a-revised: Wire native verification into FCircuit
- [x] FCircuit receives `commitment_hash_i` from native verification (already built)
- [x] FCircuit hashes via Poseidon sponge → accumulator (current placeholder IS the correct design)
- [x] Pipeline wires native Ajtai verification before FCircuit proving
- [x] ~8K constraints per step (Poseidon only, no NTT needed)

### Phase 4b: AjtaiCommitmentStepCircuit (~2 days)
- [x] FCircuit: ExternalInputs6 carries (s_i coeffs, expected commitment hash, matrix seed)
- [x] Derive Ajtai matrix A from seed via Poseidon (placeholder — NTT deferred)
- [x] Compute commitment = A·s_i (placeholder — Poseidon of coeffs)
- [x] Hash commitment → compare with expected
- [x] State: [accumulated_commitment_hash, step_count]

### Phase 4c: SonobeCompressor + pipeline wiring (~1 day)
- [x] `prove_steps_ajtai` method (pattern identical to `prove_steps_share_verify`)
- [x] Witness generation: `AjtaiCommitmentWitness` struct
- [x] Pipeline: compute `combined_commitment_hash` and pass to Prover.toml

### Phase 4d: aggregator_final Noir update (~4 hours)
- [ ] Accept `combined_commitment_hash` as public input
- [ ] Absorb into d_commitment binding
- [ ] Verify matches accumulator hash from Nova proof
