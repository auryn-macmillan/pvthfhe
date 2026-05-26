# Phase 4a — Revised: Lattice-Only NTT, R1CS for Aggregation Only

**Status**: DESIGN REVISED per architectural decision  
**Principle**: Lattice operations stay in lattice-native proving; only final aggregation enters R1CS/Noir

## Wrong Approach (Previous Plan)

```
AjtaiCommitmentStepCircuit (R1CS):
  └─ NTT ring multiplication over Z_q[X]/(X^256+1)  ← 13K constraints × 13 = 170K
  └─ Range checks on 256 coefficients per step         ← 12K constraints
```

This forces R1CS to emulate Z_q arithmetic (49-bit modulus in 254-bit field) — inefficient and wrong layer.

## Correct Approach

```
Native (Cyclo/Ajtai lattice prover): 
  └─ verify commit(s_i) == expected_commitment
     (Full Ajtai commitment: 13 ring mults over Z_q[X]/(X^256+1))
  └─ Proven once per party, outside R1CS
     ↓
  commitment_hash_i → passed to FCircuit via thread-local

AjtaiCommitmentStepCircuit (R1CS / FCircuit):
  └─ absorb commitment_hash_i into Poseidon sponge
  └─ State: [accumulated_hash, step_count]
  └─ ~8K constraints per step (just Poseidon, no NTT)
     ↓
Nova fold n steps → compressed proof
     ↓
aggregator_final (Noir): receive combined_commitment_hash
     ↓
On-chain HonkVerifier.sol: check against registered commitments
```

## What Changes

Phase 4a (NTT in Noir) is **cancelled**. Replaced with:

- [ ] **Phase 4a-revised**: Wire native Ajtai verification result into `AjtaiCommitmentStepCircuit`
  - Each party's commitment is verified natively (already done in Phase 3)
  - FCircuit receives `commitment_hash_i` via thread-local (already built)
  - FCircuit hashes into Poseidon sponge → accumulator (already built — current placeholder IS the real thing)
  - No code changes needed — the scaffolded `AjtaiCommitmentStepCircuit` already does exactly this

The placeholder was actually the correct design. The only missing piece is ensuring the native verification result flows through the pipeline before the FCircuit runs.

## Constraint Budget (Revised)

| Operation | Layer | Constraints |
|-----------|-------|------------|
| Ajtai commit(s_i) | Native (Cyclo) | 0 R1CS |
| Hash commitment → FCircuit | R1CS | 8K per step |
| Nova fold n steps | R1CS | 27K amortized |
| **Total per party** | | **~8K** (vs 170K with NTT) |
