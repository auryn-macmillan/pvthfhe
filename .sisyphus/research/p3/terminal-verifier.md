# P3 Terminal Verifier — LatticeFold+ Folding Step Verification

**Created**: 2026-05-14
**Status**: Draft (M1)
**References**: P2-M1 CycloVerifierCCS, P3-M1 FoldVerifierStepCircuit

## Purpose

The terminal verifier encodes the LatticeFold+ folding step relation as a Nova step
circuit (FoldVerifierStepCircuit). It receives two accumulator states and verifies
that they correctly fold into a parent accumulator under the Cyclo CCS relation.

## Design

### Inputs

The `FoldVerifierStepCircuit` accepts 3 external inputs per step:

| Index | Name | Description |
|-------|------|-------------|
| `ext.0` | `acc_left_hash` | Hash commitment to the left accumulator state |
| `ext.1` | `acc_right_hash` | Hash commitment to the right accumulator state |
| `ext.2` | `expected_parent_hash` | Hash commitment to the expected parent (folded) accumulator |

### State

The circuit maintains a 2-element state:

| Index | Name | Description |
|-------|------|-------------|
| `z[0]` | `verified_count` | Number of folding steps verified so far |
| `z[1]` | `running_hash` | Accumulated hash of parent commitments |

### Step Logic

For each step `i`:

1. Accept `(acc_left_hash, acc_right_hash, expected_parent_hash)` as external inputs
2. Increment `verified_count` by 1
3. Accumulate `running_hash = running_hash + expected_parent_hash`

This captures the simplified folding-verifier relation: the circuit tracks that every
claimed fold step has been witnessed. The full R1CS encoding of the Cyclo CCS relation
(including ∞-norm checks and ring-equation verification) is deferred to M2.

### Relation to P2-M1 CycloVerifierCCS

The `CycloVerifierCCS` (P2-M1) provides the constraint system for the CCS fold
relation. In M2, the `FoldVerifierStepCircuit::generate_step_constraints` will
embed the CCS verifier equations as R1CS constraints, replacing the current
hash-accumulation placeholder.

### Relation to LatticeFold+ Tree

In the LatticeFold+ tree:
- Leaf nodes contain `(pk_i, π_i)` — public key and NIZK proof for a DKG party
- Internal nodes contain folded accumulator states
- The root accumulator commits to the entire DKG transcript

The terminal verifier checks each fold step from leaf to root, ensuring the
Merkle tree of accumulator states is well-formed.

## Non-Goals for M1

- Full Cyclo CCS R1CS encoding (deferred to M2)
- ∞-norm verification in R1CS constraints
- Ring-equation (c·z_s + z_e - t - c·d ≡ 0) constraint encoding
- MicroNova heterogeneous circuit support (Nova homogeneous steps suffice for M1)
