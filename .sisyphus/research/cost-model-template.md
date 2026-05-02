# Cost Model Template

## Overview
This template defines the cost axes for evaluating candidate architectures A, B, C.
Filled instances live at `.sisyphus/research/arch-{A,B,C}-costs.json` and are validated
against `costs.schema.json`.

## Cost Axes

### 1. Per-party communication (bytes)
- Asymptotic class: O(?)
- Description: bytes sent/received per party per protocol round
- Includes: share messages, proof data, broadcast

### 2. Per-party computation (ops)
- Asymptotic class: O(?)
- Description: arithmetic operations per party
- Includes: NTT, polynomial multiplication, hash, NIZK prover

### 3. Aggregator computation (ops)
- Asymptotic class: O(?)
- Description: work done by the aggregating party
- Includes: share combination, proof aggregation, folding

### 4. Verifier computation (ops)
- Asymptotic class: O(?)
- Description: work done by the public verifier
- Includes: SNARK verification, on-chain calldata parsing

### 5. On-chain calldata (bytes)
- Asymptotic class: O(?)
- Description: bytes posted to the EVM per threshold decryption
- Includes: proof, public inputs, ciphertext reference

### 6. On-chain gas (gas units)
- Asymptotic class: O(?)
- Description: EVM gas consumed per threshold decryption verification
- Target: ≤5,000,000 gas; hard ceiling: 10,000,000 gas

## Concrete Cost Table

| n | Per-party comm (bytes) | Per-party compute (ops) | Aggregator compute (ops) | Verifier compute (ops) | Calldata (bytes) | Gas |
|---|---|---|---|---|---|---|
| 64 | TBD | TBD | TBD | TBD | TBD | TBD |
| 128 | TBD | TBD | TBD | TBD | TBD | TBD |
| 256 | TBD | TBD | TBD | TBD | TBD | TBD |
| 512 | TBD | TBD | TBD | TBD | TBD | TBD |
| 1024 | TBD | TBD | TBD | TBD | TBD | TBD |

## Asymptotic Summary

| Axis | Big-O class | Constants |
|---|---|---|
| Per-party comm | O(?) | TBD |
| Per-party compute | O(?) | TBD |
| Aggregator compute | O(?) | TBD |
| Verifier compute | O(polylog n) | TBD |
| Calldata | O(?) | TBD |
| Gas | O(polylog n) | TBD |

## Notes
- All concrete values are placeholders; T8/T9/T10 fill arch-specific JSON instances
- T15 compiles the filled instances into a comparison matrix
- Gas target: ≤5M (hard ceiling 10M)
