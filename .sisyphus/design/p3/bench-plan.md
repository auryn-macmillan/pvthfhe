# P3 Benchmark Plan

Date: 2026-05-03
Gate: D.D.4 — P3 benchmark matrix and measurement protocol

## Context

This document defines the benchmark matrix, axes, metrics, and measurement protocol for P3
on-chain verifier evaluation. The primary stack is SP1 + Groth16 EVM wrap (~270k gas, ~260 B
proof); the fallback is Rust-in-zkVM + Groth16/PLONK EVM wrap.

Rollback triggers from stack-decision:
- Gas > 4,000,000 on any network tier
- Calldata > 12,288 bytes (12 KB)

---

## Benchmark Matrix

### Axes

| Axis | Values |
|------|--------|
| **n** (party count) | 128, 512, 1024 |
| **stack** | SP1+Groth16, Rust-in-zkVM+Groth16 |
| **network** | local-anvil, sepolia-fork, mainnet-fork |

### Full Matrix (n × stack × network = 18 cells)

| n | stack | network | gas used | calldata bytes | prover wall-time | verifier wall-time |
|---|-------|---------|----------|----------------|------------------|--------------------|
| 128 | SP1+Groth16 | local-anvil | TBD | TBD | TBD | TBD |
| 128 | SP1+Groth16 | sepolia-fork | TBD | TBD | TBD | TBD |
| 128 | SP1+Groth16 | mainnet-fork | TBD | TBD | TBD | TBD |
| 128 | Rust-in-zkVM+Groth16 | local-anvil | TBD | TBD | TBD | TBD |
| 128 | Rust-in-zkVM+Groth16 | sepolia-fork | TBD | TBD | TBD | TBD |
| 128 | Rust-in-zkVM+Groth16 | mainnet-fork | TBD | TBD | TBD | TBD |
| 512 | SP1+Groth16 | local-anvil | TBD | TBD | TBD | TBD |
| 512 | SP1+Groth16 | sepolia-fork | TBD | TBD | TBD | TBD |
| 512 | SP1+Groth16 | mainnet-fork | TBD | TBD | TBD | TBD |
| 512 | Rust-in-zkVM+Groth16 | local-anvil | TBD | TBD | TBD | TBD |
| 512 | Rust-in-zkVM+Groth16 | sepolia-fork | TBD | TBD | TBD | TBD |
| 512 | Rust-in-zkVM+Groth16 | mainnet-fork | TBD | TBD | TBD | TBD |
| 1024 | SP1+Groth16 | local-anvil | TBD | TBD | TBD | TBD |
| 1024 | SP1+Groth16 | sepolia-fork | TBD | TBD | TBD | TBD |
| 1024 | SP1+Groth16 | mainnet-fork | TBD | TBD | TBD | TBD |
| 1024 | Rust-in-zkVM+Groth16 | local-anvil | TBD | TBD | TBD | TBD |
| 1024 | Rust-in-zkVM+Groth16 | sepolia-fork | TBD | TBD | TBD | TBD |
| 1024 | Rust-in-zkVM+Groth16 | mainnet-fork | TBD | TBD | TBD | TBD |

### Metric Definitions

| Metric | Unit | Measurement method |
|--------|------|--------------------|
| **gas used** | gas units | `eth_estimateGas` / forge test `--gas-report` |
| **calldata bytes** | bytes | `len(tx.data)` at call site |
| **prover wall-time** | seconds | `time` wrapper around `sp1_sdk::prove` / zkVM prove call |
| **verifier wall-time** | milliseconds | forge test elapsed for `verify()` call only |

### Budget Thresholds

| Metric | Soft warn | Hard fail (rollback trigger) |
|--------|-----------|------------------------------|
| gas used | > 2,000,000 | > 4,000,000 |
| calldata bytes | > 8,192 | > 12,288 |
| prover wall-time | > 300 s | > 600 s |
| verifier wall-time | > 500 ms | > 2,000 ms |

---

## Measurement Protocol

### Environment setup

```bash
# Network tiers
# 1. local-anvil: anvil --block-time 0 (instant mining, no gas cost distortion)
anvil --block-time 0 --chain-id 31337

# 2. sepolia-fork: fork from a stable Sepolia RPC at a pinned block
anvil --fork-url $SEPOLIA_RPC_URL --fork-block-number $SEPOLIA_FORK_BLOCK --chain-id 11155111

# 3. mainnet-fork: fork from a stable mainnet RPC at a pinned block
anvil --fork-url $MAINNET_RPC_URL --fork-block-number $MAINNET_FORK_BLOCK --chain-id 1
```

### SP1+Groth16 prover run

```bash
# Off-chain prove (for each n in {128,512,1024})
time cargo run -p pvthfhe-aggregator --release --features sp1-groth16 -- prove --n $N
# Output: target/sp1-proof-n${N}.bin + calldata estimate printed to stdout
```

### Gas measurement (Foundry)

```bash
# Run gas report for verifier contract
forge test --root contracts --match-test testVerify --gas-report --fork-url $RPC 2>&1 \
  | tee bench/gas-report-n${N}-${STACK}-${NETWORK}.txt
```

### Calldata measurement

```bash
# Decode calldata bytes from forge verbose output
forge test --root contracts --match-test testVerify -vvv --fork-url $RPC 2>&1 \
  | grep "calldata" | awk '{print $NF}' \
  > bench/calldata-n${N}-${STACK}-${NETWORK}.txt
```

### Aggregation

Results are collected into `bench/results-p3.csv` with columns:
`n,stack,network,gas_used,calldata_bytes,prover_wall_time_s,verifier_wall_time_ms`

Pass/fail thresholds are evaluated by `bench/check-p3-bench.py` which reads the CSV and
emits `.sisyphus/evidence/p3-bench/` JSON records.

### Reproducibility

- All RPC fork URLs and block numbers pinned in `REPRODUCING.md` (T44).
- Prover binary version, SP1 SDK version, and Groth16 circuit hash recorded in each evidence file.
- Three warm-up runs discarded; five measurement runs averaged.

---

## VERDICT: APPROVE

The benchmark matrix covers all required axes (n, stack, network), all required metrics
(gas, calldata, prover time, verifier time), provides concrete measurement commands, and
defines hard rollback thresholds consistent with the stack-decision memo.
