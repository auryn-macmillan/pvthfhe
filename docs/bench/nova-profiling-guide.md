# Nova Profiling Guide

How to profile the Sonobe Nova hot path in PVTHFHE for C7 decryption aggregation.

## Why Profile Nova

The C7 decryption aggregation pipeline folds `t` per-party decryption shares through Sonobe Nova IVC over the BN254/Grumpkin cycle. At `t=250`, this means 250 sequential `prove_step` calls, each performing:

1. Fiat-Shamir challenge derivation (Poseidon sponge permutation)
2. R1CS witness generation (`generate_step_constraints`)
3. NIFS (Non-Interactive Folding Scheme) update (relaxed R1CS + commitment folding)
4. State transition (z_i -> z_{i+1})

The target is sub-5 second total decryption at `t=114`. Profiling reveals where those 18.3 seconds (current) are actually spent.

## Prerequisites

Install the profiling tools:

```bash
# perf (Linux kernel profiler)
sudo apt install linux-tools-common linux-tools-generic

# cargo-flamegraph (visual flamegraph from perf data)
cargo install flamegraph

# Optional: hotspot viewer
cargo install inferno    # text-based flamegraph viewer
```

Enable kernel perf event access for non-root users (optional but recommended):

```bash
sudo sysctl -w kernel.perf_event_paranoid=1
```

## Which Binaries to Profile

### 1. Per-Node Benchmark (per-party workload)

The `per-node` binary simulates wall time for one party at arbitrary `n` and `t`:

```bash
# Release build (required for meaningful profiles)
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build --release -p pvthfhe-cli --bin per-node

# Profile with perf
perf record -g --call-graph dwarf \
  target/release/per-node -- --n 500 --threshold 250 --seed 1

# Generate report
perf report -g
```

This binary exercises the per-party work (keygen, Shamir split, encrypt, NIZK prove/verify) but does NOT run the Nova compression path. Use it to profile per-party cryptographic overhead.

### 2. End-to-End Demo (full pipeline including Nova)

For profiling the actual Nova prove_step hot path, profile the E2E demo:

```bash
# Build
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build --release -p pvthfhe-cli --bin pvthfhe_e2e

# Profile with flamegraph (visual)
cargo flamegraph --release -p pvthfhe-cli --bin pvthfhe_e2e -- \
  --n 20 --threshold 8 --seed 1

# Profile with perf (call-graph)
perf record -g --call-graph dwarf \
  target/release/pvthfhe_e2e -- --n 20 --threshold 8 --seed 1
perf report -g
```

### 3. Aggregator-Only (Nova compression in isolation)

The `per_aggregator` binary isolates the aggregation step:

```bash
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build --release -p pvthfhe-cli --bin per_aggregator

perf record -g --call-graph dwarf \
  target/release/per_aggregator -- --n 20 --threshold 8 --seed 1
perf report -g
```

### 4. Flamegraph (visual)

```bash
# Per-node flamegraph
cargo flamegraph --release -p pvthfhe-cli --bin per-node -- \
  --n 500 --threshold 250 --seed 1

# E2E flamegraph
cargo flamegraph --release -p pvthfhe-cli --bin pvthfhe_e2e -- \
  --n 20 --threshold 8 --seed 1
```

Output: `flamegraph.svg` (open in any browser).

## Key Functions to Profile

When examining the profile output, focus on these call chains:

### 1. `SonobeCompressor::prove_steps`

**Location**: `crates/pvthfhe-compressor/src/sonobe/mod.rs:568`

This is the top-level Nova IVC loop. Each iteration calls `nova.prove_step()` which internally:

- Computes the Fiat-Shamir challenge (Poseidon transcript)
- Generates R1CS witness via `FCircuit::generate_step_constraints`
- Performs the relaxed R1CS fold (NIFS update)
- Folds Pedersen commitments

**What to look for**: The cumulative time here dominates the Nova path. If a single step is slow, drill into the sub-functions. If the per-step cost is uniform, the bottleneck is per-iteration work.

### 2. `PoseidonSpongeVar::permute` / `permute` (R1CS gadget)

**Location**: `crates/pvthfhe-compressor/src/sonobe/poseidon_gadget.rs:66`

The Poseidon permutation runs inside R1CS for every step's Fiat-Shamir challenge. Parameters: `t=5` (rate=4, capacity=1), 8 full rounds + 60 partial rounds, alpha=5.

- **Full rounds**: 5 S-boxes per round, each costing 3 field multiplications (x^2, x^4, x^5)
- **Partial rounds**: 1 S-box per round
- **MDS mixing**: 5x5 matrix-vector multiply per round (constant * variable, free in R1CS)
- **Round constants (ARK)**: additions only, negligible cost

**Total per permutation**: ~300 R1CS constraints. Three permutations per hash8 call (2 absorbs + 1 squeeze via the sponge). The Fiat-Shamir transcript may trigger multiple hash8 calls per step.

**What to look for**: A tall `permute` or `full_sbox` tower in the flamegraph indicates Poseidon is the dominant cost. This is expected: the S-box exponentiation is the most expensive single operation in Nova folding.

### 3. `FCircuit::generate_step_constraints`

**Location (C7 circuit)**: `crates/pvthfhe-compressor/src/sonobe/c7_circuit.rs:53`

**Location (CycloFold circuit)**: `crates/pvthfhe-compressor/src/sonobe/mod.rs:185`

For the C7 circuit, this is lightweight: one field multiplication (`ext.1 * ext.0`) plus two additions. For the CycloFold circuit, it is four field additions.

**What to look for**: This function should be a sliver in the flamegraph, not a tower. If it is wide, the issue is not in the step constraints themselves but in the surrounding R1CS machinery (witness allocation, constraint system clone).

### 4. NIFS folding (arkworks `folding_schemes` internals)

Calls into `Nova::prove_step` eventually land in the NIFS prover inside the `folding_schemes` crate. These symbols will show as:

- `folding_schemes::folding::nova::Nova::prove_step`
- `folding_schemes::nifs::NIFS::prove`
- Pedersen commitment operations (scalar multiplications on BN254 G1 / Grumpkin G2)

### 5. Field Multiplication (`ark_bn254::Fr` arithmetic)

At the bottom of every R1CS constraint stack lives field multiplication over the BN254 scalar field (254-bit prime). These appear as:

- `ark_ff::fields::arithmetic::*`
- Montgomery multiplication internals

**What to look for**: A broad `Fr::mul_assign` or Montgomery reduction bar is normal. This is the compute substrate of all Nova work. If this bar dominates (>60% of prove_step time), the bottleneck is raw arithmetic throughput, not algorithm design.

## Expected Profiling Results

### Per-node at n=500, t=250

```
per_node n=500 t=250
  keygen:         ~0.5s  (one key pair, degree=8192)
  shamir_split:   ~3.2s  (~6.4ms per share x 499)
  encrypt:        ~31.2s (~62.5ms per share x 499)
  nizk_prove:     ~6.2s  (~12.5ms per proof x 499)
  nizk_verify:    ~1.6s  (249 proofs at ~6.4ms each)
  total:          ~42.7s
```

Note: The per-node binary does NOT measure Nova compression. The ~42.7s figure represents per-party cryptographic work, not the aggregator's Nova folding cost. For Nova-specific profiling, use the E2E demo or `per_aggregator` binary.

### E2E demo at n=20, t=8 (approximate)

| Phase | Wall Time | Dominant Function |
|-------|-----------|-------------------|
| C7 IVC folding | ~2-4s | `prove_steps` / Poseidon |
| aggregate_decrypt | ~0.5-2s | `decrypt_from_shares` (NTT) |

## Bottleneck Analysis

The expected bottlenecks, in order of likely impact:

### 1. Poseidon Permutation (Likely Hotspot)

The Poseidon sponge runs once per `prove_step` for Fiat-Shamir challenge derivation and potentially again for transcript updates. With `t=250` steps and 3 permutations per hash8 call, this is ~750 permutations.

Each permutation runs 68 rounds (8 full + 60 partial) through `permute()`. The full S-box (5 elements, 3 multiplications each = 15 mults per full round) and partial S-box (1 element, 3 mults) plus MDS mixing (25 constant*variable mults per round) add up to roughly:

- 4 full rounds x 15 mults = 60 mults
- 60 partial rounds x 3 mults = 180 mults
- 4 full rounds x 15 mults = 60 mults
- 68 rounds x 25 MDS mults = 1700 mults
- **Total**: ~2000 field multiplications per permutation

At ~250ns per BN254 Fr multiplication (reference hardware), that is ~0.5ms per permutation, or ~1.5ms per hash8 call. With 250 steps, that is ~375ms in Poseidon alone. The actual cost in practice is higher due to R1CS constraint management overhead.

**Flamegraph signature**: A tall, narrow tower labeled `permute` with many `full_sbox` and `partial_sbox` children stacked underneath. The MDS `mix` function should appear as a wide section between S-box layers.

### 2. Field Multiplication (Substrate)

All Nova operations reduce to field multiplication over BN254's 254-bit scalar field. Profiling will show a wide base of `Fr` arithmetic that everything else sits on top of.

**Flamegraph signature**: A broad, flat bar at the bottom of every flame stack. Montgomery reduction (`fr_reduce`) or `mul_assign` appearing as the widest individual symbol.

### 3. Fiat-Shamir Challenge Derivation

The transcript absorb/squeeze cycle runs inside `prove_step`. It serializes R1CS instances, absorbs them into the Poseidon sponge, and squeezes the challenge. The serialization cost (converting R1CS matrices to field element vectors) can be non-trivial.

**Flamegraph signature**: A flame tower branching off `prove_step` with `absorb` and `squeeze_one` calls to the Poseidon sponge, interleaved with serialization calls.

### 4. Pedersen Commitment Folding

NIFS updates fold Pedersen commitments on BN254 G1 (accumulator) and Grumpkin G2 (proof). These are fixed-base scalar multiplications and should be fast relative to R1CS operations.

**Flamegraph signature**: `Pedersen::fold` or `group::*` operations appearing as moderate-width towers, typically narrower than the Poseidon tower.

## Reading Flamegraph Output

A flamegraph stacks function calls from bottom (caller) to top (callee). Width is proportional to CPU time.

### What to look for

1. **Tall narrow towers**: Deep call stacks. The function at the top is a leaf; its immediate parent is the direct caller. Tall towers in `permute` -> `full_sbox` indicate Poseidon is the hot path.

2. **Wide flat bars**: Self-time heavy functions. A wide bar means the function itself (not its children) consumes significant CPU. `Fr::mul_assign` or Montgomery reduction appearing as wide bars is expected.

3. **Plateaus**: Functions with many same-level siblings (wide and flat). The MDS mix layer produces a plateau during Poseidon: `FpVar::constant(mds[i][j]) * state[j]` for each cell.

4. **Hot loops**: Repeated patterns. If you see the same stack pattern repeating many times across the graph, it indicates a loop in the code. The `prove_step` loop over 250 participants will produce 250 near-identical stacks side by side.

### Practical reading workflow

1. Open `flamegraph.svg` in a browser
2. Search (Ctrl+F) for `prove_step` or `prove_steps` to locate the Nova IVC section
3. Click on the `prove_step` bar to zoom in
4. Observe the relative widths of Poseidon vs NIFS vs R1CS constraint generation
5. Search for `permute` to isolate Poseidon cost
6. Search for `Fr::` or `mul_assign` to see the arithmetic substrate
7. Hover over bars to see the full function name and source file location

### Quick perf recipes

```bash
# Top 20 functions by self-time
perf report --sort symbol -n --stdio | head -30

# Call-graph with callees expanded for prove_step
perf report -g 'graph,0.5,caller' --symbol-filter='prove_step'

# Annotate source (requires debug info)
perf annotate -s 'SonobeCompressor::prove_steps'
```

## Reducing Profiling Noise

For consistent, comparable profiles:

1. **Disable turbo boost**: `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo` (Intel) or set CPU governor to `performance`
2. **Pin to one core**: `taskset -c 0 cargo flamegraph ...`
3. **Use a fixed seed**: `--seed 1` for deterministic execution
4. **Warm the filesystem cache**: run once before profiling
5. **Build with `--release`**: debug builds are 10-100x slower and profile differently
6. **Include debug symbols**: add `debug = 1` to the release profile in `Cargo.toml` for function name resolution

```toml
# In workspace Cargo.toml or .cargo/config.toml
[profile.release]
debug = 1
```

## Profiling the C7 Merkle Path

The Merkle variant (`prove_steps_merkle`) adds Merkle proof verification per step via `C7MerkleStepCircuit`. To profile this path:

```bash
cargo flamegraph --release -p pvthfhe-cli --bin pvthfhe_e2e -- \
  --n 128 --threshold 64 --seed 1 --track b
```

Key additional functions:
- `C7MerkleStepCircuit::generate_step_constraints` (`c7_merkle_circuit.rs`)
- `hash8` / `PoseidonSpongeVar::absorb` for Merkle root verification
- Sibling path verification loops

The Merkle path adds ~3000-6000 R1CS constraints per step (depending on tree depth) from the Poseidon hash8 calls for Merkle proof validation.

## References

- **Sonobe Nova IVC**: `crates/pvthfhe-compressor/src/sonobe/mod.rs`
- **C7 circuit**: `crates/pvthfhe-compressor/src/sonobe/c7_circuit.rs`
- **Poseidon gadget**: `crates/pvthfhe-compressor/src/sonobe/poseidon_gadget.rs`
- **Per-node binary**: `crates/pvthfhe-cli/src/bin/per_node.rs`
- **REPRODUCING.md**: toolchain pins and hardware fingerprint
- **`.sisyphus/plans/performance-optimization-sub5s.md`**: A.3 batch specification
