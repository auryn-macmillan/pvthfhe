# Reproducing Benchmarks

This document provides instructions for reproducing the scaling and performance benchmarks reported in this repository.

> ⚠️ **PRELIMINARY NUMBERS**: All pre-R9 benchmarks measure the stub/surrogate pipeline
> (SHA hash chains, toy-adder IVC, synthetic constants), not the target Architecture B
> protocol. See audit finding INFO-1 in [`.sisyphus/audit/AUDIT-2026-05-08.md`](.sisyphus/audit/AUDIT-2026-05-08.md).
> The `bench-comparison-gate` lint validates baseline freshness but does not assert
> soundness of the measured pipeline.

## Toolchain Versions (PINNED)

Reproducibility requires the exact toolchain versions used during development:

- **Rust**: `1.95.0` (`rustc 1.95.0 (59807616e 2026-04-14)`; `rust-toolchain.toml` tracks the stable channel, which resolved to 1.95.0 for these artifacts)
- **Nargo (Noir)**: `1.0.0-beta.22` (`noirc 1.0.0-beta.22`)
- **BB CLI (Barretenberg)**: `5.0.0-nightly.20260522`
- **Forge (Foundry)**: `1.6.0-v1.7.0` (commit `f83bad912a9dba7bf0371def1e70bb1896048356`)

## Git Dependency Pins (PINNED)

- **`fhe`**: `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- **`fhe-traits`**: `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b`
- **`fhe-math`**: `gnosisguild/fhe.rs` rev `5f24d0b62a7329b789db07a065b68accd614a47b` — provides the iterative Cooley-Tukey (power-of-two) Number Theoretic Transform (NTT) used by Cyclo folding ring arithmetic (`crates/pvthfhe-cyclo/src/ring.rs`) and FHE backend `decrypt_from_shares`.
- **`e3-trbfv`**: intentionally not pinned in F1; plan A3 currently prefers direct composition of `fhe::mbfv` + `fhe::trbfv`, and `fhe::trbfv` is present at the locked `fhe.rs` rev above.

## Hardware Fingerprint

The benchmarks were executed on the following hardware:

- **CPU**: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S
- **RAM**: 8 GB
- **OS**: Ubuntu 24.04 LTS (Linux 6.8.0)

## Reproducing the Scaling Suite

To run the scaling benchmarks ($n=128$ to $n=1024$):

```bash
# Run the scaling benchmarks
just bench-scaling

# Run the reproducibility script (captures fingerprint and runs 3 repeats)
just reproduce-bench
```

## Expected Runtimes

> ⚠️ These numbers reflect the stub pipeline (SHA chains, toy circuits) and are **not representative of target Architecture B performance**.

| Number of Parties ($n$) | Aggregator Latency (ms) | Verifier Gas |
| :--- | :--- | :--- |
| 128 | 1.5 | 1,278* |
| 256 | 6.0 | 1,278* |
| 512 | 43.0 | 1,278* |
| 1024 | 188.0 | 1,278* |

*\*Note: Verifier gas is constant due to the use of a surrogate UltraHonk verifier. Real UltraHonk verification costs are estimated between 200k and 500k gas.*

### Regenerating the On-Chain Verifier

The HonkVerifier.sol is generated from the Noir `aggregator_final` circuit:

```bash
# 1. Execute the Noir circuit
(cd circuits && nargo execute --package aggregator_final --prover-name Prover_re)

# 2. Generate VK with keccak oracle hash (required for EVM-compatible 1888-byte VK)
bb write_vk --scheme ultra_honk --oracle_hash keccak \
  -b circuits/target/aggregator_final.json -o circuits/aggregator_final/target/

# 3. Generate Solidity verifier (post-process to fix EVM stack overflow)
bb write_solidity_verifier -k circuits/aggregator_final/target/vk \
  -o /tmp/raw_honk.sol -t evm-no-zk
python3 .sisyphus/scripts/split-honk-vk.py \
  /tmp/raw_honk.sol contracts/src/generated/HonkVerifier.sol

# 4. Build and test
forge build --root contracts
forge test --root contracts
```

> Note: `--oracle_hash keccak` is required to produce 1888-byte VKs compatible with
> `bb write_solidity_verifier`. Without it, VKs are 3680 bytes and the generator rejects them.
> The `split-honk-vk.py` script rewrites the single massive struct literal into sequential
> assignments to avoid exceeding the EVM's 16-slot stack limit (116 G1 points).
>
> The Noir `aggregator_final` circuit now always executes in the pipeline (no env var gate).
> Its `d_commitment` binds `aggregate_pk_hash` and `decrypt_nizk_hash` — properties previously
> verified only in deletable Rust code are now enforced on-chain through the UltraHonk proof.

## Scaling Methodology

Scaling benchmarks are performed in-process using the `pvthfhe-bench` crate. The benchmarks simulate the full pipeline:
1.  **DKG**: Simulated 3-round PVSS.
2.  **Partial Decrypt**: Generation of shares for $n$ parties.
3.  **Aggregation**: Folding $n$ proofs using the `FoldingAccumulator`.
4.  **Verification**: Final SNARK verification.

The measurements reflect end-to-end latency on the host machine.

## P4 Stack Pins

The P4 Hermine-adapted PVSS design memo fixes the Rust-side cryptographic and serialization stack to the following crate versions:

- `serde = "1.0.228"`
- `serde_json = "1.0.145"`
- `sha2 = "0.10.9"`
- `sha3 = "0.10.8"`
- `merlin = "3.0.0"`
- `risc0-zkvm = "2.1.0"`
- `sp1-sdk = "5.0.0"`

These pins cover the frozen serde/JSON wire format, SHA-256 transcript digests, SHAKE256 transcript challenges, the native Rust Fiat-Shamir transcript layer, and the approved zkVM fallbacks.

## KZG SRS

The MicroNova tests bind to a local BN254 KZG SRS stub at `bench/srs/bn254.srs`.

- **Provenance**: research-prototype placeholder; replace with a real universal BN254 SRS via `bench/scripts/fetch_srs.sh`
- **Stub size**: 52 bytes
- **SHA-256**: `a4b591ff765bb642dd9950db30568f220c0e86c8c390241bf048fab234399d3a`

The test suite only checks that the artifact exists and is non-empty; real KZG parsing is deferred to later tasks.

## Artifact Reproduction (Paper Claims)

To reproduce the core paper claims in one command:

```bash
just artifact-reproduce
```

This runs, in order:
1. `cargo build --workspace` — builds all Rust crates
2. `just p3-bench` — on-chain gas benchmark (verifies P3 gas-bound claim)
3. `just e2e-real` — end-to-end real integration test

Expected total runtime: ≤ 5 minutes on reference hardware.
Evidence files are written to `.sisyphus/evidence/p3-impl/`.

For the full gate suite:

```bash
just phase1-gate && just phase2-gate && just phase3-gate && just paper-gate
```
