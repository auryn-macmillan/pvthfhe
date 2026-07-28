# PVTHFHE · Private-Verifiable Threshold FHE

> ⚠️ **RESEARCH PROTOTYPE — DO NOT DEPLOY** — not production-ready. Two security audits (70 + 188 findings) and three MPC audits (22+ findings) are remediated; open problems remain. See [SECURITY.md](SECURITY.md) for the threat model and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for the fail-closed ledger.

## What

Private-verifiable threshold Fully Homomorphic Encryption with O(n) per-party work and O(polylog n) verifier cost. Maliciously-secure DKG, verifiable decryption, and on-chain verification via LatticeFold+ + UltraHonk — a post-quantum stack with no elliptic-curve or trusted-setup assumptions on the proving path.

## Status

| Layer | Backend | State |
|-------|---------|-------|
| DKG | Lattice PVSS over BFV/RLWE + NonEquiv + AVID (pvthfhe-pvss, pvthfhe-non-equiv) | ✅ |
| NIZK | Ajtai D2 sigma + BFV sigma (90-round); LaZer (LaBRADOR) via C lib | ✅ Default |
| Greyhound PCS | Lattice polynomial commitments (53KB proofs) | ✅ Default |
| Folding | LatticeFold+ per-channel native folding (pvthfhe-cyclo + pvthfhe-rings) | ✅ |
| Compression | Transparent IVC, per-channel accumulators, binary fold tree (in progress) | ✅ |
| On-chain | UltraHonk decider wrapper Verifier (Solidity), per-channel accumulator binding | ✅ |
| Decrypt | Threshold BFV partial decrypt + native R6/R7 relations | ✅ |
| Greco | LatticeFold+ algebraic range proof (replaces Greco quotient witnesses) | 🔄 Migrating |
| Compute | Verifiable FHE ops (`just compute`) | ✅ (Mul verified at N=8192 production scale; `--features bfv-n4` for fast tests) |

## Quickstart

```bash
# Dependencies: Rust 1.95+, Foundry 1.7+, Noir 1.0.0-beta.22, bb 5.0.0-nightly.20260522
git clone https://github.com/auryn-macmillan/pvthfhe
cd pvthfhe
git submodule update --init   # contracts/lib/* and lazer/
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build --workspace
just demo-e2e          # n=10, t=4, full pipeline
```

## Commands

| Command | What |
|---------|------|
| `just demo-e2e` | Full pipeline: DKG → encrypt → fold → decrypt → on-chain |
| `just per-node` | Single-party timing benchmark |
| `just aggregator` | Aggregator-node timing benchmark |
| `just greco` | Greco-style BFV encryption proof |
| `just compute n=5` | Verifiable FHE: sum n ciphertexts via LatticeFold+ |
| `just test-all` | Rust + Noir + Solidity test suites |
| `just stage0-gate` / `stage1-gate` / `phase2-gate` | Policy + tripwire gates (lean; meta-gates pruned 2026-07) |
| `just dkg-paper-gate` | DKG paper (ePrint 2026/1159) integration gate |
| `just bench-scripts-test` | Unit tests for the Python bench scripts |

Benchmark reports: [bench/results/comparison-2af6ac2.md](bench/results/comparison-2af6ac2.md) (latest comparison), [bench/results/crisp-comparison.md](bench/results/crisp-comparison.md) (CRISP comparison).

## Open Problems

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS) | OPEN |
| P2 | Lattice-native folding over RLWE (Nova substitute) | OPEN |
| P3 | Parameterized step-circuit verification for folding | ✅ Resolved (superseded by LatticeFold+) |
| P4 | On-chain IVC decider verification (currently fail-closed) | OPEN |
| C5 | Aggregate public-key formation proof (pk_agg = Σ pk_i) | ✅ Resolved |
| C6 | Committed-smudge enforcement | ✅ Resolved (full slot binding) |
| C7 | Final aggregation / threshold-decryption correctness | ✅ Resolved |
| A1 | Cyclo accumulator transcript verification | ✅ Resolved |
| G-N8 | Noir circuit ring dimension (N=256 vs production N=8192; beta.22 OOM) | 🔄 RESOLVING (native per-channel folding eliminates the ceiling) |

Three open (P1, P2, P4), one parameterized (G-N8). Canonical ledger: [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md).

## Repository layout

- `crates/` — Rust workspace (15 crates; see [ARCHITECTURE.md](ARCHITECTURE.md) for the crate map)
- `circuits/` — Noir circuits (see [circuits/README.md](circuits/README.md))
- `contracts/` — Foundry project (on-chain verifier)
- `bench/` — benchmark harness (Rust bins + Python scripts)
- `paper/` — the paper (LaTeX, `just paper-build`)
- `docs/` — protocol docs, security proofs, papers archive
- `.sisyphus/` — design specs, evidence, plans (read-only history)

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design
- [SECURITY.md](SECURITY.md) — threat model + caveats
- [WARNING.md](WARNING.md) — known surrogates and gaps
- [REPRODUCING.md](REPRODUCING.md) — benchmark reproduction + pinned toolchain
- [STATUS.md](STATUS.md) — current status snapshot
- [docs/papers/2026-1159.md](docs/papers/2026-1159.md) — Abraham–Bacho–Stern, *Quadratic Asynchronous DKG from Plain Setup*
- [docs/archive/](docs/archive/) — superseded Nova-era and Stage-0 documents

## License

MIT — see [LICENSE](LICENSE).
