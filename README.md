# PVTHFHE · Private-Verifiable Threshold FHE

> ⚠️ **RESEARCH PROTOTYPE — DO NOT DEPLOY** — not production-ready. Two security audits (70 + 188 findings), three MPC audits (22+ findings), all automatable findings remediated. Seven open problems remain. See [SECURITY.md](SECURITY.md) for threat model and caveats.

## What

Private-verifiable threshold Fully Homomorphic Encryption with O(n) per-party work and O(polylog n) verifier cost. Maliciously-secure DKG, verifiable decryption, and on-chain verification via Nova IVC + UltraHonk.

## Status

| Layer | Backend | State |
|-------|---------|-------|
| DKG | Pedersen over BFV/RLWE | ✅ |
| NIZK | Ajtai D2 sigma + BFV sigma (90-round) | ✅ |
| LaZer NIZK | Auto-generated sigma proofs (LaBRADOR) via LaZer C lib | ✅ Default |
| Greyhound PCS | Lattice polynomial commitments (53KB proofs) | ✅ Default |
| LatticeFold+ | Lattice-native folding (no EC assumptions) | ✅ Default |
| Folding | nova-snark (Microsoft) Nova IVC + Symphony T1–T4 | ✅ |
| Compression | Transparent IVC, no ceremony | ✅ |
| On-chain | UltraHonk verifier (Solidity) + IVC binding | ⚠️ OPEN¹ |
| Decrypt | Threshold BFV partial decrypt | ✅ |
| Greco | Input validation proofs (`just greco`) | ✅ |
| Compute | Verifiable FHE ops (`just compute`, Mul+Add in-circuit) | ✅ (Mul verified at N=8192 production scale; use --features bfv-n4 for fast testing) |

¹ IVC binding is NOT cryptographically verified on-chain; IVC mode is fail-closed.

Critical security blockers are documented in [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md).

[Full audit and feature table](ARCHITECTURE.md)

## Quickstart

```bash
# Dependencies: Rust 1.95.0, Foundry 1.6+, Noir 1.0.0-beta.20
git clone https://github.com/auryn-macmillan/pvthfhe
cd pvthfhe
PVTHFHE_ALLOW_RESEARCH_BUILD=1 cargo build
just demo-e2e          # n=10, t=4, all 14 steps
```

```
per_node_keygen_ms=12.3  per_node_dkg_deal_ms=45.7  distributed_estimate_ms=279.7
plaintext_roundtrip: OK  verify: ACCEPT
```

## Commands

| Command | What |
|---------|------|
| `just demo-e2e` | Full pipeline: DKG → encrypt → fold → decrypt → on-chain |
| `just per-node` | Single-party timing benchmark |
| `just aggregator` | Aggregator-node timing benchmark |
| `just greco` | Greco-style BFV encryption proof |
| `just compute n=5` | Verifiable FHE: sum n ciphertexts via Nova IVC |
| `just test-all` | Rust + Noir + Solidity test suite |

## Open Problems

| ID | Problem | Status |
|----|---------|--------|
| P1 | Lattice NIZK well-formedness soundness (Greco M-SIS) | OPEN |
| P2 | Lattice-native folding over RLWE (Nova substitute) | OPEN |
| P3 | Parameterized Nova step circuit verification | ✅ Resolved |
| P4 | On-chain IVC decider verification (currently fail-closed) | OPEN |
| C5 | Aggregate public-key formation proof (pk_agg = Σ pk_i) | ✅ Resolved |
| C6 | Committed-smudge enforcement | PARTIAL |
| C7 | Final aggregation / threshold-decryption correctness | ✅ Resolved |
| A1 | Cyclo accumulator transcript verification | ✅ Resolved |

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design
- [SECURITY.md](SECURITY.md) — threat model + caveats
- [WARNING.md](WARNING.md) — known surrogates
- [REPRODUCING.md](REPRODUCING.md) — benchmark reproduction
- [`.sisyphus/design/`](.sisyphus/design/) — protocol design docs
- [`.sisyphus/audit/`](.sisyphus/audit/) — audit reports + MPC findings
- [`.sisyphus/plans/`](.sisyphus/plans/) — remediation plans (all resolved)
- [docs/comparison-paper.md](docs/comparison-paper.md) — Nova IVC vs zkVM
- [bench/results/crisp-comparison.md](bench/results/crisp-comparison.md) — CRISP benchmarks

## License

MIT — see [LICENSE](LICENSE).