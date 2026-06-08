DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- On-chain verification: UltraHonk verifier (committing to LatticeFold+ state); however, the on-chain contract does **NOT** cryptographically verify the folding proof. Verification is fail-closed.
- KZG trusted setup: removed with Track A deprecation (nova-snark deleted). LatticeFold+ uses lattice-native Ajtai commitments with no trusted setup.
- Surrogate compressor only available via `--features surrogate-compressor` (not in defaults). Must set `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` to use.
- No active surrogates on the default path — all paths use real cryptographic proofs (LatticeFold+ folding + Poseidon R1CS + real sigma/BFV NIZK). All surrogate code is feature-gated behind `surrogate-compressor` (requires explicit opt-in).
- G-N8 circuit gap: Noir circuits (`aggregator_final`, `decrypt_share`) operate on N=8 polynomials while production RLWE uses N=8192. The mapping from N=8192→N=8 is performed in untrusted native Rust with no proof of correctness-preservation. On-chain verification accepts N=8 projections without cryptographically verifying the reduction.

See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [SECURITY.md](SECURITY.md), and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for details.
