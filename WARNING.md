DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- On-chain verification: UltraHonk decider-wrapper verifier (committing to per-channel LatticeFold+ accumulator state); the on-chain contract does **NOT** cryptographically verify the full folding proof. Verification is fail-closed until a real decider is implemented.
- KZG trusted setup: removed with Track A deprecation (nova-snark deleted). LatticeFold+ uses lattice-native Ajtai commitments with no trusted setup.
- Surrogate compressor only available via `--features surrogate-compressor` (not in defaults). Must set `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` to use.
- No active surrogates on the default path — all paths use real cryptographic proofs (per-channel LatticeFold+ folding + real sigma/BFV NIZK). All surrogate code is feature-gated behind `surrogate-compressor` (requires explicit opt-in).
- Per-channel fold cost: native folding at production N=8192 incurs ~15-90s per fold step (ring-degree-dependent). Binary fold trees (acc+acc, 2.2× wall-time reduction) mitigate this. A fast-test path at N=256 (`--features fast-ring-n256`) is available for development iteration. The Noir circuit ring-dimension ceiling (N=256) is targeted for resolution via the native per-channel architecture; see `feat/native-per-channel` branch and `.omo/plans/native-arithmetic-migration.md`.

See [SECURITY-ADVISORY-001.md](docs/archive/SECURITY-ADVISORY-001.md) (archived, resolved), [SECURITY.md](SECURITY.md), and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for details.
