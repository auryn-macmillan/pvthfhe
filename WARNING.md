DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- On-chain verification: UltraHonk verifier (committing to Nova state); however, the on-chain contract does **NOT** cryptographically verify the IVC proof. IVC mode is fail-closed.
- Noir circuits: implement aggregation and wrapping logic; however, the `aggregator_final` circuit proves only a hash binding, **NOT** decryption correctness (C7).
- Public Key Aggregation: there is **NO** public proof that `pk_agg = Σ pk_i` (C5).
- Cyclo folding: accumulator transcript verification is **OPEN** ([A1](docs/OPEN-PROBLEM-BLOCKERS.md#a1--cyclo-accumulator-transcript-verification)). Nonzero accumulator bytes are rejected fail-closed; the accepted empty `acc_len=0` path is only a non-folded placeholder, **NOT** fold verification.
- Do not use for The Interfold or any production deployment
- KZG trusted setup: uses nova-snark test-utils SRS (`default_ck_hint()`, generated at runtime). Production requires a real MPC ceremony SRS via `PublicParams::setup_with_ptau_dir()` (e.g., Aztec Ignition SRS, already used by UltraHonk).
- Surrogate compressor only available via `--features surrogate-compressor` (not in defaults). Must set `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` to use.
- No active surrogates on the default path — all paths use real cryptographic proofs (nova-snark IVC + Poseidon R1CS + real sigma/BFV NIZK). All surrogate code is feature-gated behind `surrogate-compressor` (requires explicit opt-in) or `legacy-nova` (reference only).

See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [SECURITY.md](SECURITY.md), and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for details.
