DO NOT DEPLOY — RESEARCH PROTOTYPE ONLY

- On-chain verification: UltraHonk verifier (committing to Nova state); however, the on-chain contract does **NOT** cryptographically verify the IVC proof. IVC mode is fail-closed.
- Noir circuits: implement aggregation and wrapping logic; the `aggregator_final` circuit now proves full Schwartz-Zippel threshold-decryption correctness (C7) — RESOLVED (2026-06-04).
- Public Key Aggregation: there is now on-chain binding + proof-of-possession for `pk_agg = Σ pk_i` (C5) — RESOLVED (2026-06-04).
- Cyclo folding: accumulator transcript verification is now implemented and verified (A1) — RESOLVED (2026-06-04). Nonzero accumulator bytes are accepted; the fail-closed empty `acc_len=0` path remains a legacy guard, not the active code path.
- Do not use for The Interfold or any production deployment
- KZG trusted setup: uses nova-snark test-utils SRS (`default_ck_hint()`, generated at runtime). Production requires a real MPC ceremony SRS via `PublicParams::setup_with_ptau_dir()` (e.g., Aztec Ignition SRS, already used by UltraHonk).
- Surrogate compressor only available via `--features surrogate-compressor` (not in defaults). Must set `PVTHFHE_I_UNDERSTAND_THIS_IS_A_MOCK=1` to use.
- No active surrogates on the default path — all paths use real cryptographic proofs (nova-snark IVC + Poseidon R1CS + real sigma/BFV NIZK). All surrogate code is feature-gated behind `surrogate-compressor` (requires explicit opt-in) or `legacy-nova` (reference only).
- G-N8 circuit gap: Noir circuits (`aggregator_final`, `decrypt_share`) operate on N=8 polynomials while production RLWE uses N=8192. The mapping from N=8192→N=8 is performed in untrusted native Rust with no proof of correctness-preservation. On-chain verification accepts N=8 projections without cryptographically verifying the reduction.

See [SECURITY-ADVISORY-001.md](SECURITY-ADVISORY-001.md), [SECURITY.md](SECURITY.md), and [docs/OPEN-PROBLEM-BLOCKERS.md](docs/OPEN-PROBLEM-BLOCKERS.md) for details.
