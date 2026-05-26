# Learnings

## G.23 Insecure RNG Guard in Justfile

- `option_env!("PVTHFHE_I_UNDERSTAND_INSECURE_RNG")` is a compile-time macro. Setting it as an env var prefix on `cargo run` works because cargo forwards env vars to the build process.
- 4 lines in Justfile needed the env var: line 31 (demo-e2e) and lines 60-62 (bench-comparison).
- Lines 63-64 (bench_comparison binary, render_comparison) don't use `demo-seeded-rng` so they don't need it.
- Verification: `cargo check` with the env var set passes (only warnings).
