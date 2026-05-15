# Issues

## Pre-existing: pvthfhe-compressor build errors

**Date found**: 2026-05-15
**When running**: `just demo-e2e` (release mode with `sonobe-compressor` feature)

**Errors**:
```
error[E0599]: no function or associated item named `one` found for struct `Fp<P, N>` in the current scope
error[E0599]: no function or associated item named `zero` found for struct `Fp<P, N>` in the current scope
```

**Impact**: `just demo-e2e` fails to build in release mode. Debug build (without `sonobe-compressor` feature) works fine.

**Workaround**: Run `cargo run -p pvthfhe-cli --features "demo-seeded-rng,pipeline-extra-checks" -- demo ...` (without `sonobe-compressor`).

**Note**: This is unrelated to the timing instrumentation changes. The compressor crate has `Zero`/`One` trait import issues that may stem from a dependency version conflict.
