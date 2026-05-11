# Issues — pvthfhe-skeptical-audit

## 2026-05-03 Session Start

No issues yet.

## 2026-05-09 R9 — Benchmarks, Docs, External-Audit Prep

- `partial_decrypt` signature change (7 args from 10) broke 5 callers in test and bench crates
- `bench-comparison-gate` policy test needed update for new `reshare_entropy.rs` allow attribute
- `bench/tests/` directory does not exist (no freshness script)
- `baseline_smoke` bench test has pre-existing failure (plaintext length exceeds max)
