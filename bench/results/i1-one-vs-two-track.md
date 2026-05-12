# I.1 — One-track vs two-track PVTHFHE benchmark/dryrun

- Produced: `2026-05-11T22:53:38Z`
- Git SHA: `ae40650`
- Parameters: `n=5`, `t=2`, `seed=1`
- Mode: `fallback-dryrun`

## Gate status

**not_fairly_measurable_current_branch** — The current branch can produce one-track dry-run timing only with demo-seeded-rng verification bypass; the normal path fails closed at D.1. Two-track sk/e_sm proof surfaces and committed-smudge decrypt APIs have focused tests, but no integrated real-BFV e2e benchmark runner emits comparable DKG proof-producing timings or wire sizes. The target is therefore neither met nor failed by this fallback artifact.

DKG overhead target `<= 1.5x`: **unavailable** (No fair apples-to-apples two-track committed-smudge DKG benchmark runner exists on this branch, and full one-track verification remains D.1 fail-closed.)

Performance-advantage status: **not_fairly_measurable_current_branch** — The intended PVTHFHE performance advantage is not demonstrated by this artifact. Current data quantify only fallback/dry-run one-track costs and focused non-comparable two-track probes; fair real-BFV two-track DKG overhead remains blocked by D.1 and missing integrated benchmark output.

## Metrics

| Metric | One-track current | Two-track committed-smudge current |
|---|---:|---:|
| DKG prover time per party | 507.400 ms/party | unavailable — two-track sk+e_sm DKG proof-producing path is not wired into pvthfhe-e2e/bench runner; focused batched proof test uses MockBackend and is not comparable to real one-track BFV PVSS |
| DKG prover time per wire share | 126.850 ms/share | n/a |
| Decryption proof time per party | unavailable — non-dry-run e2e path is blocked before decrypt proof metrics; dry-run does not emit pvss_decrypt_prove JSON | 2713.536 ms/test-command |
| Fold/compression time | unavailable — dry-run returns before cyclo_fold/compressor phases | unavailable — two-track committed-smudge fold/compression is not exposed by a benchmark runner |
| Verifier time | unavailable — full verifier path fails closed at D.1 before stable comparison timing | unavailable — batched two-track verification intentionally delegates to D.1 v3 verifier and fails closed |
| Proof/wire size | unavailable — PVSS adapter does not expose aggregate proof/wire size in dry-run output | unavailable — focused tests do not emit proof/wire byte counts |
| Peak memory | 78040.000 kB | 210732.000 kB |

## Commands

See `i1-one-vs-two-track.json` for exact argv, return codes, output tails, wall times, and max RSS.  The non-bypassed current one-track probe records the D.1 fail-closed error before fallback probes are used.
