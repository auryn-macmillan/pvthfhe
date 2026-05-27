# Deep Audit Remediation — Benchmark Baseline (Post-Remediation)

- **Produced**: 2026-05-12T19:57:47Z
- **Git SHA**: `1f37adc`
- **Parameters**: n=10, t=4, seed=1
- **Mode**: fallback-dryrun

## Baseline Status

No pre-remediation "before" snapshot exists. This document records the current state
as the post-remediation baseline after Batches A–D and the C.2 `B_M` bound fix.

## Summary

The benchmark infrastructure (`bench/i1_one_vs_two_track.py`) executes successfully
and writes valid JSON and Markdown output. The benchmark exercises:

| Probe | Return Code | Notes |
|-------|-------------|-------|
| `full_current_one_track_probe` | 0 | pvthfhe-e2e with nova-compressor, dry-run |
| `one_track_proof_producer_demo_seeded_fallback` | 0 | Fallback path with demo-seeded-rng |
| `two_track_batched_share_proof_focused_probe` | 0 | Focused PVSS batched proof test |
| `committed_smudge_decrypt_focused_probe` | 0 | Focused committed-smudge test |

## Metrics (One-Track Fallback)

| Metric | Value | Unit |
|--------|-------|------|
| DKG prover time per party | 627.100 | ms/party |
| DKG prover time per wire share | 69.678 | ms/share |
| Peak memory | 870,080 | kB |

## Gate Status

**not_fairly_measurable_current_branch**: The two-track committed-smudge DKG
benchmark runner does not exist on this branch, and the full one-track
verification remains D.1 fail-closed. The target overhead ratio (≤1.5x) is
therefore neither met nor failed by this fallback artifact.

## Regression Analysis

No regression detected — no prior baseline exists for comparison. The demo (`just demo-e2e 10`)
and force-large-n (`--n 11 --threshold 4 --seed 1 --force-large-n`) both pass with
`plaintext_roundtrip: OK` and `verify: ACCEPT`.

### C.2 Fix Impact

The C.2 `B_M` bound check in `scale_plaintext_to_rns` was overly restrictive and
rejected legitimate BFV sigma masking values (y_m coefficients sampled from [-B_Y, B_Y]
with B_Y = 2^30, exceeding B_M = 65536). The check was removed from the generic
function; plaintext-domain validation remains the caller's responsibility.

## Hardware

- CPU: AMD RYZEN AI MAX+ 395 w/ Radeon 8060S
- Cores: 8
- Memory: 65,847,068 kB
- Kernel: Linux 6.8.0-111-generic
