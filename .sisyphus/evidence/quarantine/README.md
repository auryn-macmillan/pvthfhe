# Quarantine Notice — Suspect APPROVE Evidence

These files were moved for forensic preservation, not deleted.
They remain available for comparison against the Stage 1 T13 multi-review re-audit.
The APPROVE verdicts here are suspected to be stale in light of red-team findings.
Stage 1 T13 multi-review supersedes these verdicts.

## Why Quarantined

The quarantined APPROVE evidence conflicts with later red-team results.
That mismatch makes the evidence suspect for current audit use.
The files are preserved in quarantine to keep git history intact.

## Quarantined Files

- `.sisyphus/evidence/final-qa/f1-plan-compliance.json` -> `.sisyphus/evidence/quarantine/final-qa/f1-plan-compliance.json`
- `.sisyphus/evidence/final-qa/f2-code-quality.json` -> `.sisyphus/evidence/quarantine/final-qa/f2-code-quality.json`
- `.sisyphus/evidence/final-qa/f3-e2e.json` -> `.sisyphus/evidence/quarantine/final-qa/f3-e2e.json`
- `.sisyphus/evidence/final-qa/f4-scope.json` -> `.sisyphus/evidence/quarantine/final-qa/f4-scope.json`
- `.sisyphus/evidence/final-qa/f2-proof-quality.json` -> `.sisyphus/evidence/quarantine/pvthfhe-followon/final-qa/f2-proof-quality.json`
- `.sisyphus/evidence/final-qa/f5-paper-readiness.json` -> `.sisyphus/evidence/quarantine/pvthfhe-followon/final-qa/f5-paper-readiness.json`

## CRITICAL Findings

- C1: `HonkVerifier.verify()` accepts proof bytes via a weak hash check.
- C2: `micronova_wrap/main.nr` and `aggregator_final/main.nr` contain tautological assertions.
- C3: Cyclo folding is only a SHA-256 hash chain, not a true lattice fold.
- C4: NIZK Fiat-Shamir misses `pvss_commitment` before challenge derivation.
- C5: Threshold validation accepts any `1≤t≤n`, while `_THRESHOLD = 4097` is unrelated.
- C6: Forged-share threshold collapse occurs through composition.

## Reference Plans

- `.sisyphus/plans/redteam-stage0-killswitch.md`
- `.sisyphus/plans/redteam-stage1-cryptographic-core.md`

## Next Steps

Use the quarantined files only for comparison.
Do not rely on these APPROVE verdicts as current truth.
Re-audit against Stage 1 T13 and the red-team findings.
If needed, compare original verdicts with new evidence line by line.
