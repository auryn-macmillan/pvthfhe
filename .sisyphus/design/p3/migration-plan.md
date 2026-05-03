# P3 Migration Plan: Surrogate HonkVerifier → SP1+Groth16 Verifier

Date: 2026-05-03
Gate: D.D.4 — migration plan from surrogate HonkVerifier to production on-chain verifier

## Context

The current on-chain verifier is a surrogate `contracts/src/generated/HonkVerifier.sol` (~3M gas,
auto-generated from Noir/BB). P3 replaces this with SP1+Groth16 EVM verifier (~270k gas). This
plan covers adapter rollout, deployment script changes, surrogate retirement, and rollback criteria.

---

## Adapter Rollout Strategy

### Feature flag (Rust off-chain)

The aggregator crate uses a Cargo feature flag to gate the real-folding / production prover path:

```toml
# crates/pvthfhe-aggregator/Cargo.toml
[features]
default = []
real-folding = ["dep:sp1-sdk"]
sp1-groth16  = ["real-folding"]
```

Migration stages:

| Stage | Feature flags | Verifier contract | Notes |
|-------|--------------|-------------------|-------|
| **S0 — current** | `default` (no real-folding) | `HonkVerifier.sol` (surrogate) | P2 state |
| **S1 — shadow** | `sp1-groth16` enabled, shadow mode | Both deployed; shadow verifier receives calls but result discarded | Validate gas/calldata on real traffic |
| **S2 — dual-write** | `sp1-groth16` | Both deployed; `AggregatorV2` routes to SP1 verifier; HonkVerifier kept | Hot-swap fallback live |
| **S3 — primary** | `sp1-groth16` | SP1 verifier is sole verifier; HonkVerifier paused | Surrogate retirement pending |
| **S4 — retired** | `sp1-groth16` | HonkVerifier undeployed / tombstoned | Surrogate fully retired |

### Off-chain coordinator change

```rust
// Before (S0)
#[cfg(not(feature = "sp1-groth16"))]
fn prove_aggregate(...) -> SurrogateProof { ... }

// After (S1+)
#[cfg(feature = "sp1-groth16")]
fn prove_aggregate(...) -> Sp1Groth16Proof { ... }
```

---

## Deployment Script Changes

All Foundry deployment scripts live under `contracts/script/`.

### New scripts to add

| Script | Purpose |
|--------|---------|
| `contracts/script/DeployAggregatorV2.s.sol` | Deploy `AggregatorV2` pointing to SP1 verifier |
| `contracts/script/UpgradeToSP1Verifier.s.sol` | Swap verifier address in proxy/registry; emit `VerifierUpgraded` event |
| `contracts/script/RetireSurrogate.s.sol` | Revoke `HonkVerifier` role + emit `SurrogateRetired` event |

### Existing scripts to patch

| Script | Change |
|--------|--------|
| `contracts/script/DeployAggregator.s.sol` | Add `--with-shadow-verifier` flag for S1 |
| `contracts/script/VerifyOnChain.s.sol` | Accept `--verifier-type sp1\|honk` selector |

### Environment variables

```bash
# .env.migration (not committed; documented in REPRODUCING.md)
SP1_VERIFIER_ADDR=<deployed address from DeployAggregatorV2>
HONK_SURROGATE_ADDR=<existing HonkVerifier address>
MIGRATION_STAGE=S1   # S0 | S1 | S2 | S3 | S4
```

### Deployment sequence (S2 → S3)

```bash
# 1. Deploy SP1 verifier (already done in S1/S2)
forge script contracts/script/DeployAggregatorV2.s.sol \
  --root contracts --rpc-url $RPC --broadcast

# 2. Run shadow traffic validation (S1 → S2 gate check)
python bench/check-p3-bench.py --require-shadow-pass

# 3. Upgrade proxy to SP1 verifier
forge script contracts/script/UpgradeToSP1Verifier.s.sol \
  --root contracts --rpc-url $RPC --broadcast \
  --env-file .env.migration

# 4. Verify on-chain
forge script contracts/script/VerifyOnChain.s.sol \
  --root contracts --rpc-url $RPC \
  --verifier-type sp1
```

---

## Surrogate Retirement

The surrogate `contracts/src/generated/HonkVerifier.sol` is retired when **all** of the
following criteria are met:

| # | Criterion | Evidence artifact |
|---|-----------|-------------------|
| R1 | SP1+Groth16 verifier has processed ≥ 100 proof verifications on the target network (Sepolia or mainnet) without revert | `.sisyphus/evidence/p3-migration/shadow-pass.json` |
| R2 | Gas used ≤ 4,000,000 in all 18 benchmark cells (bench-plan matrix) | `.sisyphus/evidence/p3-bench/results.json` |
| R3 | Calldata bytes ≤ 12,288 in all 18 benchmark cells | same as R2 |
| R4 | `AggregatorV2` has been at primary verifier role for ≥ 7 days without incident | `.sisyphus/evidence/p3-migration/primary-soak.json` |
| R5 | `RetireSurrogate.s.sol` script executed and `SurrogateRetired` event confirmed on-chain | tx hash in evidence |

The surrogate file `contracts/src/generated/HonkVerifier.sol` is archived (not deleted) to
`contracts/src/generated/archive/HonkVerifier.sol.retired` after R5, preserving audit trail.

---

## Rollback Criteria

Rollback from SP1+Groth16 to surrogate HonkVerifier is triggered if **any** of:

| Trigger | Action |
|---------|--------|
| Gas used > 4,000,000 on any verified tx | Immediate revert to S2 (dual-write); page on-call |
| Calldata bytes > 12,288 on any tx | Immediate revert to S2 |
| Verifier contract revert rate > 0.1% over 24 h | Revert to S2 within 1 h SLA |
| SP1 SDK proof generation failure rate > 1% | Switch off-chain coordinator to `default` (no sp1-groth16) feature; swap verifier to HonkVerifier |
| Critical vulnerability in SP1 Groth16 circuit disclosed | Emergency pause `AggregatorV2`; reactivate HonkVerifier |

### Rollback procedure

```bash
# Reactivate HonkVerifier as primary
forge script contracts/script/UpgradeToSP1Verifier.s.sol \
  --root contracts --rpc-url $RPC --broadcast \
  --env SP1_VERIFIER_ADDR=$HONK_SURROGATE_ADDR

# Switch off-chain prover back to surrogate path
MIGRATION_STAGE=S0 cargo run -p pvthfhe-aggregator --no-default-features
```

The rollback target is the most-recently-promoted stage (e.g., S2 if at S3, S0 if at S1).
HonkVerifier is never decommissioned until S4 is confirmed stable for ≥ 7 days.

---

## Timeline

| Milestone | Target | Depends on |
|-----------|--------|------------|
| S1 shadow deployed | T31 | bench-plan matrix executed |
| S2 dual-write live | T32 | S1 shadow passing all gates |
| S3 SP1 primary | T33 | S2 soak period (R4) |
| S4 surrogate retired | T34 | All R1–R5 criteria met |

---

## VERDICT: APPROVE

This migration plan provides a staged adapter rollout via Cargo feature flags, concrete Foundry
deployment script changes under `contracts/script/`, explicit surrogate retirement criteria (R1–R5)
with evidence artifact paths, and unambiguous rollback triggers consistent with the stack-decision
memo thresholds (>4M gas, >12 KB calldata).
