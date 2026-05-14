# P3-M4: Gas Optimization Plan

**Module**: P3-M4
**Status**: DEFERRED (blocked on P3-M3 EVM deployment)
**Last Updated**: 2026-05-14
**Depends On**: P3-M3 (EVM deploy with real HonkVerifier)
**Related Theorem**: P3-T4 (Gas-bound theorem for on-chain verification)

---

## 1. Summary

The on-chain verifier must stay under 100,000 gas per proof submission. This document captures the optimization strategy, measurement methodology, and known constraints. Actual profiling and tuning are deferred until P3-M3 delivers a deployed verifier we can measure.

## 2. Gas Targets

| Metric | Value | Source |
|--------|-------|--------|
| Baseline (Aztec UltraHonk) | ~39,687 gas | Aztec HonkVerifier.sol reference |
| Current placeholder (not real) | ~3,000,000 gas | `HonkVerifier.sol` stub (keccak256 placeholder) |
| Target ceiling | <100,000 gas | P3-M4 acceptance criteria |
| Proof size bound | ≤14 KB | P3-T4 theorem assumption |
| Public inputs | 200 bytes (fixed) | P2→P3 bundle boundary |

The 100,000 gas target accounts for LatticeFold+ specific additions layered on top of a standard UltraHonk verifier. The baseline represents a vanilla Honk verifier without LatticeFold+ customizations. We accept some overhead for our domain-specific constraints while staying well under the T4-mandated ceiling of 5,000,000 gas.

## 3. Optimization Opportunities

### 3.1 Remove Unused UltraHonk Features

LatticeFold+ proofs do not use lookup arguments. Standard UltraHonk includes lookup-related verification logic (log-derivative checks, table commitments) that burns gas but contributes nothing to our proof's soundness.

**What to strip**:
- Log-derivative accumulator verification
- Table commitment opening checks
- Lookup-specific challenge derivations

**Expected saving**: ~8,000–12,000 gas. Removing lookup logic eliminates roughly one round of multivariate openings and one batch of scalar multiplications.

### 3.2 BN254 Pairing Optimizations

BN254 pairings cost approximately 45,000 gas each on Ethereum (precompile 0x08 at base cost 45,000 + 34,000 per-pairing). LatticeFold+ requires 0–2 pairings depending on the compression strategy:

| Strategy | Pairings | Est. gas (pairings only) |
|----------|----------|--------------------------|
| No recursive wrap (direct verify) | 0 | 0 |
| Single recursive wrap | 1 | ~79,000 (base + 1 pairing) |
| Double recursive wrap or MicroNova | 2 | ~113,000 (base + 2 pairings) |
| Batch verification across proofs | amortized | variable |

**Optimization tactics**:
- Prefer a single-pairing or zero-pairing verifier design where possible
- If two pairings are unavoidable, batch the pairing check into a single `ecPairing` call when the precompile supports it (EIP-1108 reduced pairings to 34,000 each)
- Defer pairing to a separate batch verification contract that amortizes the base cost across multiple proofs when the protocol submits proofs in batches

**Critical constraint**: If we use zero pairings, we must verify that the LatticeFold+ compression circuit's soundness does not depend on a pairing-based final check. This must be confirmed with the cryptography team before selecting the zero-pairing path.

### 3.3 Inline G1/G2 Scalar Multiplication

Many verifier implementations call into general-purpose EC arithmetic libraries that add overhead per operation. Inlining the scalar multiplication loops for G1 (over Fp) and G2 (over Fp²) removes function-call overhead and lets the Solidity compiler apply more aggressive optimizations.

**What to inline**:
- G1 scalar multiplication (point on BN254 base field)
- G2 scalar multiplication (point on BN254 extension field)
- Multi-scalar multiplication (MSM) hot paths in the Pippenger bucket loop

**Expected saving**: ~3,000–7,000 gas. The exact saving depends on how many scalar multiplications the stripped-down verifier performs after removing lookup checks.

### 3.4 Additional Low-Hanging Optimizations

- **Calldata layout**: Pack proof bytes tightly. Avoid ABI-encoding overhead on fixed-size fields by reading calldata directly with `calldataload`.
- **Static precomputations**: Precompute base points and field constants as compile-time constants rather than runtime lookups.
- **Short-circuit rejections**: Fail fast on malformed inputs before entering expensive cryptographic checks. This is already a P3-T4 requirement (abort on malformed calldata within the gas ceiling).

## 4. Measurement Protocol

### 4.1 Tooling

Use Foundry's gas profiler:

```
forge test --gas-report --match-contract HonkVerifierTest
```

For per-opcode granularity, supplement with a custom Foundry test that reports gas via `gasleft()` before and after each logical verification phase.

### 4.2 Statistical Baseline

- Run 100 proof submissions with real LatticeFold+ proofs
- Record gas consumption per submission
- Report: mean, median, p95, p99, min, max
- Confirm worst-case stays under the 5,000,000 gas ceiling (T4 requirement)

### 4.3 Regression Gate

After each optimization round, re-run the same 100-proof suite. Any regression above 100,000 gas in the mean or above 5,000,000 in the maximum fails the gate.

## 5. Dependencies and Timeline

| Dependency | Status | Impact |
|-----------|--------|--------|
| P3-M3 (EVM deploy) | PENDING | Gate: cannot measure until real verifier is deployed |
| P3-T4 (gas-bound theorem) | SKELETON | Sets the hard ceiling and security rationale |
| `bb write_solidity_verifier` | BLOCKED | BB 5.0.0-nightly.20260324 produces wrong VK shape; needs upgrade |

### Sequencing

1. P3-M3 completes: real HonkVerifier deployed
2. Profile baseline with Foundry gas report (P3-M4.1)
3. Apply optimizations in order: strip lookups → inline scalarmul → pairing strategy (P3-M4.2)
4. Re-measure against 100-proof baseline (P3-M4.3)
5. Document final numbers and update `p3-micronova-target.md` (P3-M4.4)

## 6. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Stripping lookup logic introduces soundness gap | Low | High | Audit the LatticeFold+ proof structure to confirm no lookup dependency before removal |
| Zero-pairing path unsound for our circuit | Medium | High | Cryptography review must approve pairing count before selecting strategy |
| BB Solidity verifier generator remains broken | Medium | High | Manual verifier construction as fallback; document the deviation |
| Gas target unreachable without switching proof system | Low | Critical | Escalate to architecture decision if profile shows >150K gas for minimal verifier |

## 7. References

- `.sisyphus/plans/p3-m4-gas-optimization.md` — parent plan
- `docs/security-proofs/p3/theorem-inventory.md` — P3-T4 gas-bound theorem
- `docs/security-proofs/p3/p3-micronova-target.md` — P3 architecture target (to be updated on completion)
- `contracts/src/generated/HonkVerifier.sol` — current verifier stub
- Aztec Protocol: UltraHonk verifier gas benchmarks (reference baseline source)
