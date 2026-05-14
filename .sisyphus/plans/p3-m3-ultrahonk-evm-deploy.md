# Plan: P3 M3 — UltraHonk Verifier EVM Deployment

**Plan**: `p3-m3-ultrahonk-evm-deploy`
**Status**: DRAFT
**Created**: 2026-05-14
**Depends on**: P3-M2 (MicroNova compression)
**Goal**: Deploy the UltraHonk verifier Solidity contract to an EVM testnet and measure gas consumption.

---

## Implementation

### P3-M3.1 — Deploy HonkVerifier.sol

**Source**: Aztec protocol's `HonkVerifier.sol` (UltraHonk circuit verifier for BN254)

Deployment steps:
1. Clone Aztec protocol repo, extract `HonkVerifier.sol`
2. Compile with `solc --optimize`
3. Deploy to Sepolia testnet via Foundry
4. Verify on Etherscan

### P3-M3.2 — Generate test proof

Generate an UltraHonk proof from the MicroNova root proof (P3-M2) and submit to the on-chain verifier.

### P3-M3.3 — Measure gas

| Metric | Target | Projection |
|--------|--------|------------|
| Gas consumption | ≤ 500,000 | ~39,687 (Aztec baseline) |

### P3-M3.4 — Documentation

- Update `p3-micronova-target.md` — mark M3 complete
- Update `docs/security-proofs/p3/proof-skeletons.md` — record measured gas

## Acceptance Criteria

- [ ] HonkVerifier.sol deployed to testnet
- [ ] Valid proof accepted by on-chain verifier
- [ ] Gas measured and documented

## Estimated Effort

~1-2 weeks. Primarily EVM deployment and integration engineering.
