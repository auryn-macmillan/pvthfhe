# Issues — P3-M5 Security Proofs

## 2026-05-14

### Issue: BB Solidity verifier generator produces wrong VK shape

The currently pinned BB version (5.0.0-nightly.20260324) cannot generate a valid `HonkVerifier.sol`. This blocks P3-M3 deployment and therefore blocks all gas measurement work that T4 depends on. Tracked in `.sisyphus/design/p3/gas-optimization.md` §5.

### Issue: MicroNova verifier circuit not yet built

The MicroNova verifier circuit that the UltraHonk Noir wrapper must verify has not been implemented. This affects both T1 (UltraHonk knowledge soundness requires the concrete Noir circuit) and T2 (MicroNova reduction requires the specific Nova step circuit). Blocked on P3-M2.

### Issue: Concrete soundness bounds not computable without circuit sizes

All three documents reference concrete bounds (knowledge-soundness error ε, constraint count, gas mean) that cannot be computed until P3-M2 produces real circuits and P3-M3 deploys a real verifier. The documents are structurally complete but numerically empty.

### Issue: UltraHonk ceremony risk not documented for P3-T3

The UltraHonk variant of P3-T3 (trusted-setup security) has not been drafted. UltraHonk uses KZG commitments, which require a trusted setup. The existing P3-T3 in proof-skeletons.md covers the Groth16 ceremony for the SP1 variant, but the KZG ceremony for UltraHonk is a different risk model. This is an open task not covered by the current P3-M5 scope.

### Issue: No concrete Aztec UltraHonk security analysis citation

T1 references "Aztec Protocol's security analysis" for UltraHonk knowledge soundness, but a concrete citation (paper, audit report, or specification version) is not yet pinned. The Aztec protocol repository documentation is the assumed source but a versioned reference is needed.
