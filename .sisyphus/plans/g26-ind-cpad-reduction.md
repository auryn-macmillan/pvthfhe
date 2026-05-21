# G.26 — IND-CPAD Security Reduction Plan

**Status**: RESEARCH  
**Estimate**: ~2 weeks  
**Reference**: Checri et al. (CRYPTO 2024), Boudgoust et al. (eprint 2023/016)

## Background

Threshold FHE decryption leaks information through the partial decryption oracle. Standard IND-CPA security (chosen-plaintext attack without decryption oracle) is insufficient when each committee member publishes their partial decryption share. IND-CPAD (Chosen-Plaintext with Aggregated-Decryption) models this threat.

## Current State

We use committed smudging noise: σ_smudge = 2^40 · σ_err. Each party adds independent smudging noise to their partial decryption before publishing. The aggregator combines shares with Lagrange interpolation.

## What Needs to Be Proved

### Theorem (informal)
Under the RLWE assumption with parameters (N=8192, Q≈2^174, σ_err), the threshold decryption protocol with smudging noise σ_smudge = 2^40·σ_err is IND-CPAD secure. Security loss due to threshold interaction is ≤ n·2^40 per query.

### Proof Structure

1. **RLWE instance**: Reduce IND-CPAD adversary to RLWE distinguisher
2. **Hybrid argument**: Replace each party's smudging noise with a fresh sample, moving to a uniformly random partial decryption. n hybrids, each with advantage ≤ RLWE advantage + statistical distance from smudging.
3. **Statistical distance**: ‖D_smudge - D_smudge + m‖ ≤ 2^{-40} per coefficient. With 8192 coefficients: total ≤ 8192·2^{-40} ≈ 2^{-27} per query. Amplify over q queries with union bound.
4. **Concrete parameters**: For 2^{-128} security, need smudging factor ≥ 2^44 (raise from current 2^40). Alternatively, limit decryption queries to q ≤ 2^{16}.

## Implementation Checklist

- [ ] Write formal IND-CPAD game definition
- [ ] Prove Lemma 1: RLWE → hybrid step (smudge replaces real share)
- [ ] Prove Lemma 2: Statistical distance bound per coefficient
- [ ] Prove Lemma 3: Amplification over coefficients (Rényi divergence)
- [ ] Combine lemmas into main theorem
- [ ] Derive concrete parameters for 128-bit security
- [ ] Document in `paper/security-proofs/g26-ind-cpad.tex`

## Parameter Recommendation

Raise σ_smudge from 2^40·σ_err to 2^44·σ_err for 128-bit security with unlimited queries. If queries are limited to 2^16, current 2^40 suffices.
