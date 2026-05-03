# P3 Security Proofs — Advisor Verdict

**Date**: 2026-05-03  
**Scope**: P3 on-chain verifier, ECDSA secp256k1 / `ecrecover` implementation (Option C)  
**Theorems reviewed**: T1 (Completeness), T2 (Soundness), T3 (Trusted Setup), T4 (Gas Bound), T5 (Cross-Input Binding)

---

## Review Notes

### T1 — Completeness

The proof is a direct computation with no hardness assumption. The chain
`Sign(sk*, ·)` → `ecrecover(·)` → `address comparison` is correctly traced
through IEEE P1363 / RFC 6979 and the EVM Yellow Paper §F. No gaps detected.
The proof correctly notes that completeness is independent of security
assumptions — it is purely algorithmic.

**Status: ACCEPTED**

---

### T2 — Soundness (EUF-CMA reduction)

The reduction from `verify`-soundness to ECDSA EUF-CMA is tight (loss factor = 1).
The forger construction is correct: the adversary's output `(publicInputs*, v*, r*, s*)`
maps directly to an ECDSA forgery `(keccak256(publicInputs*), v*, r*, s*)`.

The proof correctly handles the keccak256 pre-processing step by adding a second-preimage
resistance term `ε_SPR` to the total soundness error. The combined bound
`ε_total ≤ ε_EUF-CMA + ε_SPR` is rigorous.

One minor point: the proof notes the CMA game provides a signing oracle, but the
verifier is non-interactive, so `A` never uses the oracle. This makes the reduction
only stronger (no-query CMA is a special case of CMA). Correctly handled.

**Status: ACCEPTED**

---

### T3 — Trusted-Setup Analysis

The three claims are well-structured:
- **Claim A** (no toxic waste): Correctly argued by inspection of the `verify()` function;
  no CRS, no structured reference string, no ceremony.
- **Claim B** (single-point trust): Correctly reduces all soundness to `sk*` security.
- **Claim C** (key rotation): Correctly argues forward security under rotation.

The threat table is comprehensive and honest about the post-quantum migration risk.
No gaps in the formal argument.

**Status: ACCEPTED**

---

### T4 — Gas Bound (from first principles)

The gas arithmetic is explicit and cites the correct EIPs:

| Item | Claimed | Verification |
|------|---------|-------------|
| Non-zero calldata byte | 16 gas (EIP-2028) | ✓ |
| Zero calldata byte | 4 gas (EIP-2028) | ✓ |
| `ecrecover` precompile | 3,000 gas (EIP-1884 / Byzantium) | ✓ |
| Warm CALL to precompile | 100 gas (EIP-2929) | ✓ |
| `KECCAK256` base | 30 gas (Yellow Paper §A) | ✓ |
| `KECCAK256` per-word | 6 gas/word (Yellow Paper §A) | ✓ |
| 200 bytes = 7 words | ceil(200/32) = 7 | ✓ |
| Total analytic bound | 5,485 gas | ✓ |
| Empirical (Forge) | 5,273 gas | ✓ (consistent, analytic is conservative) |

The empirical 5,273 gas is below the 5,485 analytic upper bound because real
`publicInputs` contain zero bytes (4 gas vs. 16 gas). The analytic bound is
validly conservative (all-non-zero worst case).

The adversarial 14 KB case is correctly bounded at 2,211,514 gas (including
transaction overhead) << 5,000,000 gas budget.

No dynamic loops in `verify()`; the bound is a compile-time constant.

**Status: ACCEPTED — arithmetic verified independently**

---

### T5 — Cross-Input Binding

The reduction to keccak256 second-preimage resistance is correct and tight.
Step 4 (ECDSA nonce non-collision) provides a useful tightening argument,
correctly noting that a fixed `(v, r, s)` can verify against at most one
message per public key. The SPR bound of `2^{-256}` under ROM is standard.

**Status: ACCEPTED**

---

## Summary Table

| Theorem | Reduction Target | Proof Quality | Gaps |
|---------|-----------------|---------------|------|
| T1 Completeness | Direct computation | Complete | None |
| T2 Soundness | ECDSA EUF-CMA (tight) | Complete | None |
| T3 Trusted Setup | Key security (no ceremony) | Complete | None |
| T4 Gas Bound | EVM gas schedule constants | Complete, empirically confirmed | None |
| T5 Cross-Input Binding | keccak256 SPR | Complete | None |

All five theorems are complete with explicit reductions, no hand-waving, and
no open gaps. The gas arithmetic in T4 matches the empirical forge measurement
(5,273 gas) within the conservative analytic bound (5,485 gas).

---

## VERDICT: APPROVE
