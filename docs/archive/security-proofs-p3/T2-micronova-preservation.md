# P3-T2 — MicroNova Compression Preserves Knowledge Soundness of Nova IVC

**Theorem ID**: P3-T2 (MicroNova refinement)
**Status**: **DOCUMENTED — G2 full in-circuit Poseidon implemented (639K constraints/step); MicroNova compression layer remains deferred**
**Reduction target**: MicroNova soundness reduces to Nova IVC knowledge soundness
**Replaces**: P3-T2 in `proof-skeletons.md` (SP1 + Groth16 wrap variant)

---

## Statement

**Theorem P3-T2 (MicroNova Compression Preserves Knowledge Soundness).** Let the P3 pipeline use MicroNova to compress the verification of a Cyclo terminal accumulator under the frozen P2 verifier relation. Let the P2 terminal accumulator be an object `acc*` that is valid under the Nova IVC chain of length 1 (one step: verify the final Cyclo accumulator per `.sisyphus/design/spec-real-p2p3.md` §5.4). Let `π_mn` be a MicroNova proof purporting to attest that `acc*` satisfies the P2 terminal relation on public inputs `x`.

If an adversary can produce a MicroNova proof `π_mn` such that MicroNova's verifier accepts `(x, π_mn)` but no valid Nova IVC witness `(acc*, w)` exists for the P2 terminal relation on `x`, then the adversary can be converted into an adversary that breaks the knowledge soundness of the underlying Nova IVC.

In the contrapositive: **MicroNova's soundness error is bounded by the soundness error of the underlying Nova IVC**. MicroNova does not introduce new soundness assumptions; it inherits the soundness security of Nova.

Equivalently: for every PPT adversary `A` against MicroNova soundness, there exists a PPT reduction `R` against Nova IVC knowledge soundness such that:

```
Adv_A[MicroNova-soundness] ≤ Adv_R[Nova-IVC-soundness]
```

The reduction is essentially tight (constant-factor loss only, bounded by the overhead of the MicroNova verifier circuit encoding).

## P3 Stack Context

The MicroNova compression step sits between the Cyclo terminal accumulator (P2 output) and the UltraHonk Noir wrapper (P3 on-chain verifier). The full chain is:

```
Cyclo accumulator → MicroNova compresses Nova IVC proof → UltraHonk Noir circuit → HonkVerifier.sol
```

MicroNova's role is to take a Nova IVC proof (which is linear in the number of fold steps, if verified naively) and compress it to a constant-size proof suitable for nesting inside the UltraHonk Noir circuit. The compression is achieved by having MicroNova recursively verify the Nova IVC verifier circuit itself, folding each verification step into a single constant-size accumulator.

The IVC chain length in the PVTHFHE context is 1: the Cyclo accumulator is verified by a single Nova step circuit (`CycloFoldStepCircuit`). This single-step structure simplifies the soundness analysis because MicroNova's recursion depth equals 1.

## Proof Sketch

1. **MicroNova construction review.** MicroNova (Zhao, Setty, Cui, Zaverucha; IEEE S&P 2025, ePrint 2024/2099) is a folding-based argument that compresses a Nova IVC chain. It works by taking the Nova IVC verifier circuit `V_nova` and constructing a MicroNova folding scheme over `V_nova`. The MicroNova prover produces a proof `π_mn` that `V_nova` accepts on the claimed statement. The MicroNova verifier checks this proof in polylog time (in the IVC chain length).

2. **Soundness reduction.** If an adversary produces an accepting MicroNova proof `(x, π_mn)` without a valid Nova IVC witness, then either:
   - (a) The adversary has forged a MicroNova folding proof for a false statement about `V_nova`'s execution, or
   - (b) The adversary has found a valid Nova IVC witness but the MicroNova verifier incorrectly rejects it (completeness violation).

   Case (a) is ruled out by MicroNova's own knowledge-soundness theorem, which is itself reducible to Nova IVC knowledge soundness (MicroNova ePrint 2024/2099, Theorem 1). Informally, MicroNova's folding verifier is a thin wrapper around the Nova verifier; a break of MicroNova soundness translates directly to a break of Nova soundness because the MicroNova accumulator essentially replays the Nova verification step-by-step. Case (b) is the completeness direction and does not threaten soundness.

3. **PVTHFHE IVC chain length = 1.** In this protocol, the Nova IVC chain has exactly one step: the Cyclo terminal accumulator is the only object that Nova verifies. There is no multi-step recursion. This means MicroNova's compression reduces the verification of a single Nova step, not a long chain. The soundness argument for a single-step chain is strictly stronger than for a multi-step chain: there is no accumulation of soundness error across steps. The MicroNova soundness bound for chain length 1 collapses to the Nova soundness bound for a single step circuit.

4. **Nova IVC soundness (inherited).** Nova IVC's knowledge soundness rests on the assumption that the folding scheme (Nova's R1CS folding) is knowledge-sound. In the PVTHFHE stack, Nova IVC operates over the BN254/Grumpkin cycle. The concrete soundness error for a single Nova step is bounded by `|C|⁻¹` where `|C|` is the challenge space size, concretely `2⁻¹⁶⁰` for 10 rounds with 2¹⁶ challenges per round (`.sisyphus/design/fold-soundness-budget.md`).

5. **Conclusion.** An adversary that breaks MicroNova soundness at the PVTHFHE compression layer must break Nova IVC soundness for the single-step Cyclo verifier circuit. The concrete advantage is preserved up to constant factors.

## Dependencies

| Dependency | Role |
|---|---|
| MicroNova knowledge soundness theorem (ePrint 2024/2099, Theorem 1) | Primary reduction target |
| Nova IVC knowledge soundness over BN254/Grumpkin | Underlying assumption reduced to |
| Cyclo terminal accumulator correctness (P2-T1, P2-T2) | The statement that MicroNova verifies |
| `.sisyphus/design/spec-real-p2p3.md` §5.4, §6.2–6.4 | IVC chain length = 1, Option B stack |
| `.sisyphus/design/fold-soundness-budget.md` | Concrete challenge space bound (ε_fold ≤ 2⁻¹⁶⁰) |

## Single-Step Chain Simplification

The PVTHFHE Nova IVC chain has length 1. This is an important structural simplification for the soundness argument:

- **No recursive soundness accumulation.** In a standard Nova chain of length `T`, the soundness error accumulates as `T · |C|⁻¹` (ePrint 2024/2099, Lemma 2). For `T = 1`, the bound is simply `|C|⁻¹`, with no linear loss in `T`.
- **MicroNova's recursion depth equals 1.** MicroNova's own recursion is over the Nova verifier circuit, not over the Cyclo fold steps. With only one Nova step to verify, MicroNova's internal tree depth is trivial.
- **Tighter concrete bound.** The single-step structure eliminates the `T` factor from the soundness budget. The tightness loss between Nova and MicroNova is essentially the overhead of the MicroNova verifier circuit encoding, which is a small constant (likely ≤ 4× for the PLONKish gate representation of a Nova verifier).

## Open Gaps

- The concrete MicroNova soundness bound (ε_mn) for the specific Cyclo verifier circuit has not been computed numerically. This requires the final circuit's R1CS constraint count from P3-M2.
- MicroNova's ePrint paper (2024/2099) provides asymptotic bounds; a concrete-security analysis for the PVTHFHE parameter choice is not yet written.
- The MicroNova verifier circuit has not been built. The single-step Nova chain claim depends on the correctness of the `CycloFoldStepCircuit` encoding.
- The MicroNova-to-Nova reduction has not been formalised for the specific BN254/Grumpkin cycle used by Nova/Nova in the PVTHFHE stack.

## Measurement Status

G2 full in-circuit Poseidon commitment verification has been implemented: the Noir aggregator_final circuit compiles with 639K constraints/step, including 8192 coefficient witnesses hashed in-circuit and r-power correctness constraints. Real UltraHonk proofs from this circuit are verified on-chain via `HonkVerifier.sol` (`test_real_proof_accepts()` PASSES).

**Remaining deferred items:**
- A MicroNova compressed proof (the middle layer between Cyclo accumulator and UltraHonk wrap) has not yet been produced. The current pipeline goes directly from aggregator_final to UltraHonk without a MicroNova compression step.
- The MicroNova verifier circuit (the circuit that the UltraHonk Noir wrapper will verify) has not been implemented.
- The concrete MicroNova soundness bound (ε_mn) for the specific Cyclo verifier circuit has not been computed numerically.
- The MicroNova-to-Nova reduction has not been formalised for the specific BN254/Grumpkin cycle used by Nova/Nova in the PVTHFHE stack.
- The Nova IVC soundness analysis for the specific Cyclo step circuit depends on P2's own soundness theorems, which are under active development.

---

**References**

- Zhao, Setty, Cui, Zaverucha. "MicroNova: Folding-based Arguments with Efficient (On-Chain) Verification." IACR ePrint 2024/2099, IEEE S&P 2025.
- Kothapalli, Setty, Tzialla. "Nova: Recursive Zero-Knowledge Arguments from Folding Schemes." CRYPTO 2022.
- `.sisyphus/design/spec-real-p2p3.md` §5.4 (IVC chain structure), §6.2–6.4 (Option B stack).
- `.sisyphus/design/fold-soundness-budget.md` (challenge space bound derivation).
- `docs/security-proofs/p3/proof-skeletons.md` (original P3-T2 skeleton, SP1 + Groth16 variant).
