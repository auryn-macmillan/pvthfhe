# Bootstrapping-PV feasibility memo

DEFER: CKKS publicly verifiable bootstrapping is plausibly ~30x-80x and BFV bootstrapping ~60x-100x the cost of a decryption-share proof at N=4096 under an optimistic Noir/BB encoding; this is not on the Phase-3 critical path, but should be revisited if T12 folding benchmarks show that recursive aggregation can compress multi-million-op bootstrap statements to an effective <10x overhead.

## Scope and question

This memo asks whether we should put **publicly verifiable bootstrapping (PV bootstrap)** on the critical path of the Phase-1/2 architecture.

For this project, "publicly verifiable bootstrapping" means:

- public statement: input ciphertext `ct_in`, output ciphertext `ct_out`, public parameters, evaluation/bootstrapping keys, and any required modulus metadata;
- proved claim: `ct_out` encrypts the **same plaintext** as `ct_in` under the same threshold public key, while resetting noise / restoring modulus headroom;
- verifier model: any external observer can check the proof with no committee secret material.

This is strictly stronger than our mandatory threshold-decryption proof, which only proves correctness of a party's partial decryption share.

## Baseline: decryption-share proof cost

The mandatory statement for T35/T36 is:

- given RLWE ciphertext `(c0, c1)`, secret share `s_i`, and partial decryption `d_i`, prove `d_i = c1 * s_i + e_i` and that `e_i` satisfies the agreed noise/range bound.

For `N=4096`, a reasonable Noir/BB budget is still the inherited project estimate: **~10k-100k ACIR opcodes**. The estimate comes from one RLWE multiplication, linear combinations, and per-coefficient range/noise checks. Even if the witness is given in NTT form, this remains one "single relation" proof, not a full refresh circuit.

I use this as the comparison baseline because bootstrapping is optional while decryption-share correctness is mandatory.

## Evidence from the literature

### CKKS bootstrapping

Canonical CKKS bootstrapping has four steps:

1. `ModRaise`
2. `CoeffToSlot`
3. `EvalMod`
4. `SlotToCoeff`

Evidence:

- Cheon et al. (ePrint 2018/153) introduced CKKS bootstrapping and reported **139.8 s** to refresh 128 packed slots (about **1.1 s/slot**) and stated cost grows linearly with decryption-circuit depth.
- Bossuat et al. (ePrint 2020/1203) improved dense-key CKKS bootstrapping to **18 s** for `C^32768`, still describing bootstrapping as the bottleneck.
- Lee et al. (ePrint 2020/1549) report `EvalMod` depth **10** for state-of-the-art accuracy, versus prior depth **11-12**.
- Kim et al. (ePrint 2022/1256) note roughly **half** the consumed levels are spent in `CoeffToSlot` and `SlotToCoeff`.
- Yan et al. (ePrint 2025/1403) still frame CKKS bootstrapping as the performance bottleneck and only improve throughput by **20%-35%**.

Implication for a Noir/BB proof:

- `CoeffToSlot` and `SlotToCoeff` are each dense linear transforms with many rotations/key-switches; in a SNARK, each rotation/key-switch becomes a large arithmetic relation over all `N` coefficients and gadget limbs.
- `EvalMod` is not a tiny gadget: even the improved line still needs depth about **10-12** for the modular-reduction polynomial path.
- `ModRaise` is cheaper than the three steps above but is still an all-coefficient basis-extension consistency relation.

### BFV bootstrapping

Evidence:

- Chen-Han (ePrint 2018/067) report FV bootstrapping depth about `log h + log(log_p(ht))` and example runtimes from **6.75 s** (small 7-bit plaintext space, 64 slots) up to **1381 s** (large plaintext extension field, 128 slots).
- Geelen-Vercauteren (ePrint 2022/1363) show BGV and BFV have **identical bootstrapping complexity** at the homomorphic-operation level; BFV is not materially cheaper.
- Geelen et al. (ePrint 2022/1364) identify **digit extraction / digit removal** as the main bottleneck and state polynomial evaluations are **3x-50x more expensive than all other operations combined** in HElib; their optimization gives only up to **2.6x** speedup.
- Liu-Wang (ePrint 2024/172) achieve **1-2 orders of magnitude** speedups only by moving to **relaxed functional bootstrapping**, i.e. a weaker notion than exact "same plaintext, lower noise" refresh.
- Ma et al. (ePrint 2025/1594) still describe dense-key BGV/BFV bootstrapping as bottlenecked by high-degree polynomial evaluation and report a **2.48x** throughput improvement rather than a qualitative simplification.

Implication for a Noir/BB proof:

- BFV bootstrapping does not reduce to one RLWE multiply plus a few checks.
- The expensive part is repeated polynomial evaluation for digit extraction/removal, plus the same style of linear transforms/automorphisms/key-switches needed around it.
- Since 2024/172's large speedups come from *relaxed/functional* bootstrapping, they do not directly discharge our exact-equality PV statement.

### TFHE programmable bootstrapping (alternative, not primary scheme)

Evidence:

- TFHE programmable bootstrapping is structurally nicer for verifiability because it is one gate/LUT refresh primitive rather than a packed SIMD word-wise refresh.
- Thibault-Walter (ePrint 2024/451) give the strongest positive evidence here: a full TFHE-like programmable bootstrap can be SNARK-proven in practice in **under 20 minutes**, with **~200 kB** proof size and **<10 ms** verification using plonky2 + recursive IVC.

Implication:

- Publicly verifiable bootstrapping is not impossible in general.
- But the only concrete practical proof result we found is for **TFHE**, not for our target BFV/CKKS threshold scheme, and it relies on a proving stack tailored to recursion rather than Noir/BB arithmetic circuits.

## ACIR-size estimates for Noir/BB

These are estimates, not measured numbers. I am translating the operation mix above into a conservative Noir/BB budgeting model for `N=4096`.

### Decryption-share baseline

| Statement | Estimated ACIR ops | Reasoning |
|---|---:|---|
| Threshold decryption share correctness | 10k-100k | One RLWE multiplication + linear checks + coefficient range/noise bounds |

### CKKS bootstrapping proof

| CKKS sub-step | Estimated ACIR ops | Reasoning |
|---|---:|---|
| `ModRaise` | 50k-150k | all-coefficient basis-extension and consistency checks |
| `CoeffToSlot` | 400k-1.2M | multiple global rotations/key-switches + diagonal multiplications across `N=4096` |
| `EvalMod` | 300k-900k | depth-10-to-12 polynomial/mod-reduction path with rescaling consistency |
| `SlotToCoeff` | 400k-1.2M | inverse dense linear transform, same shape as `CoeffToSlot` |
| **Total CKKS bootstrap** | **1.15M-3.45M** | optimistic packed-circuit estimate |

Central ratio versus the `10k-100k` decryption-share baseline: **~30x-80x**.

### BFV bootstrapping proof

| BFV sub-step | Estimated ACIR ops | Reasoning |
|---|---:|---|
| Eval-map / linear transforms | 300k-800k | rotations, automorphisms, key-switch structure similar in scale to CKKS transforms |
| Digit extraction / digit removal | 900k-4.5M | dominant high-degree polynomial-evaluation component; literature says 3x-50x cost of all other ops combined |
| Inverse eval-map / cleanup | 300k-800k | same order as the forward transform |
| **Total BFV bootstrap** | **1.5M-6.1M** | exact-refresh estimate, excluding relaxed functional shortcuts |

Central ratio versus the `10k-100k` decryption-share baseline: **~60x-100x**.

## Why the proof is much larger than decryption-share correctness

The asymmetry is structural:

- decryption-share proof = one local RLWE relation;
- bootstrap proof = a full homomorphic execution trace containing basis changes, automorphisms/rotations, key-switches, and nontrivial polynomial evaluation.

Even if we aggressively witness intermediate NTT/CRT forms, the verifier still needs enough constraints to enforce:

1. same-plaintext preservation from input to output,
2. correctness of every key-switch/rotation,
3. correctness of the nonlinear refresh step (`EvalMod` or digit removal),
4. refreshed modulus/noise headroom.

That is why the gap is tens-to-low-hundreds, not single digits.

## Decision against project criteria

Project rule:

- **GO** if proof cost is within 10x of decryption-share proofs and does not delay mandatory scope.
- **NO-GO** if proof cost is >100x or needs assumptions outside the ledger.
- **DEFER** if proof cost is 10x-100x and may become acceptable with later optimizations.

Assessment:

- CKKS fits the **DEFER** bucket directly: the best reasonable Noir/BB estimate is tens-of-times larger than decryption-share proofs, not single-digit overhead.
- BFV sits on the **upper edge of DEFER**: exact bootstrapping is close to the 100x threshold, and relaxed functional variants improve cost only by weakening the statement we actually need.
- TFHE is the only variant with a concrete "proved in practice" public-verifiability result, but adopting it would change the scheme family away from our primary packed BFV/CKKS direction.

So the correct project decision is to **defer publicly verifiable bootstrapping**, not to put it on the critical path.

## Consequence for Phase 1 gate JSON

`phase1-gate.json` should eventually expose the memo result as:

```json
{
  "bootstrapping_pv_decision": "defer",
  "bootstrapping_pv_rationale": "CKKS PV bootstrapping is estimated at roughly 30x-80x and BFV at roughly 60x-100x the cost of a decryption-share proof under an optimistic Noir/BB encoding; not on mandatory-scope critical path, revisit after recursive folding benchmarks."
}
```

The current `.sisyphus/scripts/phase1-gate.py` stub is not yet wired to read this field, but this is the field name and payload shape the gate artifact should use.

## Recommendation

1. Keep mandatory public verifiability limited to **key generation + threshold decryption** in Phase 3.
2. Treat PV bootstrapping as a **post-gate stretch item** gated on T12/T13 evidence.
3. Re-open only if either:
   - recursive folding/IVC compresses a multi-million-op bootstrap statement to an effective **<10x** overhead, or
   - architecture selection shifts toward a TFHE-family design, which is currently outside the primary BFV/CKKS path.

## References

- ePrint 2018/153 — *Bootstrapping for Approximate Homomorphic Encryption*
- ePrint 2018/067 — *Homomorphic Lower Digits Removal and Improved FHE Bootstrapping*
- ePrint 2020/1203 — *Efficient Bootstrapping for Approximate Homomorphic Encryption with Non-Sparse Keys*
- ePrint 2020/1549 — *High-Precision Bootstrapping for Approximate Homomorphic Encryption by Error Variance Minimization*
- ePrint 2022/1256 — *EvalRound Algorithm in CKKS Bootstrapping*
- ePrint 2022/1363 — *Bootstrapping for BGV and BFV Revisited*
- ePrint 2022/1364 — *On Polynomial Functions Modulo p^e and Faster Bootstrapping for Homomorphic Encryption*
- ePrint 2024/172 — *Relaxed Functional Bootstrapping: A New Perspective on BGV and BFV Bootstrapping*
- ePrint 2024/451 — *Towards Verifiable FHE in Practice: Proving Correct Execution of TFHE's Bootstrapping using plonky2*
- ePrint 2025/1403 — *Faster Bootstrapping for CKKS with Less Modulus Consumption*
- ePrint 2025/1594 — *Practical Dense-Key Bootstrapping with Subring Secret Encapsulation*
- Springer Cybersecurity 2026 survey — representative RLWE bootstrap latency range **4-95 s**
