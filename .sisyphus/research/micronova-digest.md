# MicroNova: Implementation-Oriented Digest

**Paper**: IACR ePrint 2024/2099 — "MicroNova: Folding-based Arguments with Efficient (On-Chain) Verification"
**Authors**: Jiaxing Zhao (USTC + Microsoft Research), Srinath Setty (MSR), Weidong Cui (MSR), Greg Zaverucha (MSR)
**Venue**: IEEE S&P 2025, pp. 1964–1982
**ePrint**: https://eprint.iacr.org/2024/2099 (PDF: 1486 lines extracted via pdftotext)
**Note**: Repo `paper/bib.bib` references ePrint 2024/1826 — **WRONG**, that is a quantum-cloning paper. Bib must be corrected to 2024/2099.

---

## 1. Paper Metadata

| Field | Value |
|---|---|
| Full title | MicroNova: Folding-based arguments with efficient (on-chain) verification |
| Authors | Jiaxing Zhao, Srinath Setty, Weidong Cui, Greg Zaverucha |
| Affiliations | University of Science and Technology of China; Microsoft Research |
| Venue | IEEE S&P 2025 (May 12–15, 2025, San Francisco) |
| ePrint number | 2024/2099 (NOT 2024/1826) |
| Implementation | Open-source Rust (~11,000 LoC) + Solidity (~3,300 LoC) |

---

## 2. What MicroNova Is (and Is Not)

### 2.1 What it is

A **folding-based IVC (Incremental Verifiable Computation) scheme** producing proofs of `y = F^(ℓ)(x)` where:
- `F` is a step function encoded as R1CS
- `x` is initial input, `y` is final output, `ℓ` is the number of steps
- Proof size and verifier time are **independent of ℓ**
- The final IVC proof is then **compressed** to a succinct SNARK for on-chain verification

### 2.2 What it is NOT

- **NOT lattice-native**. MicroNova is built over **BN254 / Grumpkin** ("half-pairing" elliptic curve cycle) using:
  - KZG univariate polynomial commitments (over BN254, pairing-friendly)
  - Pedersen commitments (over Grumpkin, non-pairing-friendly)
  - **Universal trusted setup** (KZG ceremony — can reuse existing ceremonies like Powers-of-Tau)
- **NOT post-quantum**. Discrete-log/pairing assumptions only.
- **NOT a folding scheme for lattice relations**. Encoding a Cyclo (lattice) accumulator into a MicroNova-compatible R1CS instance is a separate research problem (this is the **P3 open problem** in PVTHFHE's SECURITY.md).

---

## 3. Core Construction (Round-by-Round)

### 3.1 Layered Architecture

MicroNova decomposes into four reductions of knowledge (RoKs):

1. **NIFS** (Non-Interactive Folding Scheme) — folds two committed-relaxed-R1CS (CRR1CS) instances into one. Modified Nova over a half-pairing cycle.
2. **MicroSpartan** — proves satisfiability of a CRR1CS instance, reducing to a Linear Knowledge Polynomial (LKP) instance via sum-check + polynomial evaluation. Variant of Spartan tuned to avoid expensive on-chain operations.
3. **HyperKZG** — multilinear polynomial evaluation argument reducing to a batched univariate KZG opening.
4. **HASH-to-HAC RoK** (Construction 1) — auxiliary RoK that lets the in-circuit verifier use Poseidon while the on-chain verifier checks a Keccak commitment, bridging the hash-function mismatch.

### 3.2 Compression Pipeline

```
IVC chain F^(ℓ) (R1CS, Poseidon)
       │
       ▼  (NIFS folds at each step)
Committed Relaxed R1CS instance Uₙ
       │
       ▼  (Construction 3: SNARK of valid IVC)
MicroSpartan (sum-check + LKP)
       │
       ▼  (Construction 4: CRR1CS → LKP)
HyperKZG opening (batched KZG)
       │
       ▼  (Construction 5: MPE → UPE)
Single batched univariate KZG check
       │
       ▼  (Solidity verifier)
On-chain: O(log N) MSM + 2 pairings ≈ 2.2M gas
```

### 3.3 The Hash-Function Bridge (Critical Innovation)

**Problem**: Recursive verifier circuits need an algebraic hash (Poseidon) for efficiency, but on-chain Solidity wants Keccak. Replacing Poseidon with Keccak inside the circuit is prohibitively expensive.

**Solution (Construction 1, Lemma 4.1)**: Lightweight RoK from `HASH` to `HAC` (Hash-Accumulated Commitment) that:
- The in-circuit (recursive) verifier produces a Poseidon-accumulated commitment digest
- The verifier additionally commits to the same data with a Keccak fingerprint, generated *outside* the circuit
- A random-challenge-based fingerprinting check ensures consistency
- The on-chain verifier only needs to (a) Keccak-hash and (b) re-execute the fingerprint operation — both are cheap

This avoids producing any extra SNARK and adds O(1) overhead.

---

## 4. Soundness Theorems

### 4.1 Theorem 4.1 — A SNARK of a Valid IVC Proof

Construction 3 (compose Construction 2's IVC with MicroSpartan and HASH→HAC RoK) is a **succinct, knowledge-sound SNARK** for the relation "there exists an IVC proof π attesting `y = F^(ℓ)(x)`," assuming:
- Knowledge soundness of the underlying SNARK (MicroSpartan)
- Knowledge soundness of the auxiliary RoK (Construction 1)
- Folding scheme (NIFS) is knowledge-sound
- KZG is binding under the SDH (Strong Diffie-Hellman) assumption
- Pedersen commitments are binding under DL on Grumpkin
- Random-oracle model (Fiat-Shamir)

### 4.2 Lemma 4.1 — RoK from HASH to HAC (Construction 1)

Knowledge-sound under collision resistance of Poseidon and Keccak in ROM, with negligible knowledge error.

### 4.3 Lemma 4.2 — IVC Construction (Construction 2)

Modified Nova IVC scheme is knowledge-sound and provides incremental verifiability with the modifications described.

### 4.4 Lemma 5.1 — Spartan's NARK (referenced)

For instances in CRR1CS, MicroSpartan inherits Spartan's NARK soundness with the substitutions:
- HyperKZG instead of Hyrax/Dory for multilinear polynomial commitment
- Sum-check over the boolean hypercube
- Univariate KZG opening for final extraction

---

## 5. Concrete Performance (from §VII Evaluation)

### 5.1 Proof Sizes and Verifier Costs

| Metric | Value |
|---|---|
| Compressed proof size | O(log N) group elements (BN254) |
| Native verifier time | ≈14 ms |
| **On-chain Solidity verifier** | **≈ 2.2M gas** until N ≈ 2²¹ |
| Logarithmic scaling | +32K gas per doubling of N beyond 2²¹ |
| Verification group operations | O(log N) MSMs + 2 pairings |

### 5.2 Prover Costs

| Metric | Value |
|---|---|
| Folding step cost (P) | Linear in step circuit size, dominated by MSMs |
| Compression cost | Tens of seconds, dominated by an additional ≈1.7M-constraint R1CS proving the polynomial evaluation over Grumpkin |
| Compression ≪ chain length | Cost amortized across many IVC steps before posting |

### 5.3 Implementation Stats

- Rust prover: ≈11,000 LoC, modular library
- Solidity verifier: ≈3,300 LoC
- Curves: BN254 (pairing-friendly) + Grumpkin (non-pairing-friendly), half-pairing cycle
- In-circuit hash: Poseidon
- On-chain hash: Keccak
- Universal setup: any existing KZG ceremony (Powers-of-Tau-compatible)

### 5.4 Comparison Context (PVTHFHE-relevant)

Per `paper/figures/p3-bench.tex` in this repo, MicroNova compressed-on-EVM is benchmarked at 2.2M gas — significantly less than Halo2-KZG and on par with hand-tuned Groth16/PlonK/UltraHonk for similar circuit sizes. PVTHFHE's `P3` benchmark target is below that.

---

## 6. Compatibility with PVTHFHE Target Architecture

### 6.1 PVTHFHE's Intended Use

Per `ARCHITECTURE.md` line 22 and `SECURITY.md` line 34, MicroNova sits **between Cyclo (P2) and the on-chain UltraHonk verifier (P3)**:

```
Cyclo accumulator (lattice, R1CS over Fq, Module-SIS)
   │
   ▼  ?? "MicroNova-lattice encoding" ??
   │
MicroNova IVC compression (R1CS over BN254 scalar field)
   │
   ▼  (KZG + pairing)
On-chain Solidity verifier (≈2.2M gas)
```

### 6.2 The Encoding Gap (P3 OPEN PROBLEM)

The arrow labeled "??" is the **MicroNova-lattice encoding** problem identified in `SECURITY.md` line 34:

> "P3 (MEDIUM): MicroNova-lattice Encoding. The encoding efficiency of lattice relations into MicroNova-compatible structures is an active area of research."

Concretely, the gap is:
- **Cyclo's accumulator** is a tuple `(commitment c ∈ R_q^a', auxiliary fields, public IO, slack)` over a lattice Module-SIS commitment with q ≈ 2⁵⁰ in a cyclotomic ring R_{q,φ=128 or 256}.
- **MicroNova consumes** R1CS over the BN254 scalar field F_p where p ≈ 2²⁵⁴.
- An R1CS expressing the predicate "this Cyclo accumulator is well-formed" requires:
  1. Emulating R_q arithmetic (φ-degree polynomial multiplication mod q ≈ 2⁵⁰) inside F_p — feasible but constraint-heavy
  2. Verifying Ajtai commitment opening (a' = 13 hashes at φ = 128 dimensions) — moderate cost
  3. Verifying norm bounds (β ≤ some budget) — range checks via bit-decomposition (cheapest with Cyclo's L=1 sequential folding pattern)
  4. Verifying sum-check transcripts (the proof itself, ≈30–60 KB of F_{q^e} elements) — moderate cost

**Estimated R1CS constraint count** for one Cyclo accumulator verifier: 2²⁰ to 2²² constraints (rough order of magnitude — needs precise costing in L4).

This puts the Cyclo→MicroNova bridge well within MicroNova's 2.2M-gas plateau (which holds up to N = 2²¹).

### 6.3 Risks and Open Questions

| Risk | Severity | Notes |
|---|---|---|
| **Encoding constraint count** | MED | Likely fits in 2²¹ R1CS, but needs concrete circuit-design L4 task |
| **Trusted setup acceptability** | LOW | Universal KZG (Powers-of-Tau) widely accepted; PVTHFHE already assumes this for Phase 3 UltraHonk anyway |
| **Hash-function mismatch** | LOW | MicroNova's Construction 1 already solves this via the Poseidon↔Keccak RoK |
| **Half-pairing cycle dependency** | LOW | BN254/Grumpkin is well-understood; Solidity precompile support is stable |
| **PQ-security loss** | MED | MicroNova breaks lattice-only PQ guarantees of Cyclo. PVTHFHE's threat model already accepts this for the on-chain layer (per SECURITY.md). |
| **No off-the-shelf Cyclo→MicroNova adapter** | HIGH | Must be designed from scratch; an estimated ≈1k–5k Rust LoC + Noir circuit |

### 6.4 Compatibility with the Frozen 7 Public Inputs

PVTHFHE's frozen public-input tuple is `(ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, D_commitment)` per `.sisyphus/design/proof-boundary.md`. MicroNova allows arbitrary public inputs `(x, y)` to the IVC chain, which is more than sufficient. The 7-tuple is bound at compression time as the IVC's final output `y`.

### 6.5 Compatibility with UltraHonk on-Chain Path

There is a strategic question: **MicroNova's own Solidity verifier (≈2.2M gas) directly competes with the UltraHonk path described in `ARCHITECTURE.md`**. Two design options:

- **Option A (Direct)**: Use MicroNova's own Solidity verifier as the on-chain endpoint, replacing UltraHonk. Saves the UltraHonk wrapper layer entirely. Forces dependency on Microsoft's Solidity verifier code (3,300 LoC) but it is open-source.
- **Option B (Wrapped)**: Wrap MicroNova's compressed proof inside a Noir circuit that re-verifies it, then prove that circuit with UltraHonk and verify on-chain via BB-generated UltraHonk verifier. Adds one more recursion layer (cost: ~2× verifier circuit), but keeps the codebase consistent with the existing P3 surrogate ABI (`IPvthfheVerifier.sol`).

**Decision deferred to L4** (joint spec).

---

## 7. Implementation Pointers

### 7.1 Reference Implementation

A modular open-source library exists. The paper states:
> "We implement MicroNova as a modular library in about 11,000 lines of Rust. We also implement MicroNova's verifier in about 3,300 lines of Solidity."

Microsoft Research has historically open-sourced their folding-scheme work (Spartan, Nova). Specific repo URL is not in the PDF excerpt; needs follow-up search (likely under `microsoft/MicroNova` or a successor to `microsoft/Nova`).

### 7.2 Cycle Choice

- **Recommended**: BN254 / Grumpkin (used in paper).
- **Alternatives**: Pluto / Eris ("half-pairing" cycle) — paper notes this is generic and the codebase supports swapping.
- **PVTHFHE alignment**: BN254 matches the curve already used by UltraHonk + Solidity precompile path; minimal integration friction.

### 7.3 Solidity Verifier

- 3,300 LoC, gas-optimized
- Uses BN254 EVM precompiles (ec_add, ec_mul, ec_pairing) — gas-stable on Ethereum mainnet
- Verifies O(log N) group operations + 2 pairings + O(log N) Keccak hashes

### 7.4 What Must Be Built for PVTHFHE (Beyond Adopting MicroNova)

| Component | New code estimate |
|---|---|
| Cyclo → R1CS circuit generator (Rust) | ~3000–5000 LoC |
| R1CS → MicroNova step function adapter | ~500 LoC |
| End-to-end test harness | ~1000 LoC |
| Solidity ABI shim to match `IPvthfheVerifier.sol` | ~200 LoC |

---

## 8. Risk Register for PVTHFHE Integration

| Risk | Severity | Mitigation |
|---|---|---|
| Cyclo→R1CS encoding cost | HIGH | Concrete circuit costing in L4; iterate parameters |
| MicroNova verifier ABI mismatch | LOW | Solidity adapter pattern |
| Trusted setup (KZG) | LOW | Re-use Powers-of-Tau; documented in SECURITY.md |
| PQ-security loss on Layer 3 | KNOWN/ACCEPTED | Already declared in SECURITY.md |
| Microsoft library maintenance | MED | Vendor key crypto code; pin version |
| Bib reference is wrong (2024/1826 vs 2024/2099) | LOW | Fix in T44 reproducibility task |

---

## 9. Key Open Questions for Implementation

1. **Concrete R1CS constraint count** for one Cyclo accumulator verification step? (Depends on Cyclo parameters from `cyclo-digest.md` §6.5; likely 2²⁰–2²².)
2. **Direct vs wrapped** (§6.5 Option A vs B) — does PVTHFHE retain UltraHonk on-chain or switch to MicroNova's Solidity verifier?
3. **MicroNova source repo URL** and license — need to confirm Apache-2.0 or MIT before vendoring.
4. **KZG ceremony** — which Powers-of-Tau tap (Ethereum, Aztec, or fresh)?
5. **Step function granularity** — fold one Cyclo proof per step, or batch?
6. **Recursion depth** — for n=1024 parties with sequential T=10 Cyclo folds, how many MicroNova IVC steps? (Likely 1: fold all Cyclo output into a single MicroNova step.)

---

## References

- Zhao, Setty, Cui, Zaverucha — MicroNova (ePrint 2024/2099, S&P 2025)
- Kothapalli, Setty, Tzialla — Nova (CRYPTO 2022)
- Setty — Spartan (CRYPTO 2020)
- Kate, Zaverucha, Goldberg — KZG (ASIACRYPT 2010)
- Bowe, Grigg, Hopwood — Halo (Pasta cycle), Halo2 (Pluto/Eris)
- Kothapalli, Setty — CycleFold (2023)

---

*Digest compiled: 2026-05-04*
*Source: full PDF text extraction of ePrint 2024/2099 via pdftotext (1486 lines), plus IACR/Microsoft web sources*
*Note: paper/bib.bib reference 2024/1826 is INCORRECT and must be updated to 2024/2099 in a future task (T44 reproducibility).* 
