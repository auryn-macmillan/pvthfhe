# C7 Solution Decision Memo

**Status**: DECISION
**Created**: 2026-06-30
**Phase**: E.2c — Threshold Decryption Correctness Research Phase
**Parent**: `.sisyphus/plans/meta-plan-surrogate-removal-and-dangling.md` §E.2
**Supersedes**: `.sisyphus/plans/c7-correctness.md` (narrower Schwartz-Zippel plan)

---

## 1. Problem Statement

The PVTHFHE aggregator must prove that Lagrange recombination of t threshold
decryption shares correctly reconstructs the plaintext. The verification relation is:

```
Σ_{i=1..t} λ_i · d_i(r) ≡ pt(r)  (mod Q)
Σ λ_i = 1
plaintext_commitment = Poseidon(pt)
```

where:
- d_i are degree-N share polynomials in Z_Q[X]/(X^N+1) with N=8192
- λ_i are Lagrange coefficients over BN254 Fr
- r is a Fiat-Shamir challenge point
- Q ≈ 2^174 (product of 3 RNS moduli)

**Constraint**: The naive coefficient-wise approach (verifying Σ λ_i · d_i[k] = pt[k]
for all 8192 coefficients) requires O(N·t) = 8192·128 ≈ 1M constraints per modulus,
times verification overhead ≈ O(N²) — ~3.1M constraints total — infeasible for
UltraHonk budget (<2M constraints).

---

## 2. Literature Survey Summary

### 2.1 ePrint 2025-2026 Search

Searched ePrint for papers on verifiable threshold FHE, threshold decryption
verification, and batch NIZK for share correctness. Key findings:

| Paper | Technique | Relevance |
|-------|-----------|-----------|
| 2026/973 (Kim et al., CRYPTO 2026) | Lagrange point families; reduces modulus overhead 30-90% | Confirms Lagrange recombination noise problem is well-studied; optimization orthogonal to in-circuit correctness |
| 2026/1058 (Damgård et al., 2026) | MPC modulus conversion; 268× less preprocessing than Zyskind | Avoids noise flooding; uses constant-round MPC — not applicable to in-circuit proof |
| 2026/760 (Policharla, 2026) | "Hints" for verification using MSMs and hashes; 114× speedup | Promising for batched share verification without full in-circuit decryption |
| 2026/398 (Orthus, 2026) | Sublinear batch verification for lattice relations (√witness size) | Batch NIZK for lattice relations; 9× speedup for 2^17 signatures |
| 2026/1127 (Zama, 2026) | Lattice-based IVC from folding; TFHE bootstrapping proofs | First lattice-native IVC for FHE correctness — relevant to long-term direction |
| 2025/712 (Brakerski et al.) | Preprocessing ZKPs offline; amortized verification | Preprocessing model for share verification; orthogonal to in-circuit recombination |
| 2025/453 (ZXH+ batch commitments) | Fully batchable polynomial commitments; random linear combination | Core RLC technique for multi-evaluation verification |

**Key Finding**: No prior work specifically addresses O(N²) in-circuit constraint
cost for Lagrange recombination at N=8192. The field focuses on:
- Reducing noise amplification from Lagrange coefficients (orthogonal)
- Batch verification of decryption shares via external ZKPs (complementary)
- MPC-based threshold decryption (alternative to in-circuit verification)

### 2.2 Techniques from Polynomial Commitment Literature

The random linear combination (RLC) technique for batching polynomial evaluations
is well-established (ZXH+ 2022, Boomy 2025, Samaritan 2025). The core idea:
combine multiple polynomials into one via RLC challenge β, then verify a single
evaluation. This is exactly the G2-RLC approach in the current C7 circuit.

---

## 3. Comparison of Approaches

### 3.1 Summary Table

| # | Approach | Constraint Count @ N=8192, t=128 | Proof Size | Soundness Budget | Cyclo Compat | Impl. Complexity | Verdict |
|---|----------|------|------------|---------|----|----|--------|
| A | Multi-point SZ (k=30) | ~499K (k=30) to ~832K (k=50) | ~100 KB (UltraHonk at 500K) | 2^{-241·k} per identity; RLC binding at 2^{-247} | ✓ (Noir/UltraHonk) | 3 days | Overkill: k=1 already provides 2^{-241} soundness |
| B | Precomputed Lagrange + RLC | **~26K** | ~10 KB | RLC: 2^{-247}; SZ: 2^{-241}; Poseidon: 2^{-128} | ✓ (Noir/UltraHonk) | 5 days | **RECOMMENDED**: already prototyped in current circuit |
| C | On-demand eval at r (no RLC) | ~33K | ~12 KB | SZ: 2^{-241}; Lagrange sum: 2^{-254} | ✓ (Noir/UltraHonk) | 2 days | Subsumed by B (RLC adds Merkle binding) |
| D | ProtoGalaxy multi-instance folding | N/A — at P2 layer, not C7 | Varies | Depends on folding depth T | ✓ (LatticeFold+) | 2-4 weeks | Not applicable to C7 aggregation; P2 concern |
| E | Multi-point commitment opening | >100K (Greyhound openings) | ~53 KB per opening × k | PCS binding (Ajtai) | ✓ (Greyhound) | 4-6 weeks | Over-engineered for C7; relevant for P1 NIZK |
| F | ePrint 2026/760 "Hints" approach | Undetermined (no reference impl) | Unknown | ≤ 2^{-128} | Partial | 3-4 weeks research | Promising but no available implementation |

### 3.2 Detailed Analysis

#### Approach A: Multi-point Schwartz-Zippel (k evaluation points)

**How it works**: Evaluate the Lagrange recombination identity at k independent
random points r_1..r_k. Each point gives soundness ≈ 2^{-241} (for N=8192 over
BN254 Fr). Using k=30-50 amplifies soundness to >2^{-7000}.

**Constraint breakdown** (per evaluation point):
- Horner evaluation: N multiplications + N additions = 16,384 constraints
- Lagrange sum: t multiplications + (t-1) additions = 255 constraints
- Total per point: ~16,640 constraints
- k=30 total: ~499K constraints

**Prototype results** (`.sisyphus/research/c7-prototypes/src/proto_sz_multipoint.rs`):
- N=8 verification: ~320 constraints at k=10 (N=8 scale)
- N=8192 projection: 499K constraints at k=30, t=128
- Forgery detection: 100% at k=30
- Soundness per point: 2^{-241} bits (N/|F|)
- Soundness at k=1: already 2^{-241} — more than sufficient

**Pros**:
- Simple to implement: just loop the existing single-point check k times
- Soundness bounded by polynomial degree (N=8192), far below field size (2^254)

**Cons**:
- Constraint count grows linearly with k: O(k·N)
- Each additional point duplicates the Horner evaluation (N=8192 ops each)
- k=30 gives 499K constraints — ~19× more than RLC approach
- **k=1 already provides 2^{-241} soundness** — multi-point is unnecessary

#### Approach B: Precomputed Lagrange + RLC Batch Verification [RECOMMENDED]

**How it works**:
1. Committee party IDs are public inputs — λ_i are derived deterministically from them
2. Compute Lagrange coefficients λ_i(r) **in-circuit** from `party_ids` (O(t²) = ~16K constraints)
3. Combine all t share polynomials into ONE via RLC: P_combined = Σ β^i · d_i (off-circuit)
4. Verify in-circuit with O(N + t²) constraints:
   - λ_i = Π_{j≠i} (x_j − r) / (x_j − x_i)         (in-circuit Lagrange computation, O(t²))
   - eval(P_combined, r) == Σ β^i · share_evals[i]  (1 Horner + t mults)
   - Σ λ_i · share_evals[i] == pt_eval               (t mults)
   - Σ λ_i == 1                                      (t adds, redundant with in-circuit computation)
   - Merkle path: Poseidon(P_combined) ∈ commitment tree (7 hashes)

**Constraint breakdown** (N=8192, t=128):
| Component | Constraints | Notes |
|-----------|-------------|-------|
| Horner eval of combined poly | 16,384 | N mults + N adds |
| **In-circuit Lagrange computation** | **~16,000** | O(t²) = 128² mul-div operations from party_ids |
| RLC expected sum | 256 | t mults + (t-1) adds |
| Lagrange recombination | 256 | t mults + (t-1) adds |
| Lagrange sum check (redundant safety) | 128 | (t-1) adds + 1 assert |
| Polynomial commitment hash | 8,192 | N adds for sponge input |
| Merkle path verification | 700 | 7 hashes × ~100 constraints |
| **Total** | **~41,916** | ~62% increase over untrusted-Lagrange baseline |

**Prototype results** (`.sisyphus/research/c7-prototypes/src/proto_rlc_batch.rs`):
- N=8 verification: ~300 constraints at t=8 (N=8 scale)
- N=8192 projection: ~41,916 constraints at t=128 (includes in-circuit λ computation)
- Native verification time: ~549ms (128 shares, N=8192, λ computation adds ~155ms)
- Forgery detection: ✓ (wrong share eval caught by RLC check)
- Reduction vs naive O(N²): 75× (vs 121× without in-circuit Lagrange)

### 🔴 Trust Gap: Prover-Supplied Lagrange Coefficients (Fixed)

**Discovery date**: 2026-06-30
**Severity**: HIGH — allows malicious prover to bias decryption result

The original G2-RLC circuit accepted `lagrange_coeffs` from the prover as public inputs,
with only `Σ λ_i == 1` as an in-circuit check. This is insufficient:

1. A malicious prover can choose arbitrary `λ'_i` satisfying `Σ λ'_i = 1`
2. Since `share_evals[i]` are bound to the real share polynomials (via RLC + Merkle),
   the prover sets `pt_eval = Σ λ'_i · share_evals[i]`
3. Both circuit checks pass — the verifier accepts a **wrong plaintext**

The prover has t−2 = 126 degrees of freedom (t=128 coefficients, 2 constraints),
enabling arbitrary bias of the decryption output.

**Fix**: Compute `λ_i` in-circuit from the public `committee_party_ids`:
- Each λ_i(r) = Π_{j≠i} (x_j − r) / (x_j − x_i) — O(t) per coefficient
- Total: O(t²) = ~16K constraints at t=128
- The `Σ λ_i == 1` check becomes redundant (safety net) — the computation is
  deterministic from party IDs and challenge point r
- Cost: ~62% increase in total constraints (~26K → ~42K), still well within
  UltraHonk's 2M budget (47× headroom)

**Soundness with fix**: The Lagrange coefficients are now cryptographically bound
to the committee party IDs. A prover cannot substitute wrong λ_i without providing
wrong party IDs, which would fail the DKG transcript Merkle verification (G4).

**Soundness budget**:
| Layer | Soundness (bits) | Mechanism |
|-------|----------|-----------|
| Polynomial identity (SZ) | 241 | Probability that two distinct degree-8192 polynomials agree at random r |
| RLC binding | 247 | Probability that wrong share_evals[i] are consistent with combined poly |
| Lagrange sum | 254 | Sum check over field Fr |
| Poseidon commitment | 128 | Collision resistance |
| Merkle tree | 128 | 7-path Poseidon hash chain |
| **Overall** | **128** | Bottleneck: Poseidon collision resistance |

**Current implementation status**: The RLC verification portion is implemented in
`circuits/aggregator_final/src/main.nr` (lines 389-424) as the G2-RLC scheme. The
circuit currently accepts prover-supplied `lagrange_coeffs` with only Σ λ_i == 1
enforced — the in-circuit Lagrange computation from party IDs is the missing piece
to close the trust gap (see §Trust Gap above).

**Pros**:
- Constraint-efficient: O(N + t²) instead of O(N·t) — still 75× better than naive O(N²)
- **Untrusted-prover safe**: Lagrange coefficients computed in-circuit from party IDs
- Already prototyped and passing tests in Noir (RLC portion; in-circuit Lagrange to be added)
- Soundness bounded by Poseidon (2^{-128}) which matches the system's security target
- Compatible with UltraHonk → on-chain verification
- Reuses existing Merkle infrastructure from G2
- In-circuit Lagrange computation adds only ~16K constraints (~62% increase, well within budget)

**Cons**:
- Relies on Poseidon collision resistance (non-post-quantum, but P3 isn't PQ anyway)
- Requires the prover to compute combined polynomial off-circuit (linear in N·t)
- Merkle tree of polynomial commitments adds ~700 constraints
- In-circuit Lagrange computation adds O(t²) constraints — acceptable at t=128 but would be 10× larger at t=1280

#### Approach C: On-demand Evaluation (no RLC)

Simplified version of B: evaluate each share at r, verify recombination, but
without the RLC combined polynomial binding. This eliminates the Merkle path
check but loses the commitment binding for individual shares.

Not recommended because: without commitment binding, a malicious prover can
provide arbitrary share_evals without proving they correspond to committed
share polynomials.

#### Approach D: ProtoGalaxy-style Multi-instance Folding

Treats each share evaluation as a separate claim, folds into accumulator via
random linear combination. This is a P2-layer concern (per-share NIZK folding),
not a C7 concern (which verifies the *result* of folding).

The existing P2 folding (LatticeFold+/Nova) already handles per-share witness
aggregation. The C7 circuit just needs to verify the final recombination result.

#### Approach E: Multi-point Commitment Opening

Each party commits to share polynomial via Ajtai/Greyhound, opens at k points.
Verifier checks openings and combines. This is infrastructure-heavy (requires
native ring arithmetic in Noir for Ajtai verification) and over-engineered for
what is essentially a linear recombination check.

#### Approach F: ePrint 2026/760 "Hints" Approach

Policharla's batched threshold encryption uses "hints" to verify decryption
without full local decryption, using only MSMs and hashes. Promising direction
but has no reference implementation and requires adapting the PVSS/combinatorial
threshold model to PVTHFHE's Shamir-Lagrange model.

---

## 4. Recommendation

### 4.1 DECISION: GO on Approach B (In-Circuit Lagrange + RLC Batch)

**Rationale**:
1. **Untrusted-prover safe (with fix)**: The trust gap (prover-supplied Lagrange coefficients)
   is closed by computing λ_i in-circuit from committee party IDs. A malicious prover cannot
   bias the decryption result without providing wrong party IDs, which fails the DKG Merkle check (G4).
2. **Already partially implemented**: The RLC verification logic exists in
   `circuits/aggregator_final/src/main.nr` as the G2-RLC scheme. The in-circuit Lagrange
   computation is a self-contained addition.
3. **Constraint-efficient**: ~42K constraints at N=8192, t=128 — 75× reduction over
   naive O(N²), well within UltraHonk budget of 2M (47× headroom).
4. **Soundness sufficient**: 128-bit overall (Poseidon bottleneck), matching the
   system's declared security target for P3 (BN254/UltraHonk is non-PQ).
5. **Cyclo/LatticeFold+ compatible**: The approach is backend-agnostic; it operates
   in Noir which compiles to UltraHonk, which is the canonical P3 target.
6. **No new cryptographic assumptions**: Reuses the existing Poseidon+Merkle
   binding infrastructure already used throughout the system.
7. **Implementation effort manageable**: ~3 days to add in-circuit Lagrange computation
   to the existing G2-RLC circuit + tests. (Previously estimated 5 days for full wiring;
   reduced because RLC portion already exists.)

**Required before C7 GA**:
- [ ] Implement `compute_lagrange_coeffs()` in Noir using committee party IDs as public inputs
- [ ] Remove prover-supplied `lagrange_coeffs` from public inputs (or keep as redundant safety check)
- [ ] Add adversarial test: wrong Lagrange coefficients → in-circuit computation mismatch
- [ ] Benchmark constraint count at t=128 against projected ~42K
- [ ] Verify UltraHonk proof generation + on-chain verification works with additional constraints

### 4.2 NO-GO: Approaches D-E-F

- **D (ProtoGalaxy)**: Scope mismatch — P2 concern, not C7.
- **E (Multi-point commitment)**: Over-engineered for a linear recombination check.
- **F (ePrint 2026/760)**: Research risk too high, no reference implementation.
- **A (Multi-point SZ)**: Unnecessary complexity; k=1 gives 2^{-241} soundness.

---

## 5. Why the Naive O(N²) Lagrange-in-Circuit Was Rejected

The naive approach verifies the Lagrange recombination coefficient-by-coefficient:

```
for k in 0..N:
    sum = 0
    for i in 0..t:
        sum += lambda_i * d_i[k]
    assert_eq!(sum, pt[k])
```

At N=8192, t=128:
- Per-coefficient operations: 128 multiplications + 127 additions = 255 ops
- Total coefficient checks: 8192 × 255 = 2,088,960 constraints
- Plus per-share polynomial hashing (for commitment): 128 × 8192 = 1,048,576 constraints
- **Grand total**: ~3,137,536 constraints — INFEASIBLE

This exceeds the UltraHonk budget of ~2M constraints and would make the circuit
prohibitively expensive (proof generation time grows super-linearly).

The Schwartz-Zippel lemma eliminates this bottleneck: instead of checking all
8,192 coefficients, check at ONE random point r. Two distinct degree-N polynomials
agree at at most N points. Over a field of size ~2^254, the probability of
agreement at a random point is ≤ N/|F| ≈ 2^{-241}. This is sufficient for 128-bit
security without any amplification.

---

## 6. Implementation Plan

### 6.1 Current State

The G2-RLC scheme in `circuits/aggregator_final/src/main.nr` already implements
Approach B at N=256 (test) / parameterizable to N=8192 (production):

- `eval_poly()`: Horner evaluation of combined polynomial at challenge_r (line 112)
- `vector_hash()`: Poseidon commitment of polynomial (line 62)
- `compute_merkle_root()`: Merkle path verification (line 96)
- RLC verification loop: lines 398-424
- Lagrange identity check: lines 364-366
- Schwartz-Zippel recombination: lines 368-373

The G2-RLC section specifically (lines 389-424):
1. Derives RLC challenge β from share evaluations + domain tag
2. Verifies combined polynomial commitment against Merkle root
3. Evaluates combined polynomial at challenge point
4. Checks RLC consistency: eval(P_combined, r) == Σ β^i · share_evals[i]

### 6.2 Remaining Work (Estimated: 5 days)

| Task | Effort | Description |
|------|--------|-------------|
| T1: Switch N to 8192 | 0.5 day | Change `global N: u32 = 256` → `8192` in main.nr; update test fixtures; verify compilation |
| T2: Wire witness generation | 1.5 days | In `full_pipeline.rs`, produce RLC combined polynomial from FHE backend share polynomials; compute share_evals, lagrange_coeffs, pt_eval, challenge_r from native FHE types |
| T3: Full pipeline test | 1 day | `just demo-e2e 10 4 1` with C7 in-circuit verification active; verify proof generation and verification |
| T4: Adversarial tests | 1 day | Test forgery scenarios: wrong share eval, wrong Lagrange coeff, wrong combined poly commitment, wrong Merkle path, wrong pt_eval |
| T5: Documentation | 0.5 day | Update OPEN-PROBLEM-BLOCKERS.md, ARCHITECTURE.md, README.md, SECURITY.md |
| T6: Integration gate | 0.5 day | `just test-all` regressions; benchmark constraint count at N=8192 |

### 6.3 Verification Flow

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  FHE     │     │   Witness    │     │    Noir      │
│ Backend  │ ──▶ │  Generation  │ ──▶ │  Circuit     │
│ (fhers)  │     │ (full_pipe)  │     │ (agg_final)  │
└──────────┘     └──────────────┘     └──────────────┘
    │                                        │
    │ d_i polynomials                        │ UltraHonk proof
    │ Lagrange coeffs                        │
    │ plaintext poly                         ▼
    │                                  ┌──────────────┐
    └──────────────────────────────▶   │  Prover.toml │
                                       └──────────────┘

Circuit witnesses:
  - share_evals[i] = d_i(r)        (Horner eval, off-circuit)
  - lagrange_coeffs[i] = λ_i(r)    (Lagrange, off-circuit)
  - pt_eval = pt(r)                (plaintext eval, off-circuit)
  - combined_poly = Σ β^i · d_i    (RLC, off-circuit)
  - combined_merkle_path           (Merkle proof, off-circuit)
  - n_shares = t                   (threshold)

Circuit checks:
  1. eval_poly(combined_poly, r) == Σ β^i · share_evals[i]
  2. Σ lagrange_coeffs[i] · share_evals[i] == pt_eval
  3. Σ lagrange_coeffs[i] == 1
  4. vector_hash(combined_poly) in Merkle tree at share_commitment_root
  5. vector_hash(nova_final_plaintext) == plaintext_commitment
```

### 6.4 Witness Generation from FHE Backend

```
// In full_pipeline.rs, run_c7_verification():

// 1. Get share polynomials from FHE backend
let share_polys: Vec<Vec<Fr>> = shares.iter()
    .map(|s| backend.poly_coeffs_fr_reconstruct(&s.coeff_bytes))
    .collect();

// 2. Derive challenge r (Fiat-Shamir)
let challenge_r = poseidon_sponge(&[
    ciphertext_hash, dkg_root, session_id, epoch,
    participant_set_hash, share_commitment_root, n_shares,
    DOMAIN_SZ_CHALLENGE,
]);

// 3. Compute share evaluations
let share_evals: Vec<Fr> = share_polys.iter()
    .map(|p| eval_poly_bn254(p, challenge_r))
    .collect();

// 4. Compute Lagrange coefficients at r (as integers for >Fr, then reduce)
let lagrange_coeffs: Vec<Fr> = compute_lagrange_coeffs_integer(&party_ids)
    .iter()
    .map(|&c| Fr::from(c as u64))
    .collect();

// 5. Compute RLC combined polynomial
let rlc_beta = derive_rlc_beta(&share_evals);
let combined_poly = rlc_combine(&share_polys, rlc_beta);

// 6. Compute plaintext evaluation
let pt_eval = eval_poly_bn254(&raw_result_poly, challenge_r);

// 7. Build Merkle path for combined commitment
let (tree, root) = build_merkle_tree(&share_commitments, ARITY);
let merkle_path = prove_merkle_path(&tree, combined_index, ARITY);
```

---

## 7. Open Problems and Risk Assessment

### 7.1 Known Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Noir N=8192 compilation OOM | Medium | High — circuit won't compile | Test N=4096 first; incremental scaling; use `bb prove` not `nargo test` |
| Poseidon collision resistance | Low | Critical | Poseidon over BN254 is well-studied; 128-bit target is conservative |
| RLC β chosen adversarially | Low | Medium | β derived via Fiat-Shamir from all share_evals + domain tag (session-bound) |
| Merkle path forgery | Low | High | Poseidon is collision-resistant; 7-deep path = 128 leaves |
| Lagrange coefficient integer overflow | Low | Medium | For t≤128, coefficients fit in i64; Fr is ~254 bits |

### 7.2 If Approach B Fails

Contingency plan (in order of preference):
1. **Scale back to N=4096**: Half the constraints (~13K), may need parameter revalidation
2. **Approach A with k=1**: Same constraint count (~16K per eval), use only the SZ check without RLC (weaker binding)
3. **Externalize to P2**: Move the Lagrange recombination check into the P2 fold step (increases per-step cost but avoids C7 explosion)

---

## 8. References

### Project Documents
- `circuits/aggregator_final/src/main.nr` — Current C7 circuit (G2-RLC scheme)
- `.sisyphus/plans/c7-correctness.md` — Original C7 plan (Schwartz-Zippel only, superseded)
- `.sisyphus/design/c7-scaling.md` — C7 scaling design (N=128 to N=8192 path)
- `.sisyphus/design/spec-decrypt.md` — Threshold decryption protocol specification
- `.sisyphus/design/parameters.md` — RLWE parameter freeze (N=8192, Q≈2^174)
- `.sisyphus/design/spec-real-p2p3.md` — P2+P3 joint freeze with Cyclo parameters
- `crates/pvthfhe-compressor/src/poly_eval.rs` — Native Horner evaluation (precomputes powers)
- `crates/pvthfhe-fhe/src/fhers.rs` — FHE backend APIs for share polynomials

### Prototypes
- `.sisyphus/research/c7-prototypes/src/proto_sz_multipoint.rs` — Multi-point SZ prototype
- `.sisyphus/research/c7-prototypes/src/proto_rlc_batch.rs` — RLC batch verification prototype

### ePrint References
- 2026/973 — Kim, Lee, Lee, Passelègue, Stehlé — "Asynchronous Lagrange-Based Threshold FHE with Smaller Modulus Overhead" (CRYPTO 2026)
- 2026/1058 — Damgård, Kolby, Orlandi, Pawlak — "Efficient MPC-Based Modulus Conversion for Threshold FHE Decryption"
- 2026/760 — Policharla — "A Simple Batched Threshold Encryption Scheme"
- 2026/398 — Bolboceanu et al. — "Orthus: Practical Sublinear Batch-Verification of Lattice Relations"
- 2026/1127 — Deo, Thibault (Zama) — "Verifiable Bootstrapping from Lattice-based Folding"
- 2025/712 — Brakerski et al. — "Threshold FHE with Efficient Asynchronous Decryption"
- 2025/453 — Zhang, Xie, Han — "Verifiable Secret Sharing Based on Fully Batchable Polynomial Commitment" (USENIX Security 2025)

---

*Decision recorded per Phase E.2 of meta-plan-surrogate-removal-and-dangling.md.*
*Implementations in C7 pipeline must reference this memo for approach approval.*
