# Literature Refresh #2 — PVTHFHE Phase 2 Close
Date: 2026-05-02
Scope: Papers since T14 refresh (2026-05-02) relevant to PVTHFHE Architecture B

## New Papers

### [ePrint 2025/409] Threshold FHE with Known-Covariance MLWE
**Authors**: Kim, Polyakov, Zucca et al. (September 2025)
**Relevance**: Threshold BFV/CKKS; knLWE follow-ups; smudging
**Summary**: Solves the open question from Passelègue-Stehlé (PS25/2024/1984) of extending knLWE-based ThFHE to the MLWE/RLWE setting. Introduces two techniques: (1) a simple masking approach for knLWE + Shamir secret sharing, and (2) "noise padding" — adding small noise ζ to prevent leakage of ∥s∥, enabling security from standard LWE/MLWE.
**Blocker**: NON-BLOCKING: The noise-padding technique confirms our RLWE-based ThFHE approach is viable but introduces an additional small noise term ζ whose distribution must be carefully calibrated. For our design, this means verifying that the noise padding ζ does not significantly reduce our already comfortable noise budget (>108 bits remaining at t=512). The Shamir-sharing variant is also relevant if we want O(1) share sizes instead of additive sharing.

### [ePrint 2025/712] Threshold FHE with Efficient Asynchronous Decryption
**Authors**: Zvika Brakerski, Offir Friedman, Avichai Marmor, Dolev Mutzari, Yuval Spiizer, Ni Trieu (dWallet Labs, April 2025)
**Relevance**: Threshold BFV; asynchronous networks; ZKP preprocessing
**Summary**: BGV-based ThFHE achieving O(N) ciphertext modulus growth (vs. O(N²) in prior work). For N=360, achieves 593 bits increase vs 5086 bits in [BGG+18]. Introduces offline ZKP preprocessing to batch proof generation before ciphertext is known. Also shows O(1) overhead when relying on non-PQ assumptions (Tiresias-based Paillier).
**Blocker**: NON-BLOCKING: Our threshold decryption operates under synchronous network assumptions (per protocol spec), so the asynchronous contribution is not directly applicable. However, the offline ZKP preprocessing technique could reduce our proving latency. The O(N) ciphertext modulus growth result is relevant if we ever transition to larger threshold sizes.

### [ePrint 2025/1618] Tighter IND-CPA-D Security via HintLWE for CKKS/BFV
**Authors**: Anonymous (November 2025)
**Relevance**: Noise flooding; IND-CPA-D attacks; smudging bounds; CKKS
**Summary**: Analyzes IND-CPA-D security of CKKS with noise flooding using two approaches: (1) game-hopping via KL divergence giving constant-factor improvement over prior noise-flooding bounds, and (2) HintLWE-based reduction showing that rescale-induced noise can be flooded with as little as 2 additional bits of precision loss. Uses the HintLWE problem [KLSS23] for tighter reductions on rescaled ciphertexts.
**Blocker**: NON-BLOCKING: Our design uses σ_smudge = 2^40 · σ_err which far exceeds the requirements identified here. However, the HintLWE approach confirms that for CKKS-like schemes, the flooding noise can be tighter than the conservative statistical-distance bounds we use. For BFV (our scheme), the game-hopping approach gives a constant-factor improvement but does not change the fundamental smudging requirement.

### [ePrint 2025/2288] Automated CPA-D Security for BFV with Smudging
**Authors**: Anonymous (December 2025)
**Relevance**: Noise flooding; smudging; BFV; automated parameter selection
**Summary**: Proposes an automated methodology for achieving CPA-D security for BFV. Combines alternate average-case/worst-case noise variance monitoring with smudging noise of appropriately large variance. Monitors ciphertext noise dependencies during homomorphic calculations and smudges correlated ciphertexts before computation to reset noise dependencies. Supports relaxed correctness (decryption may fail with bounded probability).
**Blocker**: NON-BLOCKING: Our threshold BFV scheme already uses worst-case noise estimation (per spec). This work's automated monitoring approach could refine our noise budget calculations but does not change the fundamental design. The relaxed-correctness model (BMP_ct = L·B·(2nL+1)) confirms our smudging noise calculation is in the right ballpark.

### [ePrint 2025/899] Improved BFV Ciphertext Multiplication Noise Bound
**Authors**: Anonymous (May 2025)
**Relevance**: BFV noise analysis; ciphertext multiplication
**Summary**: Improves noise bound in Fan's scheme by swapping the distribution space for secret key and error (secret from χ_err, error from R² with max norm reduced from B_err to 1). Re-applies this to Kim et al.'s BFV multiplication to derive a tighter noise bound, delaying bootstrapping. Claims >128-bit security.
**Blocker**: NON-BLOCKING: The noise bound improvement (~factor of 2 in noise growth) is a concrete optimization that could save ~1 bit of ciphertext modulus. Not significant enough to change our N=8192 parameter choice, but worth incorporating into T20 parameter tuning.

### [ePrint 2025/972] Generalized BGV, BFV, CKKS over Matrix Rings
**Authors**: Anonymous (May 2025)
**Relevance**: BFV/BGV generalization; noise analysis; module rings
**Summary**: Generalizes BGV, BFV, CKKS to operate over noncommutative matrix rings instead of polynomial rings. Shows that Ring-LWE, Module-LWE, and LWE are equally efficient for different matrix sizes. Key finding: per-multiplication noise growth is identical when keeping effective lattice dimension constant. Introduces ring expansion factor δ for matrix rings.
**Blocker**: NON-BLOCKING: While interesting theoretically, matrix-ring BFV requires significant implementation changes and has no current performance advantage over standard RLWE BFV. Not a near-term consideration for our protocol.

### [ePrint 2025/901] Generic Framework for Practical Lattice-Based Non-interactive PVSS
**Authors**: Behzad Abdolmaleki, John Clark, Mohammad Foroutani, Shahram Khazaei, Sajjad Nasirzadeh (May 2025)
**Relevance**: Lattice PVSS; vector commitments; proof of smallness
**Summary**: First practical fully lattice-based non-interactive PVSS scheme under standard lattice assumptions. Generic framework transforming vector commitments + linear encryption schemes into PVSS protocols. Key technique: proof of smallness to ensure encrypted shares are verifiable and privacy-preserving. Two tailored lattice-based encryption schemes with efficient ZK proofs of decryption correctness.
**Blocker**: NON-BLOCKING: Provides an alternative PVSS construction framework. Our Architecture B uses a different PVSS approach (based on RLWE encryption with NIZK well-formedness proofs), but this work's "proof of smallness" techniques could potentially reduce our NIZK overhead for share verification.

### [ePrint 2025/2057] Efficient DKG for Threshold-CKKS with Sparse Keys
**Authors**: Anonymous (October 2025)
**Relevance**: Threshold FHE; DKG; sparse secret keys; bootstrapping
**Summary**: Novel Distributed Key Generation protocol for threshold-CKKS that produces sparse ternary secret keys (required for efficient CKKS bootstrapping). Goes beyond existing DKG [MTPBH21] which produces dense keys. Key technique: runs existing DKG algorithm producing large keys, then applies a sparse-key extraction step. Addresses the gap where no prior DKG produced sparse keys without a trusted dealer.
**Blocker**: NON-BLOCKING: Our Architecture B uses BFV, not CKKS, and deferred bootstrapping (P1 decision). However, the sparse-key DKG techniques are relevant if we ever revisit bootstrapping in Phase 3+. The core technique of sparse-key extraction from dense DKG output could be adapted.

### [ePrint 2026/242] Neo and SuperNeo: Post-quantum Folding with Pay-per-Bit Costs
**Authors**: Wilson Nguyen, Srinath Setty (Stanford/NYU/Microsoft, February 2026)
**Relevance**: Lattice folding; Neo/LatticeFold comparison; small-field support
**Summary**: First folding scheme achieving all six properties: post-quantum security, pay-per-bit commitment costs, field-native arithmetic, general constraint systems, small-field support, low recursion overhead. Neo satisfies 5/6 (requires SIMD); SuperNeo satisfies all 6. Single sum-check invocation over small field extension. New norm-preserving embeddings of field vectors into ring vectors. Interactive reductions framework for modular security proofs.
**Blocker**: NON-BLOCKING: Neo/SuperNeo improve on LatticeFold+ in several dimensions (pay-per-bit costs, small-field support) but our Architecture B already uses LatticeFold+ with its specific advantages for RLWE. The "interactive reductions" framework is relevant for P1 (lattice NIZK well-formedness) and could provide a more modular security proof methodology.

### [ePrint 2026/575] RoKoko: Lattice-based Succinct Arguments, a Committed Refinement
**Authors**: Michael Klooss, Russell W. F. Lai, Ngoc Khanh Nguyen, Michał Osadnik, Lorenzo Tucci (March 2026)
**Relevance**: Lattice folding; succinct arguments; sumcheck; well-formedness
**Summary**: Improves RoK and Roll (ASIACRYPT 2025) by Θ(log λ) factor. Linear-time prover with polylog communication/verifier. ~200KB proofs, 100× faster verification than Greyhound. Key innovations: (1) committed folding — prover commits to cross-terms instead of sending in clear, (2) recursive commitments extending LaBRADOR's double-commitment, (3) sumcheck-driven structured recursion proving random projection correctness, inner-product claims, and well-formedness of recursive commitments.
**Blocker**: NON-BLOCKING: The "well-formedness of recursive commitments" proof technique is directly relevant to our open problem P1 (lattice NIZK well-formedness soundness). RoKoko's approach of expressing well-formedness as sumcheck relations could inform our NIZK construction. The committed folding technique could reduce our accumulator size.

### [ePrint 2026/721] Improving LatticeFold+ with ℓ2-norm Checks
**Authors**: Michał Osadnik (Aalto University, April 2026)
**Relevance**: Lattice folding; LatticeFold+ improvement; ℓ2-norm
**Summary**: Final ℓ2-norm-check design combining random-projection constraints (Rok and Roll) with exact shortening (SALSAA) to recover original witness ℓ2-norm bound at extraction time. Reduces prover cost on the dominant norm-check path while maintaining proof size and verification cost. Modular and applicable to other lattice-based folding schemes.
**Blocker**: NON-BLOCKING: This is a concrete improvement to LatticeFold+ that could reduce our folding prover overhead. Worth incorporating into the folding layer design but does not change the fundamental Architecture B approach. The ℓ2-norm approach trades off between ℓ∞ (current LatticeFold+) and ℓ2, and our choice should depend on concrete benchmarking.

### [ePrint 2026/233] FHE for SIMD ALUs with Amortized O(1) Bootstrapping
**Authors**: Mingyu Gao, Hongren Zheng (Tsinghua, February 2026)
**Relevance**: CKKS; bootstrapping; SIMD; encoding
**Summary**: Amortizes O(n) bootstrapping iterations across O(n) ciphertexts for SIMD scenarios using triangle encoding. Each iteration on a combined ciphertext processes multiple ciphertexts, achieving amortized constant cost per ciphertext. Supports leveled arithmetic with only two CKKS bootstrapping operations. 3×–3.8× higher throughput than CPL, 15×–491× higher than REFHE.
**Blocker**: NON-BLOCKING: Our design defers bootstrapping (Phase 1 decision), so this is not directly relevant. However, the triangle encoding technique is interesting for future CKKS-based extensions.

### [ePrint 2026/367] High-Precision Functional Bootstrapping for CKKS from Fourier Extension
**Authors**: Song Bian, Yunhao Fu, Ruiyu Shen, Haowen Pan, Anyu Wang, Zhenyu Guan (Beihang, February 2026)
**Relevance**: CKKS; bootstrapping precision; Fourier extension
**Summary**: New functional bootstrapping framework for CKKS using Fourier extension. Achieves degree-n Fourier series with errors of O(n^{-κ-2}) for smoothness class C^κ functions (improving on previous O(n^{-1})). 10–27 bits improvement in data precision, 1.1–2× latency reduction. Published as minor revision at EUROCRYPT 2026.
**Blocker**: NON-BLOCKING: CKKS-specific and deferred bootstrapping means not directly applicable. The Fourier extension technique could inform future CKKS bootstrapping if we revisit this direction.

### [ePrint 2026/732] Faster Logical Operations from Discrete CKKS
**Authors**: Jaehyung Kim (Stanford, April 2026)
**Relevance**: CKKS; logical operations; GBFV
**Summary**: Efficient non-arithmetic operations in (G)BFV with arbitrary plaintext modulus via scheme conversions between (G)BFV and Discrete CKKS. Asymptotically faster logical operations: O(log p · log log p) for BFV, O(log log p) for GBFV comparisons.
**Blocker**: NON-BLOCKING: Logical operations optimization not relevant to our threshold decryption protocol. GBFV is mentioned as a research direction but not part of our current architecture.

### [ePrint 2026/021] IND-CCA Lattice Threshold KEM under 30 KiB
**Authors**: Katharina Boudgoust, Oleksandra Lapiha, Rafaël del Pino, Thomas Prest (January 2026)
**Relevance**: Lattice threshold KEM; PVSS-adjacent; small ciphertexts
**Summary**: Lattice-based IND-CCA threshold KEM with ~30 KiB ciphertexts for T=32, Q=2^45 queries, 128-bit security. Improves on Lapiha-Prest (Asiacrypt'25) 540 KiB result by 18×. Uses NTRU trapdoors instead of module-NTRU, approximate computations, and verifiable key-extraction shares. Presented at PKC 2026.
**Blocker**: NON-BLOCKING: Threshold KEM is related to but distinct from threshold FHE/PVSS. The verifiable key-extraction shares technique is interesting for our DKG layer but not a direct threat or enhancement.

### [ePrint 2026/813] Practical Post-Quantum Secure PVSS and Applications
**Authors**: Aniket Kate, Pratyay Mukherjee, Hamza Saleem, Pratik Sarkar, Rohit Sinha (Mysten Labs/Purdue, April 2026)
**Relevance**: PVSS; lattice IBE; practical PVSS (already in T14, confirmed)
**Summary**: Lattice-IBE-based PVSS achieving 2 orders of magnitude improvement over Gentry et al. [Eurocrypt 2022]. 692ms for 1024 receivers, 128ms verification, 4MB communication. Introduces "long-lasting security" model (post-quantum privacy with pre-quantum authentication via Pedersen commitments).
**Blocker**: NON-BLOCKING: Already listed in T14. Confirmed as a practical PVSS alternative but our Architecture B uses a different PVSS construction (RLWE-based with NIZK well-formedness proofs).

### [ePrint 2026/772] Lattice-based Ring Verifiable Random Functions
**Authors**: Jie Xu, Muhammed F. Esgin, Ron Steinfeld (Monash, April 2026)
**Relevance**: Ring VRFs; lattice-based anonymity; one-out-of-many proofs
**Summary**: Modular compiler transforming provable VRFs into RVRFs via one-out-of-many proofs. Instantiations from LaV and LB-VRF lattice VRFs. New security notion T-uniqueness. Detailed parameter analysis across ring sizes.
**Blocker**: NON-BLOCKING: Ring VRFs are interesting for PVSS anonymity layers but not directly relevant to our current protocol design. Could inform future enhancements for dealer anonymity.

### [ePrint 2026/614] Attacks on Sparse LWE and Sparse LPN with New Sample-Time Tradeoffs
**Authors**: Shashwat Agrawal, Amitabha Bagchi, Rajendra Kumar (IIT Delhi, March 2026)
**Relevance**: Sparse LWE attacks; Kikuchi method; lattice security
**Summary**: Extends Kikuchi method to sparse LWE/LPN for higher moduli q. Two attacks: (1) spectral norm of Kikuchi graph adjacency matrix, (2) closed walks with edge label polynomials. New tradeoffs between sample complexity and time complexity.
**Blocker**: NON-BLOCKING: Our scheme uses dense RLWE (not sparse), so these sparse-LWE attacks do not apply. Relevant for any future sparse-key extensions but not a current threat.

### [ePrint 2026/650] A Search-to-Decision Reduction for Continuous LWE
**Authors**: Kirpa Prince (Mahidol, April 2026)
**Relevance**: CLWE; search-to-decision; lattice foundations
**Summary**: First search-to-decision reduction for general continuous LWE (CLWE). Approximates secret vector to within small error using decision oracle. Improves on prior CLWE-to-LWE reduction which was only for discrete-CLWE.
**Blocker**: NON-BLOCKING: Theoretical result improving our understanding of CLWE hardness. Not a threat to our standard RLWE-based construction.

## Impact Assessment

### Overall: No design-breaking papers found
None of the papers discovered since T14 (2026-05-02) constitute a BLOCKING finding that would require changes to our Architecture B design. The lattice folding landscape continues to improve (Cyclo, Neo/SuperNeo, RoKoko, LatticeFold+ ℓ2-norm improvements) but all represent incremental enhancements rather than fundamental breaks.

### Positive trends (NON-BLOCKING improvements):
1. **Noise flooding analysis** (2025/1618, 2025/2288): Tighter bounds confirm our smudging noise σ_smudge = 2^40 · σ_err is conservative and safe. The HintLWE approach could inform future optimization.
2. **Lattice folding improvements** (2026/575, 2026/721, 2026/242): RoKoko's well-formedness-as-sumcheck technique and LatticeFold+ ℓ2-norm improvements are both worth incorporating into the folding layer.
3. **PS25 resolution** (2025/409): The open question of knLWE → MLWE extension has been solved via noise padding, confirming our RLWE-based ThFHE approach is sound.
4. **Lattice NIZK progress** (2026/575, 2025/313): RoKoko and Zhang et al. provide relevant techniques for our open problem P1 (lattice NIZK well-formedness soundness).

### Open problems status:
- **P1 (lattice NIZK well-formedness soundness)**: Still open. RoKoko's approach of expressing well-formedness as sumcheck relations is a promising direction to investigate.
- **P2 (LatticeFold+ over RLWE)**: Still open. Neo/SuperNeo's norm-preserving embeddings are relevant but don't directly address RLWE folding.

## Action Items

1. **[P1 research]** Investigate RoKoko's (2026/575) approach of proving well-formedness via sumcheck relations for potential adaptation to our RLWE NIZK layer.
2. **[Folding optimization]** Evaluate LatticeFold+ ℓ2-norm checks (2026/721) for potential integration — could reduce prover overhead.
3. **[Parameter tuning]** Incorporate BFV multiplication noise improvements (2025/899) into T20 parameter selection — may save ~1 bit of ciphertext modulus.
4. **[Smudging review]** Monitor HintLWE-based noise flooding bounds (2025/1618) — may enable tighter smudging parameters in future iterations.
5. **[Security proof]** Consider Neo/SuperNeo's (2026/242) "interactive reductions" framework for modular security proofs of composed lattice-based protocols.

## Papers Already Covered by T14 (Confirmed Still Relevant)
- Cyclo (2026/359) — lattice folding O(1) norm growth ✓
- Hermine (2026/419) — everywhere-short secret sharing ✓
- Zyskind et al. (2025/1781) — noise-flooding-free decryption ✓
- Ajax (2025/1834) — mask-then-open noise removal ✓
- Practical PQ PVSS (2026/813) — lattice IBE-based PVSS ✓
- PS25 / knLWE (2024/1984) — smudging caveats ✓
- ℓ-BFV (2024/1285) — linear-RLK BFV baseline ✓

## Search Methodology
- eprint.iacr.org keyword search across all 9 topic areas
- Cross-referenced with T14 paper list to avoid duplicates
- Verified publication dates against T14 timestamp (2026-05-02)
- Papers evaluated against PVTHFHE Architecture B components:
  - Lattice PVSS
  - LatticeFold+ folding accumulator
  - MicroNova on-chain compression
  - UltraHonk verification
  - Noise flooding / smudging
  - BFV/BGV/CKKS noise analysis
  - Lattice NIZK well-formedness (P1)
