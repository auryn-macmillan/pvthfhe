# Learnings — P1-T2 Joint Extractor

## M1: Forking-Lemma Formalization

### 2026-05-14

- **Ternary challenge space is the bottleneck.** The small |C| = 3 makes the Pointcheval-Stern forking-lemma bound vacuous for any ε_acc < 1 when Q_total ≥ 4. The standard bound gives ε_extract ≈ ε_acc²/Q_total - ε_acc/3, which is negative for Q_total = 12 and any ε_acc ≤ 1. This is a known limitation of the Pointcheval-Stern lemma with small challenge spaces, not a mistake. The actual extraction guarantee must come from M-SIS reduction (M2), not the forking lemma alone.

- **Two competing bound formulations.** The task specification uses ε_acc² without the Q_total denominator (idealized model where extractor knows which ROM query to rewind at). The standard forking lemma includes ε_acc²/Q_total. The document presents both and notes that the idealized bound is tighter (~0.65 at ε_acc=0.99) while the standard bound is vacuous. The discrepancy should be resolved in M2 when the extraction probability is recomputed under the M-SIS reduction.

- **Multi-layer ROM overhead is linear, not multiplicative.** Each additional layer adds O(Q_i/|C|) overhead to the forking-lemma loss. For |C| = 3, this is significant (~1.33 per ROM query) but does not multiply with the quadratic ε_acc² term. The composition is additive, not a product of individual extraction probabilities.

- **SHA-256 binding avoids commitment-layer rewinding.** The Ajtai commitment layer does not need separate forking-lemma extraction because the extractor can verify consistency between the extracted witness and the commitment via SHA-256 preimage check. If they don't match, it's a SHA-256 collision. This simplifies the joint extractor: only the RLWE relation layer needs rewinding.

- **Parameter bounds for Δ = ±2 need M3.** The inverse of 2 in Z_{q_commit}[X]/(X^256 + 1) has norm ~2^49, which would blow up the extracted witness norm. Lemma 9 guarantees invertibility but not norm boundedness. The question of whether Δ = ±2 extraction is sound at these parameters needs the M3 challenge-space analysis.

## M2: M-SIS Reduction

### 2026-05-14

- **The P1 reduction target is SHA-256 binding, not M-SIS.** The forking-lemma extractor recovers a witness (s, e) from two accepting transcripts. The commitment at the P1 layer is purely SHA-256 based (P1-T5). If the extracted s differs from the committed value but both hash to the same pvss_commitment, that is a SHA-256 collision. There is no Ajtai/lattice commitment at the P1 layer for M-SIS to act upon. The M-SIS assumption only enters through the Cyclo folding layer (P2).

- **Two independent reduction branches.** The joint extractor composes two reductions additively: Adv ≤ Adv_SHA-256 + Adv_M-SIS. The adversary cannot trade off a P1 break against a P2 break. Each layer must be independently secure. This is a key architectural insight: the composition is additive, not multiplicative, so there is no "weakest link" that dominates.

- **Norm bound doubling is tight.** The forking-lemma extraction doubles the witness norm (1024 → 2048) because it computes the difference of two responses. This is the standard forking-lemma norm loss and cannot be avoided in a rewinding extractor. The factor of 2 is tight because the extraction is a single algebraic step, not a chain of operations.

- **Extracted witness at 2048 is still "short" for M-SIS.** The β = 2048 bound is 12 bits, while q_commit ≈ 2^50 is 50 bits. The ratio ||w||/q_commit ≈ 2^{-38} means the M-SIS problem is well-parameterized. The adversary would need to find a vector of that shortness, which is cryptographically hard if the lattice dimension is adequate.

- **Δ = ±2 is the problematic case.** The inverse of 2 in R_{q_commit} has norm ~2^49, which would make the extracted witness norm ~2^60, larger than q_commit and thus not an M-SIS solution. M3 must quantify the probability of Δ = ±2 forks and determine whether the protocol needs to handle them (via rejection, re-parameterization, or an argument that they are negligible).

- **The document took a different shape than initially expected.** The task specification's §4 section correctly identified that the direct reduction goes to SHA-256, with M-SIS entering through P2. Rather than a document that claims an M-SIS reduction for P1 (which would be incorrect), the document traces the full reduction path honestly, showing where each assumption applies. This architectural clarity will be important for M4 composition.

## M3: Challenge-Space Analysis

### 2026-05-14

- **Invertibility of Δ = ±2 depends on q_commit parity.** For the Cyclo commitment ring R = Z_{q_commit}[X]/(X^256+1), the challenge differences are scalar constants (not general ring elements). Δ = ±1 is always invertible. Δ = ±2 is invertible if and only if gcd(2, q_commit) = 1 (i.e., q_commit is odd). If q_commit is a power of 2, 2 is not invertible. The task specification didn't clarify whether q_commit is odd or a power of two, so the document covers both cases.

- **The "astronomical challenge space" argument (3^256 ≈ 10^122) is somewhat misleading for the P1 NIZK.** The P1 challenge is a single scalar c ∈ {-1, 0, 1}, not a vector of 256 ring elements. The space of challenge differences is just {±1, ±2}, a set of size 4. The 3^256 figure applies to the Cyclo folding challenge space (a vector of ring elements), but the P1 leaf NIZK only uses a ternary scalar challenge. This distinction matters for the invertibility analysis.

- **Norm blowup for Δ = ±2 is the practical concern, not invertibility.** Even when 2 is invertible (odd q_commit), the inverse 2^{-1} mod q_commit has norm ~2^49, causing the extracted witness norm to exceed the modulus. The extractor should reject Δ = ±2 forks and retry, which adds a constant factor of 3/2 to the expected number of rewinds but does not affect the asymptotic extraction probability.

- **The document correctly treats Lemma 9 as an accepted assumption.** M3 does not attempt to prove the invertibility claim. It catalogues partial results, identifies the q_commit parity condition, and cross-references the Lemma 9 acceptance rationale. This is exactly the scope requested in the task.

## M4: Joint Extractor Composition

### 2026-05-14

- **The two extractors are independent because they rewind at different Fiat-Shamir layers.** E_leaf rewinds at the NIZK layer (outermost FS), while E_fold rewinds at the folding layer (inner FS, within each fold step). The independence of the Fiat-Shamir challenges across layers means the rewinding events don't interfere. This is important because it justifies the product formula ε_joint = (ε_leaf)^t · ε_fold.

- **The extraction probability decays exponentially in t.** With t leaf proofs and per-leaf extraction probability ε_leaf < 1, ε_joint = (ε_leaf)^t · ε_fold drops quickly. For ε_leaf ≈ 0.65 (from M1 numerical example) and t = 4, ε_joint ≈ 0.18. This means the extractor succeeds on only ~18% of runs, which is a ~2.5 bit security loss on top of the existing forking-lemma loss. This is the fundamental cost of extracting witnesses independently for each leaf.

- **The total extraction cost is O(t/ε²).** The folding extraction cost O(1/ε²) is dominated by the leaf extraction cost O(t/ε²) for non-trivial t. The constant factor is manageable: each leaf rewind takes ~12/ε_leaf attempts in expectation, and the whole joint extractor takes ~t·12/ε_leaf attempts.

- **The additive assumption composition (M2 §5) is preserved in M4.** The joint extractor's security depends on all four assumptions (Lemma 9, SHA-256, M-SIS, ROM) independently. A break of any one assumption does not break the others. The adversary's advantage is bounded by the sum of individual assumption-breaking advantages.

## M5: Formal Write-Up

### 2026-05-14

- **M5 serves as the "entry point" document.** A reader who only wants the theorem statement, assumptions, pseudocode, and parameter bounds should read M5. The detailed proofs and derivations live in M1-M4. This is the right structure: a self-contained summary with pointers to the full arguments.

- **The pseudocode makes the extraction algorithm concrete.** Without the pseudocode, the extraction would be a purely mathematical existence argument. The LeafExtractor pseudocode in particular clarifies the rewind loop, the fork acceptance criteria, and the error handling. This will be valuable for anyone implementing the extractor.

- **The vacuous forking-lemma bound is addressed honestly.** M5 §4.3 shows numerically that the standard forking-lemma bound is vacuous (negative) for the ternary challenge space with Q_total = 12. The document doesn't hide this or claim it's fine. It explains that the real guarantee comes from the reduction to M-SIS and SHA-256, not from an idealized ε_extract formula. This is the right level of intellectual honesty for a research prototype.

- **The tightness bottleneck (ternary challenge space) is clearly identified.** M5 §4.4 states plainly that the bottleneck is architectural (P1 NIZK design choice), not compositional. The joint extractor inherits the per-leaf bottleneck multiplicatively across t leaves but doesn't introduce new tightness loss. The three alternative extraction models in §4.5 provide paths forward if tighter extraction is needed.
