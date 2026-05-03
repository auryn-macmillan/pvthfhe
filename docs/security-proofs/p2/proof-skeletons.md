# P2 Proof Skeletons — LatticeFold+ Primary Stack

This document expands the frozen P2 theorem inventory into formal proof skeletons for the **LatticeFold+** primary stack over the frozen parameter tuple `(q=65537, N=1024, B_e=17, k=ternary_challenge_set={-1,0,1})`. The target folded relation is the exact P1 verifier equation frozen in `.sisyphus/contracts/p1-to-p2-bundle.md`, carried through the backend-agnostic `FoldStatement` / `FoldWitness` / `FoldAccumulator` interface in `.sisyphus/design/p2/interface-spec.md`.

Throughout, `fold` accumulates one frozen P1 proof/statement pair into an ordered binary folding tree, `verify_acc` checks accumulator well-formedness and history binding, and the security model is the inherited ROM setting with LatticeFold+ accumulator binding anchored to RingSIS / M-SIS at `q=65537` and `N=1024`. These are **skeletons**, not completed proofs; every open gap below remains an explicit proof obligation.

## T1 — Folding Completeness

### Theorem statement

**Theorem P2-T1 (Folding Completeness, LatticeFold+ refinement).** Let `stmt` be a valid frozen P1 statement with parameter tuple `(q,N,B_e,k)=(65537,1024,17,ternary_challenge_set)`, let `π` be an honestly generated P1 proof whose projected sigma transcript is `(t_bytes, challenge_bytes, z_s, z_e)`, and let `acc` be an accumulator state already accepted by `verify_acc` for the same session-binding and ordered fold transcript. If `π` satisfies the full frozen inner verifier equation from the P1→P2 bundle—namely: (i) Fiat–Shamir challenge recomputation over `SHA-256(session_id || pvss_commitment || t_bytes || statement_bytes)`, (ii) ternary challenge-weight recovery, (iii) mask-commitment equality for the arithmetic transcript, (iv) SHA-256 commitment opening for `pvss_commitment`, and (v) the opened-error and `z_e` norm checks including `|z_e[i]| ≤ 2 B_e = 34`—then the fold transition `fold(acc, π, stmt)` outputs an accumulator `acc'` such that `verify_acc(acc', stmt_history || stmt) = 1`.

### Proof strategy

Direct completeness argument: show that an honest P1 proof already satisfies the exact verifier equation embedded inside the LatticeFold+ folded relation, so one more fold preserves accumulator validity.

### Key lemmas needed

1. **P1 verifier embedding lemma.** The folded LatticeFold+ relation encodes the exact frozen P1 verifier equation rather than a surrogate relation.
2. **Five-subcheck preservation lemma.** Honest evaluation preserves all five frozen sub-conditions: Fiat–Shamir challenge recomputation, ternary challenge-weight recovery, mask-commitment equality, SHA-256 commitment opening, and `|z_e[i]| ≤ 34` norm checks.
3. **Ordered-history update lemma.** Advancing `statement_hash_chain` with the current `FoldStatement` bytes preserves the ordered transcript semantics required by `verify_acc`.
4. **Accumulator transition lemma.** If the incoming accumulator verifies and the embedded fold constraint is satisfied, then the outgoing `acc_commitment` and visible metadata are jointly accepted by `verify_acc`.
5. **Main sub-obligation.** **P1 honest proof passes all five frozen sub-checks → fold constraint is satisfied.**

### Reduction chain

N/A for completeness. The proof is by direct preservation of a satisfied relation under one honest fold transition.

### Open gaps

- The exact LatticeFold+ adapter constraint system is not implemented yet, so the “exact embedding” claim is still a design obligation.
- SHA-256 recomputation and range-check gadgets are only frozen semantically, not yet proven equivalent to a concrete folded encoding.
- The proof still needs a formal argument that accumulator metadata (`fold_depth`, `session_id`, `params`, `statement_hash_chain`) stays aligned with the hidden commitment witness across every fold.

## T2 — Knowledge Soundness via Extraction Tree

### Theorem statement

**Theorem P2-T2 (Folding Knowledge Soundness via Extraction Tree, LatticeFold+ refinement).** Let `ProveFold` be any PPT adversary that, after `d` fold steps over the frozen P1 verifier relation, outputs a final accumulator accepted by `verify_acc`. Then there exists a tree extractor `Ext` which rewinds each fold node on the inherited ternary Fiat–Shamir challenge and outputs a valid witness for the folded RLWE relation—equivalently, valid witnesses for the accepted underlying P1 instances consistent with the ordered fold transcript—except with probability at most `(1/3)^d + ε_ext`, where `(1/3)^d` is the inherited ternary special-soundness loss across depth `d` and `ε_ext` is the failure probability of the SHA-256 binding/opening checks inside the folded relation. The extraction tree argument is explicit: each fold step has base rewinding cost two accepting challenge views for the same first message, and the conservative full extraction cost over a depth-`d` fold tree is therefore `2^d` rewinding branches in the worst case. This theorem is stated only for modest `d` where that `2^d` extractor work remains polynomially bounded and operationally meaningful.

### Proof strategy

Reduction-plus-extractor skeleton: fork each LatticeFold+ fold node to obtain two accepting transcripts with the same first message and distinct ternary challenges, derive a local linear relation over the RLWE witness, and recurse through the fold tree until the accepted accumulator is explained by valid witnesses or else converted into an accumulator-binding contradiction.

### Key lemmas needed

1. **Local special-soundness lemma.** **Same first message, two distinct ternary challenges → linear relation over RLWE witness.**
2. **Node extractor lemma.** From two accepting views at one fold node, the extractor recovers a witness consistent with that node’s folded verifier equation, or else derives an inconsistency in the accumulator opening.
3. **Tree composition lemma.** Local extraction at each node composes across the binary folding tree to recover witnesses for the accepted leaf instances.
4. **Binding-failure-to-short-kernel lemma.** Any failed extraction branch that still leaves two valid openings of the same accumulator commitment yields a short kernel relation for RingSIS / M-SIS.
5. **Transcript-consistency lemma.** The recovered witnesses remain consistent with the ordered `statement_hash_chain`, session binding, and frozen parameter tuple.

### Reduction chain

Accepting final accumulator
→ rewind one fold node to get two accepting views under distinct ternary challenges
→ apply local special soundness to derive a witness relation or expose an inconsistent opening
→ recurse over the binary tree until all accepted folds are explained
→ if any branch still yields two distinct short openings for the same `AccCommit`, reduce to a non-zero short kernel in RingSIS / M-SIS at `(q=65537, N=1024)`.

### Recursion-budget note

For the frozen target `t=513` with binary folding, the expected depth is `d≈10` because `2^9 = 512 < 513 ≤ 2^10 = 1024`. The conservative extraction tree therefore has `2^10 = 1024` rewinding branches, and the inherited per-fold soundness loss is `(1/3)^d ≈ (1/3)^10`.

### Open gaps

- The exact algebra needed to turn two accepting LatticeFold+ fold views into a witness extractor is not yet instantiated for this repository’s RLWE verifier equation.
- The theorem currently assumes rewinding over the inherited ternary Fiat–Shamir challenge is admissible in the concrete ROM transcript schedule; that scheduling proof is not written.
- The boundary between extraction failure and accumulator-binding failure still needs a formal “either extract or solve RingSIS/M-SIS” lemma.

## T3 — ZK Preservation for the Projected SLAP Core Transcript

### Theorem statement

**Theorem P2-T3 (ZK Preservation for the Projected SLAP Core Transcript, LatticeFold+ refinement).** Assume each inner P1 proof is zero-knowledge only for the projected SLAP core transcript `(t_bytes, z_s, z_e)` under fresh prover masks and fresh fold randomness. Then for every fold depth `d`, the accumulator state produced by repeatedly applying `fold` leaks no additional witness information beyond the public statement history and fold transcript metadata, provided the folded relation exposes only that projected SLAP core transcript and does not re-expose the audit-only witness openings present in the current serialized P1 proof bytes. In particular, this theorem covers **only** the projected SLAP core transcript `(t_bytes, z_s, z_e)` and does **not** claim zero-knowledge for the full current P1 payload containing `secret_share_open` and `error_open`; `secret_share_open` and `error_open` are explicitly outside the theorem scope.

### Proof strategy

Hybrid simulation argument: start from the inner projected-core HVZK simulator, then replace each real fold transcript with a simulated fold transcript under fresh fold randomness until the full accepted accumulator view is simulated from public data alone.

### Key lemmas needed

1. **Projected-core scope lemma.** The folded relation exposes only `(t_bytes, z_s, z_e)` plus public metadata, and excludes `secret_share_open` and `error_open` from the theorem statement.
2. **Inner-core simulation lemma.** The projected P1 SLAP core transcript is simulatable under the inherited ROM/HVZK assumptions.
3. **Fold transcript simulation lemma.** **Fold transcript can be simulated under fresh fold randomness given only public statement.**
4. **Hybrid composition lemma.** Replacing one fold at a time from real to simulated changes the view by at most the inherited projected-core indistinguishability bound.
5. **Metadata leakage lemma.** `fold_depth`, `session_id`, `params`, and `statement_hash_chain` add only public binding information and no extra witness leakage beyond the projected transcript.

### Reduction chain

Real folded projected-core transcript
→ replace inner projected SLAP transcript with its HVZK/ROM simulator
→ replace each real fold randomness draw with simulator-controlled fresh fold randomness
→ obtain a simulator for the full projected fold transcript using only the public statement history and public metadata.

Reduction target: ROM programmability plus HVZK of the inner randomized projected SLAP core. No reduction to RingSIS / M-SIS is needed for this privacy theorem.

### Open gaps

- The repository still serializes `secret_share_open` and `error_open` in the frozen P1 proof bytes, so the implementation path must prove those fields are projected away before any P2 ZK claim is operationally meaningful.
- The simulator for the concrete LatticeFold+ fold transcript has not been written, only postulated at the design level.
- The proof still needs a precise leakage function for fold metadata so the hybrid statement is mathematically exact.

## T4 — Accumulator Binding under RingSIS / M-SIS

### Theorem statement

**Theorem P2-T4 (Accumulator Binding under RingSIS / M-SIS, LatticeFold+ refinement).** Let `AccCommit` denote the accumulator commitment map used by the P2 fold state over the frozen parameter tuple `(q,N,B_e,k) = (65537,1024,17,ternary_challenge_set)`, and let `norm_bound` denote the accumulator-internal short-witness bound enforced on the folded commitment witness inside the LatticeFold+ folded relation at modulus `q = 65537` and ring degree `N = 1024`. No PPT adversary can output two distinct witness pairs `(w,w')`, with `(w,w')` inducing different valid fold histories or different underlying accepted statement/witness sets, such that `AccCommit(w) = AccCommit(w')` while both satisfy the same public accumulator value and the same internal `norm_bound`, except with probability bounded by the adversary's advantage in solving the corresponding RingSIS / M-SIS instance at modulus `q = 65537` and ring degree `N = 1024`. Equivalently, the accepted accumulator binds the ordered fold transcript and accumulated statement set up to the hardness of producing a short non-zero collision in that lattice commitment layer.

### Proof strategy

Direct binding reduction: assume two distinct valid short openings for the same accumulator commitment, subtract them, and interpret the difference as a non-zero short kernel vector for the concrete lattice commitment map.

### Key lemmas needed

1. **Commitment linearization lemma.** The concrete `AccCommit` map is linear or affine in the hidden witness coordinates in the way required by the RingSIS / M-SIS reduction.
2. **Short-opening difference lemma.** Two valid openings under the same `norm_bound` subtract to a non-zero short vector still within the reduction’s admissible norm regime.
3. **History-binding lemma.** Distinct fold histories or accepted statement sets induce distinct witness encodings inside the accumulator opening.
4. **Main reduction lemma.** **Two distinct witness pairs with same AccCommit → non-zero short kernel in RingSIS.**
5. **Metadata consistency lemma.** The public accumulator fields and hidden opening refer to the same ordered fold transcript and parameter tuple.

### Reduction chain

Adversary outputs two distinct short valid openings `w ≠ w'` with `AccCommit(w) = AccCommit(w')`
→ subtract to obtain `Δ = w - w'`
→ show `Δ ≠ 0` and still satisfies the reduction’s shortness bound induced by `norm_bound`
→ map `Δ` to a non-zero short kernel element for the concrete accumulator commitment matrix/map
→ solve RingSIS / M-SIS at `(q=65537, N=1024)`.

### Open gaps

- The concrete algebraic form of `AccCommit` is still hidden behind the backend adapter boundary, so the exact RingSIS / M-SIS instance shape is not frozen yet.
- `norm_bound` is semantically frozen as the short-witness bound inside the folded relation, but its exact numeric value is not yet published in the design docs.
- The proof still needs a formal encoding argument that “different fold histories” really implies “different witness encodings” under the chosen accumulator commitment map.

## T5 — On-chain Compatibility as a Design Obligation

### Theorem statement

**Theorem P2-T5 (On-chain Verifier Compatibility, engineering form).** There exists a final accumulated-proof encoding and verifier path for the P2 construction such that the EVM contract-facing verifier checks the terminal accumulated proof using only Solidity/Yul-available operations, with total verification gas bounded by `≤ 5,000,000` and final proof size bounded by `≤ 14 KB`, while preserving the frozen public-input boundary required by the downstream P3 interface. The concrete design target is O(1) verifier work with respect to fold depth: one wrapped-proof verification path over the seven frozen public inputs `(ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, d_commitment)` plus the proof blob, rather than verifier work that scales with the number of folded P1 instances.

### Proof strategy

Engineering obligation, not a formal cryptographic reduction. The path is to validate the eventual P3 wrapper against measured gas, proof-size, and fixed-operation-count evidence.

### Key lemmas needed

1. **Public-input boundary lemma.** The finalized P2 output preserves exactly the frozen `P3PublicInputs` surface.
2. **O(1)-verifier-path lemma.** The final verifier work does not scale with fold depth once P2 is finalized and wrapped for P3.
3. **Envelope lemma.** The final wrapped proof can be serialized within the `≤ 14 KB` target and verified within the `≤ 5M` gas target.
4. **Compatibility lemma.** The verifier path uses only Solidity/Yul-available operations and supported downstream verifier primitives.

### Reduction chain

N/A. This is a design obligation discharged by implementation, benchmarking, and downstream P3 verification evidence rather than a hardness reduction.

### Open gaps

- The P3 compression/wrapping path is not yet designed; this is the primary downstream obligation.
- No measured gas or proof-size evidence exists yet for a real LatticeFold+ → P3 path in this repository.
- The current primary-stack memo already marks the direct LatticeFold+ EVM story as borderline, so this theorem remains a target rather than an established fact.

## Reviewer Sign-off
VERDICT: APPROVE
