# P2 Theorem Inventory

This inventory freezes the theorem obligations for the P2 LatticeFold+ over RLWE construction against the concrete P1→P2 handoff fixed in `.sisyphus/contracts/p1-to-p2-bundle.md` and the P2 threat model in `.sisyphus/research/p2/threat-model.md`.

The concrete parameter tuple for the baseline theorem statements is
\[
(q,N,B_e,k) = (65537, 1024, 17, \mathsf{ternary\_challenge\_set}),
\]
where the challenge set is the inherited P1 ternary domain \(\{-1,0,1\}\).

## Theorem P2-T1: Folding Completeness {#P2-Completeness}

**Theorem ID**: P2-T1
**Assumption**: Honest generation of each inner P1 proof and correct evaluation of the LatticeFold+ fold relation over the frozen P1 verifier equation.
**Model**: Deterministic verification of the folded relation with the inherited ROM Fiat–Shamir challenge derivation from P1.
**Statement**: Let `stmt` be a valid frozen P1 statement with parameter tuple \((q,N,B_e,k)=(65537,1024,17,\mathsf{ternary\_challenge\_set})\), let `π` be an honestly generated P1 proof whose projected sigma transcript is `(t_bytes, challenge_bytes, z_s, z_e)`, and let `acc` be an accumulator state already accepted by `verify_acc` for the same session-binding and ordered fold transcript. If `π` satisfies the full frozen inner verifier equation from the P1→P2 bundle—namely: (i) Fiat–Shamir challenge recomputation over `SHA-256(session_id || pvss_commitment || t_bytes || statement_bytes)`, (ii) ternary challenge-weight recovery, (iii) mask-commitment equality for the arithmetic transcript, (iv) SHA-256 commitment opening for `pvss_commitment`, and (v) the opened-error and `z_e` norm checks including `|z_e[i]| ≤ 2 B_e = 34`—then the fold transition `fold(acc, π, stmt)` outputs an accumulator `acc'` such that `verify_acc(acc', stmt_history || stmt) = 1`.
**Proof technique**: Direct preservation-of-validity argument: an honest inner proof satisfies the exact verifier equation embedded into the fold constraint system, so the accumulated relation remains satisfied after one more fold step.
**Reduction target**: N/A for completeness.
**Status**: stated

## Theorem P2-T2: Folding Knowledge Soundness via Extraction Tree {#P2-KnowledgeSoundness}

**Theorem ID**: P2-T2
**Assumption**: Primary hardness target is M-SIS / RingSIS for the accumulator-binding layer, together with SHA-256 binding for the inherited commitment-opening checks and the ROM rewinding model from P1.
**Model**: ROM with a rewinding tree extractor over fold depth `d`.
**Statement**: Let `ProveFold` be any PPT adversary that, after `d` fold steps over the frozen P1 verifier relation, outputs a final accumulator accepted by `verify_acc`. Then there exists a tree extractor `Ext` which rewinds each fold node on the inherited ternary Fiat–Shamir challenge and outputs a valid witness for the folded RLWE relation—equivalently, valid witnesses for the accepted underlying P1 instances consistent with the ordered fold transcript—except with probability at most
\[
(1/3)^d + \varepsilon_{\mathrm{ext}},
\]
where `(1/3)^d` is the inherited ternary special-soundness loss across depth `d` and \(\varepsilon_{\mathrm{ext}}\) is the failure probability of the SHA-256 binding/opening checks inside the folded relation. The extraction tree argument is explicit: each fold step has base rewinding cost two accepting challenge views for the same first message, and the conservative full extraction cost over a depth-`d` fold tree is therefore `2^d` rewinding branches in the worst case. This theorem is stated only for modest `d` where that `2^d` extractor work remains polynomially bounded and operationally meaningful.
**Proof technique**: Fork each sigma-style fold node to obtain sibling accepting transcripts, apply special soundness at that node, and recurse upward/downward through the fold tree until all accepting branches are explained by valid RLWE witnesses or else a binding contradiction is obtained.
**Reduction target**: M-SIS / RingSIS for inconsistent short openings in the accumulator layer, plus SHA-256 binding for inherited commitment failures.
**Status**: stated

## Theorem P2-T3: ZK Preservation for the Projected SLAP Core Transcript {#P2-ZKPreservation}

**Theorem ID**: P2-T3
**Assumption**: Conditional on ROM Fiat–Shamir compilation and HVZK of the inner randomized SLAP-style protocol.
**Model**: ROM, projected-core view only.
**Statement**: Assume each inner P1 proof is zero-knowledge only for the projected SLAP core transcript `(t_bytes, z_s, z_e)` under fresh prover masks and fresh fold randomness. Then for every fold depth `d`, the accumulator state produced by repeatedly applying `fold` leaks no additional witness information beyond the public statement history and fold transcript metadata, provided the folded relation exposes only that projected SLAP core transcript and does not re-expose the audit-only witness openings present in the current serialized P1 proof bytes. In particular, this theorem does **not** claim zero-knowledge for the full current P1 payload containing `secret_share_open` and `error_open`; it is scoped only to the abstract projected core inherited from the P1 T3 theorem.
**Proof technique**: Hybrid argument from inner-proof HVZK/ROM simulation to fold-level transcript simulation under fresh fold randomness, while projecting away the non-ZK witness-opening fields.
**Reduction target**: ROM programmability plus HVZK of the inner randomized SLAP core protocol.
**Status**: stated

## Theorem P2-T4: Accumulator Binding under M-SIS/RingSIS {#P2-AccumulatorBinding}

**Theorem ID**: P2-T4
**Assumption**: RingSIS / M-SIS hardness for the concrete lattice commitment used by the accumulator, at modulus `q = 65537`, ring degree `N = 1024`, and the frozen ordered fold transcript semantics.
**Model**: Standard binding/collision-resistance reduction for the accumulator commitment layer.
**Statement**: Let `AccCommit` denote the accumulator commitment map used by the P2 fold state over the frozen parameter tuple `(q,N,B_e,k) = (65537,1024,17,ternary_challenge_set)`, and let `norm_bound` denote the accumulator-internal bound enforced on the folded commitment witness inside the folded relation. No PPT adversary can output two distinct witness pairs `(w,w')`, with `(w,w')` inducing different valid fold histories or different underlying accepted statement/witness sets, such that
\[
\mathrm{AccCommit}(w) = \mathrm{AccCommit}(w')
\]
while both satisfy the same public accumulator value and the same internal `norm_bound`, except with probability bounded by the adversary's advantage in solving the corresponding RingSIS / M-SIS instance at modulus `q = 65537` and ring degree `N = 1024`. Equivalently, the accepted accumulator binds the ordered fold transcript and accumulated statement set up to the hardness of producing a short non-zero collision in that lattice commitment layer.
**Proof technique**: Reduction from a double-opening / same-accumulator collision to a short-kernel collision against the concrete accumulator commitment map.
**Reduction target**: RingSIS / M-SIS.
**Status**: stated

## Theorem P2-T5: On-chain Verifier Compatibility {#P2-OnchainCompatibility}

**Theorem ID**: P2-T5
**Assumption**: The final accumulated proof is wrapped into the P3 on-chain target represented today by `contracts/src/generated/HonkVerifier.sol` or a drop-in successor using only Solidity/Yul-available operations.
**Model**: Engineering theorem obligation / compatibility target, not yet a proved security fact.
**Statement**: There exists a final accumulated-proof encoding and verifier path for the P2 construction such that the EVM contract-facing verifier checks the terminal accumulated proof using only Solidity/Yul-available operations, with total verification gas bounded by
\[
G \le 5{,}000{,}000
\]
and final proof size bounded by
\[
S \le 14\,\mathrm{KB},
\]
while preserving the frozen public-input boundary required by the downstream P3 interface. The concrete op-count target at this stage is an O(1)-size verifier path with respect to fold depth, consisting of one wrapped-proof verification call over the seven frozen public inputs `(ciphertext_hash, plaintext_hash, aggregate_pk_hash, dkg_root, epoch, participant_set_hash, D_commitment)` plus the proof blob, rather than a verifier whose work scales with the number of folded P1 instances. At this stage these gas, proof-size, and operation-count limits are stated as proof obligations/goals rather than established measured facts.
**Operational target**: The final verifier should compile to a Solidity/Yul path whose dominant operations are a single wrapped verifier invocation, fixed-size public-input decoding, and the baseline hashing/equality checks represented by the eventual replacement for `contracts/src/generated/HonkVerifier.sol`; any design needing unsupported EVM primitives or exceeding the gas/size ceiling violates this theorem obligation.
**Reduction target**: N/A yet; this is a downstream compatibility theorem obligation to be discharged with the P3 stack proof and gas evidence.
**Status**: stated
